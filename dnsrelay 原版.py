import argparse
import ipaddress
import socket
import struct
import sys
import time
from datetime import datetime


DEFAULT_LISTEN_HOST = "127.0.0.1"
DEFAULT_LISTEN_PORT = 10053
DEFAULT_UPSTREAM_HOST = "8.8.8.8"
DEFAULT_UPSTREAM_PORT = 53
DEFAULT_DB_FILE = "dnsrelay.txt"
BUFFER_SIZE = 512
UPSTREAM_TIMEOUT = 5.0
DNS_HEADER_SIZE = 12
TYPE_A = 1
CLASS_IN = 1
RCODE_NAME_ERROR = 3
CACHE_TTL_SECONDS = 60


def log(message):
    now = datetime.now().strftime("%H:%M:%S")
    print(f"[{now}] {message}", flush=True)


def normalize_domain(domain):
    return domain.rstrip(".").lower()


def load_local_records(path):
    records = {}
    try:
        with open(path, "r", encoding="utf-8") as file:
            for line_number, raw_line in enumerate(file, 1):
                line = raw_line.split("#", 1)[0].strip()
                if not line:
                    continue

                parts = line.split()
                if len(parts) < 2:
                    log(f"Skip invalid record at {path}:{line_number}")
                    continue

                first, second = parts[0], parts[1]
                try:
                    ipaddress.IPv4Address(first)
                    ip_text, domain = first, second
                except ValueError:
                    try:
                        ipaddress.IPv4Address(second)
                    except ValueError:
                        log(f"Skip invalid IP at {path}:{line_number}")
                        continue
                    domain, ip_text = first, second

                records[normalize_domain(domain)] = ip_text
    except FileNotFoundError:
        log(f"Local database {path} not found; all queries will be forwarded")

    return records


def decode_domain_name(packet, offset):
    labels = []
    jumped = False
    next_offset = offset
    seen_offsets = set()

    while True:
        if offset >= len(packet):
            raise ValueError("domain name exceeds packet length")

        length = packet[offset]
        if length == 0:
            offset += 1
            if not jumped:
                next_offset = offset
            break

        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(packet):
                raise ValueError("truncated compressed domain pointer")
            pointer = ((length & 0x3F) << 8) | packet[offset + 1]
            if pointer in seen_offsets:
                raise ValueError("compressed domain pointer loop")
            seen_offsets.add(pointer)
            if not jumped:
                next_offset = offset + 2
                jumped = True
            offset = pointer
            continue

        if length & 0xC0:
            raise ValueError("unsupported domain label format")

        offset += 1
        end = offset + length
        if end > len(packet):
            raise ValueError("truncated domain label")
        labels.append(packet[offset:end].decode("ascii", errors="ignore"))
        offset = end

    return normalize_domain(".".join(labels)), next_offset


def parse_dns_query(packet):
    if len(packet) < DNS_HEADER_SIZE:
        raise ValueError("packet shorter than DNS header")

    header = struct.unpack("!HHHHHH", packet[:DNS_HEADER_SIZE])
    query_id, flags, qdcount, ancount, nscount, arcount = header
    if qdcount != 1:
        raise ValueError(f"unsupported question count: {qdcount}")

    domain, offset = decode_domain_name(packet, DNS_HEADER_SIZE)
    if offset + 4 > len(packet):
        raise ValueError("truncated question section")

    qtype, qclass = struct.unpack("!HH", packet[offset:offset + 4])
    question_end = offset + 4

    return {
        "id": query_id,
        "flags": flags,
        "domain": domain,
        "qtype": qtype,
        "qclass": qclass,
        "question_end": question_end,
    }


def build_response_flags(query_flags, rcode=0):
    recursion_desired = query_flags & 0x0100
    opcode = query_flags & 0x7800
    return 0x8000 | opcode | recursion_desired | 0x0080 | rcode


def build_name_error_response(query, parsed):
    header = struct.pack(
        "!HHHHHH",
        parsed["id"],
        build_response_flags(parsed["flags"], RCODE_NAME_ERROR),
        1,
        0,
        0,
        0,
    )
    return header + query[DNS_HEADER_SIZE:parsed["question_end"]]


def build_a_record_response(query, parsed, ip_text):
    header = struct.pack(
        "!HHHHHH",
        parsed["id"],
        build_response_flags(parsed["flags"]),
        1,
        1,
        0,
        0,
    )
    question = query[DNS_HEADER_SIZE:parsed["question_end"]]
    answer = b"".join(
        [
            b"\xC0\x0C",
            struct.pack("!HHI", TYPE_A, CLASS_IN, 60),
            struct.pack("!H", 4),
            socket.inet_aton(ip_text),
        ]
    )
    return header + question + answer


def forward_query(query, upstream):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as upstream_sock:
        upstream_sock.settimeout(UPSTREAM_TIMEOUT)
        upstream_sock.sendto(query, upstream)
        response, _ = upstream_sock.recvfrom(BUFFER_SIZE)
        return response


def response_with_query_id(response, query_id):
    return struct.pack("!H", query_id) + response[2:]


def is_cacheable_response(response):
    if len(response) < DNS_HEADER_SIZE:
        return False
    _, flags, _, ancount, _, _ = struct.unpack("!HHHHHH", response[:DNS_HEADER_SIZE])
    rcode = flags & 0x000F
    return rcode == 0 and ancount > 0


def handle_query(query, upstream_addr, local_records, cache):
    try:
        parsed = parse_dns_query(query)
    except ValueError as exc:
        log(f"Could not parse query: {exc}; forwarding")
        return forward_query(query, upstream_addr), "forward"

    domain = parsed["domain"]
    qtype = parsed["qtype"]
    qclass = parsed["qclass"]
    log(f"Query domain={domain}, type={qtype}, class={qclass}")

    local_ip = local_records.get(domain)
    if local_ip is None:
        cache_key = (domain, qtype, qclass)
        cached = cache.get(cache_key)
        now = time.time()
        if cached is not None:
            expires_at, cached_response = cached
            if expires_at > now:
                log("Cache hit; returning cached upstream response")
                return response_with_query_id(cached_response, parsed["id"]), "cache-hit"
            del cache[cache_key]

        log("No local record; forwarding")
        response = forward_query(query, upstream_addr)
        if is_cacheable_response(response):
            cache[cache_key] = (now + CACHE_TTL_SECONDS, response)
            log(f"Cached upstream response for {CACHE_TTL_SECONDS} seconds")
        return response, "forward"

    if local_ip == "0.0.0.0":
        log("Local record is 0.0.0.0; returning NXDOMAIN")
        return build_name_error_response(query, parsed), "local-nxdomain"

    if qtype != TYPE_A or qclass != CLASS_IN:
        log("Local record exists, but query type/class is unsupported; forwarding")
        return forward_query(query, upstream_addr), "forward"

    log(f"Local hit; returning {local_ip}")
    return build_a_record_response(query, parsed, local_ip), "local-answer"


def run_relay(listen_host, listen_port, upstream_host, upstream_port, db_file):
    listen_addr = (listen_host, listen_port)
    upstream_addr = (upstream_host, upstream_port)
    local_records = load_local_records(db_file)
    cache = {}

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as relay_sock:
        relay_sock.bind(listen_addr)
        log(f"DNS Relay listening on {listen_host}:{listen_port}")
        log(f"Forwarding queries to upstream DNS {upstream_host}:{upstream_port}")
        log(f"Loaded {len(local_records)} local records from {db_file}")

        while True:
            query, client_addr = relay_sock.recvfrom(BUFFER_SIZE)
            log(f"Received {len(query)} bytes from {client_addr[0]}:{client_addr[1]}")

            try:
                response, source = handle_query(query, upstream_addr, local_records, cache)
            except socket.timeout:
                log("Upstream DNS timeout; no response sent to client")
                continue
            except OSError as exc:
                log(f"Upstream DNS error: {exc}")
                continue

            relay_sock.sendto(response, client_addr)
            log(f"Sent {len(response)} bytes to {client_addr[0]}:{client_addr[1]} ({source})")


def parse_args(argv):
    parser = argparse.ArgumentParser(description="DNS relay with local hosts-like rules.")
    parser.add_argument("--listen-host", default=DEFAULT_LISTEN_HOST)
    parser.add_argument("--listen-port", type=int, default=DEFAULT_LISTEN_PORT)
    parser.add_argument("--upstream-host", default=DEFAULT_UPSTREAM_HOST)
    parser.add_argument("--upstream-port", type=int, default=DEFAULT_UPSTREAM_PORT)
    parser.add_argument("--db-file", default=DEFAULT_DB_FILE)
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv or sys.argv[1:])
    try:
        run_relay(
            args.listen_host,
            args.listen_port,
            args.upstream_host,
            args.upstream_port,
            args.db_file,
        )
    except PermissionError:
        log("Permission denied. Try --listen-port 10053, or run as administrator for port 53.")
        return 1
    except KeyboardInterrupt:
        log("DNS Relay stopped")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())