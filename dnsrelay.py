import argparse
import ipaddress
import json
import socket
import struct
import sys
import threading
import time
from collections import deque
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


DEFAULT_LISTEN_HOST = "127.0.0.1"
DEFAULT_LISTEN_PORT = 10053
DEFAULT_UPSTREAM_HOST = "8.8.8.8"
DEFAULT_UPSTREAM_PORT = 53
DEFAULT_DB_FILE = "dnsrelay.txt"
DEFAULT_DASHBOARD_HOST = "127.0.0.1"
DEFAULT_DASHBOARD_PORT = 18080
BUFFER_SIZE = 512
UPSTREAM_TIMEOUT = 5.0
DNS_HEADER_SIZE = 12
TYPE_A = 1
CLASS_IN = 1
RCODE_NAME_ERROR = 3
RCODE_SERVER_FAILURE = 2
EVENT_LIMIT = 120
CACHE_LIMIT = 64


DASHBOARD_HTML = r"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>DNS Relay Console</title>
  <style>
    :root {
      --bg: #f5f7fb;
      --panel: #ffffff;
      --text: #172033;
      --muted: #667085;
      --line: #dde3ee;
      --blue: #2563eb;
      --green: #16a34a;
      --amber: #d97706;
      --red: #dc2626;
      --slate: #334155;
      --shadow: 0 16px 42px rgba(15, 23, 42, 0.08);
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      background: var(--bg);
      color: var(--text);
      font: 14px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      overflow-x: hidden;
    }
    header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 16px;
      padding: 18px 24px;
      background: #fff;
      border-bottom: 1px solid var(--line);
      position: sticky;
      top: 0;
      z-index: 2;
    }
    h1 {
      margin: 0;
      font-size: 22px;
      letter-spacing: 0;
    }
    h2 {
      margin: 0 0 14px;
      font-size: 15px;
      letter-spacing: 0;
    }
    .chips {
      display: flex;
      gap: 8px;
      flex-wrap: wrap;
      justify-content: flex-end;
      min-width: 0;
    }
    .chip {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      min-height: 30px;
      padding: 4px 10px;
      border: 1px solid var(--line);
      border-radius: 8px;
      background: #f8fafc;
      color: var(--slate);
      font-size: 12px;
      white-space: nowrap;
      max-width: 100%;
      overflow-wrap: anywhere;
    }
    .dot {
      width: 8px;
      height: 8px;
      border-radius: 50%;
      background: var(--green);
    }
    main {
      display: grid;
      grid-template-columns: minmax(260px, 0.85fr) minmax(360px, 1.35fr) minmax(320px, 1fr);
      gap: 16px;
      padding: 16px;
      max-width: 1500px;
      margin: 0 auto;
    }
    section {
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      box-shadow: var(--shadow);
      padding: 16px;
      min-width: 0;
    }
    .stack {
      display: grid;
      gap: 16px;
      align-content: start;
      min-width: 0;
    }
    .kv {
      display: grid;
      grid-template-columns: 110px 1fr;
      gap: 9px 12px;
      color: var(--muted);
      font-size: 13px;
    }
    .kv strong {
      color: var(--text);
      font-weight: 650;
      overflow-wrap: anywhere;
      min-width: 0;
    }
    .rule-table, .event-table {
      width: 100%;
      border-collapse: collapse;
      table-layout: fixed;
      font-size: 13px;
    }
    th, td {
      text-align: left;
      border-bottom: 1px solid var(--line);
      padding: 9px 6px;
      vertical-align: top;
      overflow-wrap: anywhere;
    }
    th {
      color: var(--muted);
      font-size: 12px;
      font-weight: 650;
      background: #f8fafc;
    }
    .button-row {
      display: flex;
      gap: 8px;
      flex-wrap: wrap;
      margin-top: 14px;
    }
    button {
      min-height: 34px;
      padding: 0 12px;
      border-radius: 8px;
      border: 1px solid var(--line);
      background: #fff;
      color: var(--text);
      font: inherit;
      font-size: 13px;
      cursor: pointer;
    }
    button.primary {
      background: var(--blue);
      border-color: var(--blue);
      color: #fff;
      font-weight: 650;
    }
    input {
      width: 100%;
      min-height: 38px;
      border-radius: 8px;
      border: 1px solid var(--line);
      padding: 0 11px;
      font: inherit;
      color: var(--text);
      background: #fff;
    }
    .flow {
      display: grid;
      grid-template-columns: 1fr 42px 1fr 42px 1fr;
      align-items: stretch;
      gap: 10px;
      margin-bottom: 16px;
    }
    .node {
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 14px;
      background: #f8fafc;
      min-height: 96px;
    }
    .node strong {
      display: block;
      font-size: 15px;
      margin-bottom: 6px;
    }
    .arrow {
      display: grid;
      place-items: center;
      color: var(--blue);
      font-size: 22px;
      font-weight: 800;
    }
    .cases {
      display: grid;
      grid-template-columns: repeat(3, 1fr);
      gap: 10px;
    }
    .case {
      border: 1px solid var(--line);
      border-left-width: 4px;
      border-radius: 8px;
      padding: 12px;
      background: #fff;
      min-height: 128px;
    }
    .case.green { border-left-color: var(--green); }
    .case.red { border-left-color: var(--red); }
    .case.amber { border-left-color: var(--amber); }
    .case strong {
      display: block;
      margin-bottom: 6px;
    }
    .muted { color: var(--muted); }
    .counters {
      display: grid;
      grid-template-columns: repeat(2, 1fr);
      gap: 10px;
    }
    .counter {
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 12px;
      background: #f8fafc;
    }
    .counter span {
      display: block;
      color: var(--muted);
      font-size: 12px;
    }
    .counter strong {
      display: block;
      margin-top: 4px;
      font-size: 28px;
      line-height: 1;
    }
    .tag {
      display: inline-flex;
      align-items: center;
      min-height: 24px;
      padding: 2px 8px;
      border-radius: 8px;
      font-size: 12px;
      font-weight: 650;
      white-space: nowrap;
      max-width: 100%;
    }
    .tag.local-answer { background: #dcfce7; color: #166534; }
    .tag.local-nxdomain { background: #fee2e2; color: #991b1b; }
    .tag.forward { background: #fef3c7; color: #92400e; }
    .tag.cache-hit { background: #dbeafe; color: #1d4ed8; }
    .tag.error { background: #e2e8f0; color: #334155; }
    .log-list {
      display: grid;
      gap: 8px;
      max-height: 430px;
      overflow: auto;
      padding-right: 4px;
    }
    .log-item {
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 10px;
      background: #fff;
    }
    .log-top {
      display: flex;
      justify-content: space-between;
      gap: 8px;
      align-items: center;
      margin-bottom: 6px;
    }
    .log-domain {
      font-weight: 700;
      overflow-wrap: anywhere;
    }
    .status-line {
      min-height: 20px;
      margin-top: 8px;
      color: var(--muted);
      font-size: 13px;
    }
    @media (max-width: 1120px) {
      main { grid-template-columns: 1fr; }
      .cases, .counters { grid-template-columns: 1fr; }
    }
    @media (max-width: 720px) {
      header { align-items: flex-start; flex-direction: column; }
      .chips { justify-content: flex-start; width: 100%; }
      .chip { min-width: 0; overflow: hidden; text-overflow: ellipsis; }
      main { padding: 16px; }
      .stack, section, .node, .case { min-width: 0; max-width: 100%; }
      section { width: 100%; overflow: hidden; }
      .kv { grid-template-columns: 96px minmax(0, 1fr); }
      .flow { grid-template-columns: 1fr; }
      .arrow { min-height: 20px; transform: rotate(90deg); }
      th, td { padding: 8px 5px; font-size: 12px; }
      .tag { display: inline-block; white-space: normal; line-height: 1.25; padding: 2px 5px; font-size: 11px; }
      .rule-table { table-layout: fixed; }
      .rule-table th:nth-child(1), .rule-table td:nth-child(1) { width: 38%; }
      .rule-table th:nth-child(2), .rule-table td:nth-child(2) { width: 24%; }
      .rule-table th:nth-child(3), .rule-table td:nth-child(3) { width: 38%; }
    }
  </style>
</head>
<body>
  <header>
    <div>
      <h1>DNS Relay Console</h1>
      <div class="muted">Live view for the course DNS Relay cases</div>
    </div>
    <div class="chips">
      <span class="chip"><span class="dot"></span><span id="chip-status">running</span></span>
      <span class="chip" id="chip-listen">listen</span>
      <span class="chip" id="chip-upstream">upstream</span>
      <span class="chip" id="chip-db">database</span>
    </div>
  </header>
  <main>
    <div class="stack">
      <section>
        <h2>Server Status</h2>
        <div class="kv">
          <span>Listen</span><strong id="listen"></strong>
          <span>Upstream</span><strong id="upstream"></strong>
          <span>Database</span><strong id="db-file"></strong>
          <span>Records</span><strong id="record-count"></strong>
          <span>Started</span><strong id="started-at"></strong>
        </div>
        <div class="button-row">
          <button class="primary" id="reload-btn">Reload Rules</button>
        </div>
        <div class="status-line" id="reload-status"></div>
      </section>
      <section>
        <h2>Local Rules</h2>
        <table class="rule-table">
          <thead><tr><th>Domain</th><th>IP</th><th>Action</th></tr></thead>
          <tbody id="rules"></tbody>
        </table>
      </section>
    </div>
    <div class="stack">
      <section>
        <h2>Relay Flow</h2>
        <div class="flow">
          <div class="node"><strong>Client</strong><span class="muted">Resolver, browser, nslookup, or test panel sends a DNS query.</span></div>
          <div class="arrow">-></div>
          <div class="node"><strong>Relay</strong><span class="muted">Parse QNAME, QTYPE, QCLASS and check dnsrelay.txt.</span></div>
          <div class="arrow">-></div>
          <div class="node"><strong>Upstream DNS</strong><span class="muted">Only used when no local rule can answer the query.</span></div>
        </div>
        <div class="cases">
          <div class="case red"><strong>Case 1: Block</strong><div class="muted">IP is 0.0.0.0, return NXDOMAIN with RCODE=3.</div></div>
          <div class="case green"><strong>Case 2: Local A</strong><div class="muted">Local domain has IPv4, return A/IN answer directly.</div></div>
          <div class="case amber"><strong>Case 3: Forward</strong><div class="muted">No local rule, send original packet to upstream DNS.</div></div>
        </div>
      </section>
      <section>
        <h2>Test Query</h2>
        <input id="domain-input" value="local.test" aria-label="Domain to query">
        <div class="button-row">
          <button class="primary" data-test="local.test">Local A</button>
          <button data-test="blocked.test">NXDOMAIN</button>
          <button data-test="www.baidu.com">Forward</button>
          <button id="send-test">Send Query</button>
        </div>
        <div class="status-line" id="test-result"></div>
      </section>
      <section>
        <h2>Recent Events</h2>
        <div class="log-list" id="events"></div>
      </section>
    </div>
    <div class="stack">
      <section>
        <h2>Counters</h2>
        <div class="counters">
          <div class="counter"><span>Local Answer</span><strong id="count-local-answer">0</strong></div>
          <div class="counter"><span>NXDOMAIN</span><strong id="count-local-nxdomain">0</strong></div>
          <div class="counter"><span>Forwarded</span><strong id="count-forward">0</strong></div>
          <div class="counter"><span>Cache Hit</span><strong id="count-cache-hit">0</strong></div>
          <div class="counter"><span>Error</span><strong id="count-error">0</strong></div>
        </div>
      </section>
      <section>
        <h2>DNS Cache</h2>
        <div class="kv">
          <span>Entries</span><strong id="cache-count">0</strong>
          <span>Policy</span><strong>Forwarded A/IN responses</strong>
        </div>
        <div class="button-row">
          <button id="clear-cache-btn">Clear Cache</button>
        </div>
        <div class="status-line" id="cache-status"></div>
        <table class="event-table">
          <thead><tr><th>Domain</th><th>IP</th><th>TTL</th></tr></thead>
          <tbody id="cache-entries"></tbody>
        </table>
      </section>
      <section>
        <h2>Last Packet</h2>
        <table class="event-table">
          <tbody id="last-packet"></tbody>
        </table>
      </section>
    </div>
  </main>
  <script>
    const $ = (id) => document.getElementById(id);
    const escapeHtml = (value) => String(value ?? "").replace(/[&<>"']/g, (c) => ({
      "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
    }[c]));
    function actionLabel(source) {
      return {
        "local-answer": "Local A",
        "local-nxdomain": "NXDOMAIN",
        "forward": "Forward",
        "cache-hit": "Cache Hit",
        "error": "Error"
      }[source] || source || "unknown";
    }
    async function fetchJson(url, options) {
      const response = await fetch(url, options);
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || response.statusText);
      return data;
    }
    function render(snapshot) {
      $("chip-listen").textContent = `listen ${snapshot.config.listen_host}:${snapshot.config.listen_port}`;
      $("chip-upstream").textContent = `upstream ${snapshot.config.upstream_host}:${snapshot.config.upstream_port}`;
      $("chip-db").textContent = snapshot.config.db_file;
      $("listen").textContent = `${snapshot.config.listen_host}:${snapshot.config.listen_port}`;
      $("upstream").textContent = `${snapshot.config.upstream_host}:${snapshot.config.upstream_port}`;
      $("db-file").textContent = snapshot.config.db_file;
      $("record-count").textContent = snapshot.records.length;
      $("started-at").textContent = snapshot.started_at;
      $("cache-count").textContent = snapshot.cache.length;
      for (const [key, value] of Object.entries(snapshot.counters)) {
        const el = $(`count-${key}`);
        if (el) el.textContent = value;
      }
      $("rules").innerHTML = snapshot.records.map((record) => {
        const source = record.ip === "0.0.0.0" ? "local-nxdomain" : "local-answer";
        return `<tr><td>${escapeHtml(record.domain)}</td><td>${escapeHtml(record.ip)}</td><td><span class="tag ${source}">${actionLabel(source)}</span></td></tr>`;
      }).join("") || `<tr><td colspan="3" class="muted">No local records loaded.</td></tr>`;
      $("cache-entries").innerHTML = snapshot.cache.map((entry) => `
        <tr><td>${escapeHtml(entry.domain)}</td><td>${escapeHtml(entry.answer_ip || "-")}</td><td>${escapeHtml(entry.ttl_remaining)}s</td></tr>
      `).join("") || `<tr><td colspan="3" class="muted">No cached upstream responses.</td></tr>`;
      $("events").innerHTML = snapshot.events.map((event) => `
        <div class="log-item">
          <div class="log-top"><span class="log-domain">${escapeHtml(event.domain || "(parse error)")}</span><span class="tag ${event.source}">${actionLabel(event.source)}</span></div>
          <div class="muted">${escapeHtml(event.time)} | client ${escapeHtml(event.client)} | type ${escapeHtml(event.qtype)} | rcode ${escapeHtml(event.rcode)}</div>
          <div>${escapeHtml(event.message)}</div>
        </div>
      `).join("") || `<div class="muted">No DNS queries yet.</div>`;
      const last = snapshot.events[0] || {};
      $("last-packet").innerHTML = ["id", "domain", "qtype", "qclass", "source", "rcode", "answer_ip", "duration_ms", "bytes_in", "bytes_out"].map((key) => (
        `<tr><th>${key}</th><td>${escapeHtml(last[key] ?? "-")}</td></tr>`
      )).join("");
    }
    async function refresh() {
      try {
        render(await fetchJson("/api/status"));
      } catch (error) {
        $("chip-status").textContent = "offline";
      }
    }
    async function reloadRules() {
      $("reload-status").textContent = "Reloading dnsrelay.txt...";
      try {
        const data = await fetchJson("/api/reload", { method: "POST" });
        $("reload-status").textContent = `Loaded ${data.record_count} records.`;
        await refresh();
      } catch (error) {
        $("reload-status").textContent = error.message;
      }
    }
    async function clearCache() {
      $("cache-status").textContent = "Clearing cache...";
      try {
        const data = await fetchJson("/api/cache/clear", { method: "POST" });
        $("cache-status").textContent = `Cleared ${data.cleared} cached responses.`;
        await refresh();
      } catch (error) {
        $("cache-status").textContent = error.message;
      }
    }
    async function sendTest(domain) {
      $("domain-input").value = domain || $("domain-input").value;
      $("test-result").textContent = "Sending DNS query to the relay...";
      try {
        const data = await fetchJson("/api/test", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ domain: $("domain-input").value })
        });
        $("test-result").textContent = `${data.domain}: rcode=${data.rcode}, answers=${data.answer_count}, first A=${data.answer_ip || "-"}`;
        await refresh();
      } catch (error) {
        $("test-result").textContent = error.message;
      }
    }
    $("reload-btn").addEventListener("click", reloadRules);
    $("clear-cache-btn").addEventListener("click", clearCache);
    $("send-test").addEventListener("click", () => sendTest());
    document.querySelectorAll("[data-test]").forEach((button) => {
      button.addEventListener("click", () => sendTest(button.dataset.test));
    });
    refresh();
    setInterval(refresh, 1000);
  </script>
</body>
</html>
"""


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


class RelayState:
    def __init__(self):
        self.lock = threading.Lock()
        self.started_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.config = {}
        self.records = {}
        self.cache_entries = []
        self.events = deque(maxlen=EVENT_LIMIT)
        self.counters = {
            "local-answer": 0,
            "local-nxdomain": 0,
            "forward": 0,
            "cache-hit": 0,
            "error": 0,
        }
        self.next_event_id = 1

    def configure(self, listen_host, listen_port, upstream_host, upstream_port, db_file):
        with self.lock:
            self.config = {
                "listen_host": listen_host,
                "listen_port": listen_port,
                "upstream_host": upstream_host,
                "upstream_port": upstream_port,
                "db_file": db_file,
            }

    def set_records(self, records):
        with self.lock:
            self.records = dict(records)

    def set_cache_entries(self, entries):
        with self.lock:
            self.cache_entries = list(entries)

    def add_event(self, source, message, **details):
        with self.lock:
            event = {
                "id": self.next_event_id,
                "time": datetime.now().strftime("%H:%M:%S"),
                "source": source,
                "message": message,
                **details,
            }
            self.next_event_id += 1
            self.events.appendleft(event)
            if source in self.counters:
                self.counters[source] += 1
            else:
                self.counters["error"] += 1

    def snapshot(self):
        with self.lock:
            records = [
                {"domain": domain, "ip": ip}
                for domain, ip in sorted(self.records.items())
            ]
            return {
                "started_at": self.started_at,
                "config": dict(self.config),
                "records": records,
                "cache": list(self.cache_entries),
                "events": list(self.events),
                "counters": dict(self.counters),
            }


class DNSCache:
    def __init__(self, limit=CACHE_LIMIT):
        self.lock = threading.Lock()
        self.limit = limit
        self.entries = {}

    def get(self, key):
        now = time.time()
        with self.lock:
            entry = self.entries.get(key)
            if entry is None:
                return None
            if entry["expires_at"] <= now:
                del self.entries[key]
                return None
            return dict(entry)

    def set(self, key, response, summary, ttl):
        ttl = max(0, int(ttl))
        if ttl <= 0:
            return
        now = time.time()
        with self.lock:
            if len(self.entries) >= self.limit and key not in self.entries:
                oldest_key = min(self.entries, key=lambda item: self.entries[item]["expires_at"])
                del self.entries[oldest_key]
            self.entries[key] = {
                "response": response,
                "summary": dict(summary),
                "ttl": ttl,
                "stored_at": now,
                "expires_at": now + ttl,
            }

    def clear(self):
        with self.lock:
            cleared = len(self.entries)
            self.entries.clear()
            return cleared

    def snapshot(self):
        now = time.time()
        rows = []
        expired = []
        with self.lock:
            for key, entry in self.entries.items():
                remaining = int(entry["expires_at"] - now)
                if remaining <= 0:
                    expired.append(key)
                    continue
                domain, qtype, qclass = key
                rows.append({
                    "domain": domain,
                    "qtype": qtype,
                    "qclass": qclass,
                    "answer_ip": entry["summary"].get("answer_ip"),
                    "ttl_remaining": remaining,
                })
            for key in expired:
                del self.entries[key]
        return sorted(rows, key=lambda row: row["domain"])


class DashboardServer(ThreadingHTTPServer):
    def __init__(self, server_address, request_handler_class, state, reload_callback, clear_cache_callback):
        super().__init__(server_address, request_handler_class)
        self.state = state
        self.reload_callback = reload_callback
        self.clear_cache_callback = clear_cache_callback


class DashboardHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        return

    def _send_json(self, payload, status=200):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self):
        length = int(self.headers.get("Content-Length", "0") or "0")
        if length == 0:
            return {}
        raw = self.rfile.read(length)
        return json.loads(raw.decode("utf-8"))

    def do_GET(self):
        if self.path == "/" or self.path == "/index.html":
            body = DASHBOARD_HTML.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path == "/api/status":
            self._send_json(self.server.state.snapshot())
            return
        self._send_json({"error": "not found"}, 404)

    def do_POST(self):
        if self.path == "/api/reload":
            try:
                records = self.server.reload_callback()
            except Exception as exc:
                self._send_json({"error": str(exc)}, 500)
                return
            self._send_json({"record_count": len(records)})
            return
        if self.path == "/api/test":
            try:
                payload = self._read_json()
                domain = payload.get("domain", "")
                result = run_dashboard_test_query(domain, self.server.state)
            except Exception as exc:
                self._send_json({"error": str(exc)}, 400)
                return
            self._send_json(result)
            return
        if self.path == "/api/cache/clear":
            cleared = self.server.clear_cache_callback()
            self._send_json({"cleared": cleared})
            return
        self._send_json({"error": "not found"}, 404)


def start_dashboard(host, port, state, reload_callback, clear_cache_callback):
    server = DashboardServer((host, port), DashboardHandler, state, reload_callback, clear_cache_callback)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    log(f"Dashboard available at http://{host}:{port}")
    return server


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


def skip_domain_name(packet, offset):
    while True:
        if offset >= len(packet):
            raise ValueError("domain name exceeds packet length")
        length = packet[offset]
        if length == 0:
            return offset + 1
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(packet):
                raise ValueError("truncated compressed domain pointer")
            return offset + 2
        if length & 0xC0:
            raise ValueError("unsupported domain label format")
        offset += 1 + length


def parse_dns_response_summary(packet):
    if len(packet) < DNS_HEADER_SIZE:
        raise ValueError("packet shorter than DNS header")

    query_id, flags, qdcount, ancount, nscount, arcount = struct.unpack(
        "!HHHHHH",
        packet[:DNS_HEADER_SIZE],
    )
    rcode = flags & 0x000F
    offset = DNS_HEADER_SIZE
    for _ in range(qdcount):
        offset = skip_domain_name(packet, offset)
        offset += 4

    answer_ip = None
    min_ttl = None
    for _ in range(ancount):
        offset = skip_domain_name(packet, offset)
        if offset + 10 > len(packet):
            break
        rr_type, rr_class, ttl, rdlength = struct.unpack("!HHIH", packet[offset:offset + 10])
        offset += 10
        rdata_end = offset + rdlength
        if rdata_end > len(packet):
            break
        if rr_type == TYPE_A and rr_class == CLASS_IN and rdlength == 4 and answer_ip is None:
            answer_ip = socket.inet_ntoa(packet[offset:rdata_end])
        if rr_type == TYPE_A and rr_class == CLASS_IN:
            min_ttl = ttl if min_ttl is None else min(min_ttl, ttl)
        offset = rdata_end

    return {
        "id": query_id,
        "rcode": rcode,
        "answer_count": ancount,
        "authority_count": nscount,
        "additional_count": arcount,
        "answer_ip": answer_ip,
        "min_ttl": min_ttl,
    }


def build_dns_query(domain, query_id=None, qtype=TYPE_A, qclass=CLASS_IN):
    query_id = int(query_id if query_id is not None else int(time.time() * 1000) & 0xFFFF)
    labels = []
    for label in normalize_domain(domain).split("."):
        if not label:
            continue
        encoded = label.encode("ascii")
        if len(encoded) > 63:
            raise ValueError("domain label is longer than 63 bytes")
        labels.append(bytes([len(encoded)]) + encoded)
    if not labels:
        raise ValueError("domain is empty")

    header = struct.pack("!HHHHHH", query_id, 0x0100, 1, 0, 0, 0)
    question = b"".join(labels) + b"\x00" + struct.pack("!HH", qtype, qclass)
    return header + question


def run_dashboard_test_query(domain, state):
    domain = normalize_domain(domain)
    snapshot = state.snapshot()
    config = snapshot["config"]
    query = build_dns_query(domain)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as test_sock:
        test_sock.settimeout(UPSTREAM_TIMEOUT)
        test_sock.sendto(query, (config["listen_host"], config["listen_port"]))
        response, _ = test_sock.recvfrom(BUFFER_SIZE)
    summary = parse_dns_response_summary(response)
    return {
        "domain": domain,
        **summary,
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


def build_server_failure_response(query):
    try:
        parsed = parse_dns_query(query)
    except ValueError:
        query_id = struct.unpack("!H", query[:2])[0] if len(query) >= 2 else 0
        header = struct.pack(
            "!HHHHHH",
            query_id,
            build_response_flags(0, RCODE_SERVER_FAILURE),
            0,
            0,
            0,
            0,
        )
        return header

    header = struct.pack(
        "!HHHHHH",
        parsed["id"],
        build_response_flags(parsed["flags"], RCODE_SERVER_FAILURE),
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


def handle_query(query, upstream_addr, local_records, cache=None):
    try:
        parsed = parse_dns_query(query)
    except ValueError as exc:
        log(f"Could not parse query: {exc}; forwarding")
        response = forward_query(query, upstream_addr)
        return response, "forward", {
            "domain": "",
            "qtype": "",
            "qclass": "",
            "rcode": "",
            "answer_ip": "",
            "message": f"Parse failed; forwarded raw packet: {exc}",
        }

    domain = parsed["domain"]
    qtype = parsed["qtype"]
    qclass = parsed["qclass"]
    log(f"Query domain={domain}, type={qtype}, class={qclass}")

    local_ip = local_records.get(domain)
    if local_ip is None:
        cache_key = (domain, qtype, qclass)
        if cache is not None:
            cached = cache.get(cache_key)
            if cached is not None:
                response = response_with_query_id(cached["response"], parsed["id"])
                summary = parse_dns_response_summary(response)
                log("Cache hit; returning stored upstream response")
                return response, "cache-hit", {
                    **parsed,
                    **summary,
                    "message": "Returned cached upstream response",
                }

        log("No local record; forwarding")
        response = forward_query(query, upstream_addr)
        summary = parse_dns_response_summary(response)
        if (
            cache is not None
            and qtype == TYPE_A
            and qclass == CLASS_IN
            and summary.get("rcode") == 0
            and summary.get("answer_count", 0) > 0
            and summary.get("min_ttl")
        ):
            cache.set(cache_key, response, summary, summary["min_ttl"])
        return response, "forward", {
            **parsed,
            **summary,
            "message": "No local rule; forwarded to upstream DNS",
        }

    if local_ip == "0.0.0.0":
        log("Local record is 0.0.0.0; returning NXDOMAIN")
        response = build_name_error_response(query, parsed)
        summary = parse_dns_response_summary(response)
        return response, "local-nxdomain", {
            **parsed,
            **summary,
            "message": "Local rule is 0.0.0.0; returned NXDOMAIN",
        }

    if qtype != TYPE_A or qclass != CLASS_IN:
        log("Local record exists, but query type/class is unsupported; forwarding")
        response = forward_query(query, upstream_addr)
        summary = parse_dns_response_summary(response)
        return response, "forward", {
            **parsed,
            **summary,
            "message": "Local rule exists, but query is not A/IN; forwarded",
        }

    log(f"Local hit; returning {local_ip}")
    response = build_a_record_response(query, parsed, local_ip)
    summary = parse_dns_response_summary(response)
    return response, "local-answer", {
        **parsed,
        **summary,
        "message": f"Local A record matched; returned {local_ip}",
    }


def run_relay(
    listen_host,
    listen_port,
    upstream_host,
    upstream_port,
    db_file,
    dashboard_host=None,
    dashboard_port=None,
):
    listen_addr = (listen_host, listen_port)
    upstream_addr = (upstream_host, upstream_port)
    local_records = load_local_records(db_file)
    cache = DNSCache()
    state = RelayState()
    state.configure(listen_host, listen_port, upstream_host, upstream_port, db_file)
    state.set_records(local_records)
    state.set_cache_entries(cache.snapshot())

    def reload_records():
        nonlocal local_records
        local_records = load_local_records(db_file)
        state.set_records(local_records)
        log(f"Reloaded {len(local_records)} local records from {db_file}")
        return local_records

    def clear_cache():
        cleared = cache.clear()
        state.set_cache_entries(cache.snapshot())
        log(f"Cleared {cleared} cached upstream responses")
        return cleared

    if dashboard_host and dashboard_port:
        start_dashboard(dashboard_host, dashboard_port, state, reload_records, clear_cache)

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as relay_sock:
        relay_sock.bind(listen_addr)
        log(f"DNS Relay listening on {listen_host}:{listen_port}")
        log(f"Forwarding queries to upstream DNS {upstream_host}:{upstream_port}")
        log(f"Loaded {len(local_records)} local records from {db_file}")

        while True:
            query, client_addr = relay_sock.recvfrom(BUFFER_SIZE)
            log(f"Received {len(query)} bytes from {client_addr[0]}:{client_addr[1]}")
            started = time.monotonic()

            try:
                response, source, details = handle_query(query, upstream_addr, local_records, cache)
            except socket.timeout:
                log("Upstream DNS timeout; returning SERVFAIL")
                response = build_server_failure_response(query)
                relay_sock.sendto(response, client_addr)
                summary = parse_dns_response_summary(response)
                state.add_event(
                    "error",
                    "Upstream DNS timeout; returned SERVFAIL",
                    client=f"{client_addr[0]}:{client_addr[1]}",
                    domain="",
                    qtype="",
                    qclass="",
                    rcode=summary.get("rcode", RCODE_SERVER_FAILURE),
                    answer_ip="",
                    duration_ms=round((time.monotonic() - started) * 1000, 2),
                    bytes_in=len(query),
                    bytes_out=len(response),
                )
                continue
            except OSError as exc:
                log(f"Upstream DNS error: {exc}; returning SERVFAIL")
                response = build_server_failure_response(query)
                relay_sock.sendto(response, client_addr)
                summary = parse_dns_response_summary(response)
                state.add_event(
                    "error",
                    f"Upstream DNS error: {exc}; returned SERVFAIL",
                    client=f"{client_addr[0]}:{client_addr[1]}",
                    domain="",
                    qtype="",
                    qclass="",
                    rcode=summary.get("rcode", RCODE_SERVER_FAILURE),
                    answer_ip="",
                    duration_ms=round((time.monotonic() - started) * 1000, 2),
                    bytes_in=len(query),
                    bytes_out=len(response),
                )
                continue

            relay_sock.sendto(response, client_addr)
            state.set_cache_entries(cache.snapshot())
            state.add_event(
                source,
                details.get("message", source),
                client=f"{client_addr[0]}:{client_addr[1]}",
                domain=details.get("domain", ""),
                qtype=details.get("qtype", ""),
                qclass=details.get("qclass", ""),
                rcode=details.get("rcode", ""),
                answer_ip=details.get("answer_ip", ""),
                duration_ms=round((time.monotonic() - started) * 1000, 2),
                bytes_in=len(query),
                bytes_out=len(response),
            )
            log(f"Sent {len(response)} bytes to {client_addr[0]}:{client_addr[1]} ({source})")


def parse_args(argv):
    parser = argparse.ArgumentParser(description="DNS relay with local hosts-like rules.")
    parser.add_argument("--listen-host", default=DEFAULT_LISTEN_HOST)
    parser.add_argument("--listen-port", type=int, default=DEFAULT_LISTEN_PORT)
    parser.add_argument("--upstream-host", default=DEFAULT_UPSTREAM_HOST)
    parser.add_argument("--upstream-port", type=int, default=DEFAULT_UPSTREAM_PORT)
    parser.add_argument("--db-file", default=DEFAULT_DB_FILE)
    parser.add_argument("--dashboard-host", default=DEFAULT_DASHBOARD_HOST)
    parser.add_argument("--dashboard-port", type=int, default=DEFAULT_DASHBOARD_PORT)
    parser.add_argument("--no-dashboard", action="store_true")
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
            None if args.no_dashboard else args.dashboard_host,
            None if args.no_dashboard else args.dashboard_port,
        )
    except PermissionError:
        log("Permission denied. Try --listen-port 10053, or run as administrator for port 53.")
        return 1
    except KeyboardInterrupt:
        log("DNS Relay stopped")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
