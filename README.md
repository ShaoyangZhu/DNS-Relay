# DNS Relay 课程设计

这是一个基于 Python UDP Socket 实现的 DNS Relay 程序，用于通信与网络课程设计。

程序监听本机 DNS 查询请求，先查询本地数据库 `dnsrelay.txt`，如果本地命中则直接返回响应；如果本地没有记录，则把原始 DNS 查询转发给上游 DNS 服务器，并把上游响应返回给客户端。

## 已实现功能

- 监听 UDP DNS 查询请求
- 解析 DNS Question Section 中的查询域名、查询类型和查询类
- 支持本地 A 记录应答
- 支持通过 `0.0.0.0` 屏蔽域名，并返回 NXDOMAIN
- 本地未命中时转发到上游 DNS
- 对上游成功返回的 A/IN 响应进行 TTL 缓存，重复查询可直接从缓存返回
- 上游 DNS 超时或出错时返回 SERVFAIL（RCODE=2），避免客户端一直等待
- 提供 Web 可视化控制台，展示运行状态、本地规则、三种处理路径、实时查询日志和统计计数
- 支持在可视化页面中一键发送测试查询、重载 `dnsrelay.txt`、查看并清空 DNS 缓存
- 支持命令行参数配置监听地址、监听端口、上游 DNS 和本地数据库文件
- 输出运行日志，方便调试和写实验报告

## 文件说明

```text
dnsrelay.py   主程序
dnsrelay.txt  本地域名数据库
.gitignore    Git 忽略规则
```

## 本地数据库格式

`dnsrelay.txt` 每行一条记录：

```text
IPv4地址 域名
```

示例：

```text
1.2.3.4 local.test
5.6.7.8 example.local
0.0.0.0 blocked.test
```

含义：

- `1.2.3.4 local.test`：查询 `local.test` 时直接返回 `1.2.3.4`
- `0.0.0.0 blocked.test`：查询 `blocked.test` 时返回 NXDOMAIN，表示该域名不存在

程序也兼容下面这种顺序：

```text
local.test 1.2.3.4
```

## 运行方式

默认监听 `127.0.0.1:10053`，上游 DNS 为 `8.8.8.8:53`：

```powershell
python dnsrelay.py
```

程序默认同时启动可视化控制台：

```text
http://127.0.0.1:18080
```

如果想指定控制台端口：

```powershell
python dnsrelay.py --dashboard-port 18081
```

如果只想运行命令行 DNS Relay，不启动可视化控制台：

```powershell
python dnsrelay.py --no-dashboard
```

课程实验中如果需要监听标准 DNS 端口 `53`，请用管理员权限打开 PowerShell，然后运行：

```powershell
python dnsrelay.py --listen-port 53
```

也可以指定上游 DNS：

```powershell
python dnsrelay.py --listen-port 53 --upstream-host 114.114.114.114
```

## 测试方法

### 方法一：使用可视化控制台

打开：

```text
http://127.0.0.1:18080
```

页面中可以直接点击：

- `Local A`：测试 `local.test`，应命中本地 A 记录
- `NXDOMAIN`：测试 `blocked.test`，应返回 RCODE=3
- `Forward`：测试 `www.baidu.com`，应转发给上游 DNS

页面会实时展示：

- 本地规则表
- Client -> Relay -> Upstream DNS 流程
- Local Answer、NXDOMAIN、Forwarded、Error 计数
- Cache Hit 计数和当前缓存条目
- 最近 DNS 查询事件
- 最后一个报文的 ID、QTYPE、QCLASS、RCODE、返回 IP 和字节数

点击 `Reload Rules` 可以在不重启程序的情况下重新读取 `dnsrelay.txt`。

点击 `Clear Cache` 可以清空上游 DNS 响应缓存。

缓存说明：

- 只缓存本地未命中后由上游 DNS 成功返回的 A/IN 响应
- 缓存过期时间来自 DNS 响应里的 TTL
- 本地规则命中和 `0.0.0.0` 屏蔽规则不会进入缓存

### 方法二：使用 nslookup

如果程序监听的是 `53` 端口，可以使用：

```powershell
nslookup local.test 127.0.0.1
nslookup blocked.test 127.0.0.1
nslookup www.baidu.com 127.0.0.1
```

预期结果：

- `local.test` 返回 `1.2.3.4`
- `blocked.test` 返回 `Non-existent domain`
- `www.baidu.com` 由上游 DNS 正常解析

如果程序监听的是默认的 `10053` 端口，`nslookup` 不方便直接指定端口，可以使用 Python 测试脚本或把程序改为监听 `53` 端口后测试。

## Wireshark 抓包建议

抓包过滤条件：

```text
dns
```

或：

```text
udp.port == 53
```

如果使用 `127.0.0.1` 测试，Wireshark 中应选择 loopback 相关网卡，例如：

```text
Adapter for loopback traffic capture
```

报告中建议截图展示：

- 本地域名命中并返回 A 记录
- `0.0.0.0` 域名返回 NXDOMAIN
- 未命中域名转发给上游 DNS 并返回结果

## 代码结构简述

程序主要流程：

```text
启动程序
  读取 dnsrelay.txt
  绑定 UDP 监听端口

循环接收 DNS 请求
  解析查询域名和查询类型
  查询本地数据库
    如果 IP 是 0.0.0.0，返回 NXDOMAIN
    如果是普通 IPv4 地址，构造 A 记录响应
    如果本地没有记录，转发给上游 DNS
  将响应发送回客户端
```

核心函数：

- `load_local_records()`：读取本地域名数据库
- `parse_dns_query()`：解析 DNS 查询报文
- `build_a_record_response()`：构造 A 记录响应
- `build_name_error_response()`：构造 NXDOMAIN 响应
- `forward_query()`：转发 DNS 请求到上游服务器
- `run_relay()`：主循环

## 注意事项

- Windows 下监听 `53` 端口通常需要管理员权限
- 如果 `53` 端口被其他 DNS 服务占用，需要先关闭占用进程或换端口测试
- `nslookup` 可能会额外发送 PTR 或 AAAA 查询，日志中出现 `type=12` 或 `type=28` 是正常现象
