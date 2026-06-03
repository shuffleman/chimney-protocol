# Chimney 开发者部署与运维手册

本文档面向后续接手 `chimney-protocol` 的开发者。它不是产品介绍，也不是协议论文摘要，而是一份可以直接用于开发、构建、部署、排障和发布的工程手册。

最后更新：2026-06-04

## 0. 读者定位

接手本项目时，建议先把下面几件事分清：

- `cmd/chimney-relay` 是服务端二进制，部署在公网 Linux 机器上。
- `cmd/chimney-client` 是本地 SOCKS5 客户端，通常运行在开发者 Windows 机器或用户本机。
- 根目录 `chimney.go` 导出 Go 库 Dialer API，给 sing-box、Xray-core 或其他 Go 程序集成使用。
- `config/client.yaml.example` 当前只是配置包支持的示例；`cmd/chimney-client` 目前不支持 `-config`，只能用 flags。
- `Makefile run-client` 里仍写着 `-config config/client.yaml`，这与当前 client CLI 不一致，不能直接作为真实启动命令使用。
- `docs/project-analysis.md` 是项目地图；本文档才是部署和开发交接手册。

## 1. 当前真实部署拓扑

当前测试拓扑是：

```text
Windows 开发机
  ├─ chimney-client.exe
  │    └─ SOCKS5 监听 127.0.0.1:1080
  │
  └─ curl / 浏览器 / 其他本地应用
       └─ socks5h://127.0.0.1:1080

Internet
  └─ TCP 8444

Linux 测试服务器
  └─ chimney-relay
       ├─ 监听 0.0.0.0:8444
       ├─ TLS 握手阶段转发到白名单 SNI，例如 cloudflare.com:443
       └─ swap 成功后连接 SOCKS5 请求里的真实目标，例如 speedtest.tokyo2.linode.com:80
```

端到端数据路径：

```text
本地应用
  -> 本地 SOCKS5 127.0.0.1:1080
  -> chimney-client
  -> Chimney tunnel
  -> chimney-relay
  -> 真实目标 host:port
```

重要语义：

- client 的 `-relay` 是 relay 地址。
- client 的 `-sni` 是 TLS 借道站点，必须在 relay 的 `intent.yaml` 中。
- client 的 `-dest` 当前是必填历史参数，但在 SOCKS5 模式下，真实出口目标来自 SOCKS5 CONNECT 请求。
- curl 必须用 `socks5h://` 或 `--socks5-hostname`，这样 DNS 解析由 relay 侧完成；如果用 `socks5://`，域名可能先在本机解析。
- relay 的 `default_backend` 为空时，非认证流量或失败路径不会转发到固定后端，而是自然关闭。

## 2. 仓库结构速查

```text
.
├── chimney.go
├── cmd
│   ├── chimney-client
│   ├── chimney-relay
│   ├── socks_stress
│   ├── h2probe
│   ├── calibrate
│   ├── speedtest
│   ├── remote-throughputtest
│   ├── tcp_page_test
│   ├── tcp_raw_test
│   └── upload_debug
├── config
│   ├── relay-speedtest.yaml
│   ├── relay-test.yaml
│   ├── relay.yaml.example
│   ├── client.yaml.example
│   ├── intent.yaml
│   └── enforce.yaml
├── internal
│   ├── auth
│   ├── config
│   ├── dilution
│   ├── h2engine
│   ├── keyderiv
│   ├── pcap
│   ├── profile
│   ├── record
│   ├── relay
│   └── whitelist
├── docker
├── docs
├── README.md
├── Makefile
├── go.mod
└── Chimney-完整设计与实现规格.md
```

核心文件：

| 路径 | 用途 | 接手时重点看什么 |
| --- | --- | --- |
| `chimney.go` | 公共 Go API | `Config`、`NewDialer`、`DialContext`、连接池和自动重连 |
| `cmd/chimney-client/main.go` | 本地 SOCKS5 client | flags、`tunnelManager`、SOCKS5 CONNECT 到 H2 stream 的映射 |
| `cmd/chimney-client/fingerprint.go` | CLI 指纹轮换 | 可用 uTLS fingerprint 名称 |
| `cmd/chimney-relay/main.go` | relay 入口 | YAML 加载、systemd 日志、admin API |
| `internal/relay/relay.go` | relay 核心逻辑 | 握手转发、白名单校验、swap、CONNECT 后端 |
| `internal/h2engine/h2engine.go` | H2 帧层 | SETTINGS、DATA、padding、reserved stream |
| `internal/record/record.go` | ChimneyRecord | AEAD record 编解码、序号、错误诊断 |
| `internal/keyderiv/keyderiv.go` | 密钥派生 | auth tag、directional keys、nonce |
| `internal/auth/auth.go` | 多用户认证 | `UserStore`、key hint、PSK 派生 |
| `internal/config/config.go` | YAML 配置 | relay/client 配置结构和校验 |
| `internal/whitelist/whitelist.go` | 双层白名单 | SNI intent 与 CIDR enforce |

辅助工具：

| 命令 | 用途 |
| --- | --- |
| `cmd/socks_stress` | 通过 SOCKS5 进行多连接字节校验压测 |
| `cmd/h2probe` | 探测真实站点 HTTP/2 SETTINGS |
| `cmd/calibrate` | 从 pcap/keylog 生成或校准 profile |
| `cmd/speedtest` | 项目内速度测试辅助工具 |
| `cmd/remote-throughputtest` | 远端吞吐测试辅助工具 |
| `cmd/tcp_page_test`、`cmd/tcp_raw_test` | TCP 行为调试 |

## 3. 环境要求

### 3.1 开发机

推荐环境：

- Go 1.23 或兼容版本。
- Git。
- Windows PowerShell 7 或 Windows PowerShell 5.1。
- `curl.exe`，Windows 10/11 通常自带。
- 可选：gcc/cgo 工具链，仅 `go test -race` 或 `make test` 需要。

检查：

```powershell
go version
git status --short
curl.exe --version
```

注意：

- Windows 下 `make test` 默认会跑 `go test -race ./...`，如果没有 gcc/cgo 会失败。
- 文档、普通构建和基础测试优先用 `go test ./...`。
- PowerShell 当前会话设置 `GOOS`/`GOARCH` 后要记得清理，否则后续本地构建可能继续生成 Linux 二进制。

### 3.2 Linux relay 主机

推荐环境：

- Linux amd64。
- systemd。
- root 或具备 systemd 管理权限的用户。
- 可公网访问 relay 监听端口，例如 `8444/tcp`。
- 服务器能访问白名单 SNI，例如 `cloudflare.com:443`。
- 服务器能访问真实测试目标，例如 `speedtest.tokyo2.linode.com:80`。

检查：

```bash
uname -a
systemctl --version
ss -ltnp
curl -I --connect-timeout 10 https://cloudflare.com
curl -I --connect-timeout 10 http://speedtest.tokyo2.linode.com/100MB-tokyo2.bin
```

## 4. 构建手册

以下命令默认在仓库根目录执行。

### 4.1 下载依赖

```powershell
go mod download
```

### 4.2 Windows 本地构建

```powershell
New-Item -ItemType Directory -Force build\bin | Out-Null

go build -o build\bin\chimney-relay.exe .\cmd\chimney-relay
go build -o build\bin\chimney-client.exe .\cmd\chimney-client
go build -o build\bin\socks_stress.exe .\cmd\socks_stress
go build -o build\bin\h2probe.exe .\cmd\h2probe
go build -o build\bin\calibrate.exe .\cmd\calibrate
```

### 4.3 Linux relay 交叉编译

```powershell
$env:GOOS='linux'
$env:GOARCH='amd64'
$env:CGO_ENABLED='0'

go build -o build\bin\chimney-relay-linux-amd64 .\cmd\chimney-relay
```

恢复 PowerShell 构建环境：

```powershell
Remove-Item Env:\GOOS -ErrorAction SilentlyContinue
Remove-Item Env:\GOARCH -ErrorAction SilentlyContinue
Remove-Item Env:\CGO_ENABLED -ErrorAction SilentlyContinue
```

确认产物：

```powershell
Get-ChildItem build\bin
```

### 4.4 Linux/macOS 本机构建

```bash
mkdir -p build/bin
go build -o build/bin/chimney-relay ./cmd/chimney-relay
go build -o build/bin/chimney-client ./cmd/chimney-client
go build -o build/bin/socks_stress ./cmd/socks_stress
```

### 4.5 Makefile 现状

可用：

```bash
make build
make build-relay
make build-client
make vet
make bench
```

谨慎使用：

```bash
make test
```

原因：它使用 `-race`，Windows 未安装 cgo 工具链时会失败。

不要直接依赖：

```bash
make run-client
```

原因：当前 Makefile 仍调用 `chimney-client -config config/client.yaml`，但当前 `cmd/chimney-client` 没有 `-config` 参数。

## 5. 配置文件详解

### 5.1 relay 配置字段

配置结构来自 `internal/config/RelayConfig`。

| 字段 | 类型 | 必填 | 当前说明 |
| --- | --- | --- | --- |
| `listen_addr` | string | 是 | relay 监听地址，例如 `":8444"` 或 `"0.0.0.0:8444"` |
| `psk` | string | 三选一 | 单用户 hex PSK |
| `users` | map | 三选一 | 用户名到 hex PSK 的映射 |
| `user_ids` | list | 三选一 | 推荐模式，PSK = SHA256(userID) |
| `tag_len` | int | 是 | auth tag 长度，校验允许 8 到 32，常用 16 |
| `intent_file` | string | 是 | 意图白名单 YAML |
| `enforce_file` | string | 是 | CIDR 执行白名单 YAML |
| `cloud_region` | string | 是 | CIDR 校验区域标识，例如 `us-east-1` |
| `default_backend` | string | 否 | 非认证或失败路径后端；为空表示自然关闭 |
| `handshake_timeout` | duration | 否 | TLS 握手转发超时，默认 10s |
| `auth_read_timeout` | duration | 否 | swap/auth 阶段读取超时，默认 5s |
| `enable_profiling` | bool | 否 | relay 侧 profile/pacing 开关 |
| `profile_dir` | string | 否 | profile 目录字段存在，但当前没有完整按站点加载 |
| `cidr_refresh_interval` | duration | 否 | 配置字段存在，admin refresh 当前仍偏占位 |
| `log_level` | string | 否 | `debug`、`info`、`warn`、`error` |
| `metrics_addr` | string | 否 | 启动 JSON admin API，不是 Prometheus 文本指标 |
| `metrics_token` | string | 否 | Admin API token；为空时 `/admin/*` 仅允许 loopback client |

当前速度测试配置 `config/relay-speedtest.yaml`：

```yaml
listen_addr: ":8444"
psk: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
tag_len: 16
intent_file: "config/intent.yaml"
enforce_file: "config/enforce.yaml"
cloud_region: "us-east-1"
default_backend: ""
handshake_timeout: 10s
auth_read_timeout: 5s
enable_profiling: false
log_level: "debug"
```

### 5.2 认证模式

单用户 PSK：

```yaml
psk: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
```

显式多用户：

```yaml
users:
  alice: "64-char-hex-psk"
  bob: "64-char-hex-psk"
```

推荐多用户 `user_ids`：

```yaml
user_ids:
  - "550e8400-e29b-41d4-a716-446655440000"
  - "660e8400-e29b-41d4-a716-446655440001"
```

client 对应：

```powershell
# 显式 PSK
.\build\bin\chimney-client.exe -psk 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef ...

# user-id 自动派生
.\build\bin\chimney-client.exe -user-id 550e8400-e29b-41d4-a716-446655440000 ...
```

注意：

- client 如果没有传 `-psk`，会用 `-user-id` 派生 PSK。
- client 如果 `-user-id` 也为空，会使用 `"default"`。
- relay/client 的 `tag_len` 必须一致。

### 5.3 intent.yaml

`config/intent.yaml` 控制允许借道的 SNI。

当前文件包含：

- `cloudflare.com`
- `g.alicdn.com`
- `www.apple.com`
- `www.google.com`
- `www.microsoft.com`

每个 entry 包含：

```yaml
cloudflare.com:
  sni: cloudflare.com
  description: Live-captured 2026-06-02
  settings_snapshot:
    ENABLE_PUSH: 0
    HEADER_TABLE_SIZE: 4096
    INITIAL_WINDOW_SIZE: 65536
    MAX_CONCURRENT_STREAMS: 100
    MAX_FRAME_SIZE: 16777215
```

排障意义：

- client 的 `-sni` 必须命中 `entries`。
- relay 会根据 SNI 决定是否允许握手借道。
- `settings_snapshot` 表示真实站点采样值，但当前 H2 默认 SETTINGS 仍主要来自 `internal/h2engine.DefaultSettings()`，不要误以为所有站点 profile 已自动动态加载。

### 5.4 enforce.yaml

`config/enforce.yaml` 控制执行层 CIDR。

排障意义：

- relay 解析白名单 SNI 后，目标 IP 必须落在 enforce 允许范围。
- 如果 SNI 是 `cloudflare.com`，但 DNS 解析结果不在允许 CIDR，relay 会拒绝。
- 云厂商 IP 范围经常变化，后续需要补真实 refresh 逻辑。

### 5.5 client.yaml.example 的真实状态

`internal/config` 里有 `ClientConfig` 和 `LoadClientConfig`，但当前 `cmd/chimney-client/main.go` 没有 `-config` flag。

因此：

- 外部 Go 程序可以复用配置结构。
- CLI 用户必须使用命令行 flags。
- 不要给部署脚本写 `chimney-client -config config/client.yaml`，除非先实现这个功能。

## 6. 本地单机开发流程

本节用于在一台开发机上快速验证二进制、SOCKS5 和 tunnel 逻辑。

### 6.1 构建

```powershell
go build -o build\bin\chimney-relay.exe .\cmd\chimney-relay
go build -o build\bin\chimney-client.exe .\cmd\chimney-client
```

### 6.2 启动本机 relay

终端 A：

```powershell
.\build\bin\chimney-relay.exe -config .\config\relay-speedtest.yaml
```

成功日志通常包含：

```text
chimney relay started
```

### 6.3 启动本机 client

终端 B：

```powershell
.\build\bin\chimney-client.exe `
  -relay 127.0.0.1:8444 `
  -sni cloudflare.com `
  -dest 127.0.0.1:1 `
  -psk 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef `
  -listen 127.0.0.1:1080 `
  -fingerprint chrome
```

成功日志通常包含：

```text
Chimney tunnel established
tunnel established
SOCKS5 proxy listening
```

### 6.4 curl 验证

终端 C：

```powershell
curl.exe -L --socks5-hostname 127.0.0.1:1080 https://www.cloudflare.com/cdn-cgi/trace
```

或者：

```powershell
curl.exe -x socks5h://127.0.0.1:1080 -I https://www.cloudflare.com/
```

### 6.5 常见本地失败

端口占用：

```powershell
netstat -ano | findstr :1080
netstat -ano | findstr :8444
```

杀掉旧进程：

```powershell
Stop-Process -Id <PID> -Force
```

PSK 不一致：

```text
relay 日志可能出现 auth_failures 增加，client 可能表现为 tunnel 建立失败或 CONNECT 失败。
```

SNI 不在白名单：

```text
relay 日志会出现 whitelist rejection 或握手阶段直接关闭。
```

## 7. 远端测试服务器部署

当前测试服务器连接方式：

```bash
ssh root@103.135.147.226 -p 15042
```

生产或多人开发时，建议把真实 IP、端口、密钥和 user id 放入团队内部密钥管理，不要写进公开文档。本手册保留当前测试命令是为了复现实验环境。

### 7.1 本地构建 Linux relay

```powershell
$env:GOOS='linux'
$env:GOARCH='amd64'
$env:CGO_ENABLED='0'
go build -o build\bin\chimney-relay-linux-amd64 .\cmd\chimney-relay
Remove-Item Env:\GOOS -ErrorAction SilentlyContinue
Remove-Item Env:\GOARCH -ErrorAction SilentlyContinue
Remove-Item Env:\CGO_ENABLED -ErrorAction SilentlyContinue
```

### 7.2 创建远端目录

```powershell
ssh -p 15042 root@103.135.147.226 "mkdir -p /opt/chimney-protocol/config /opt/chimney-protocol/logs"
```

### 7.3 上传二进制和配置

```powershell
scp -P 15042 build\bin\chimney-relay-linux-amd64 `
  root@103.135.147.226:/opt/chimney-protocol/chimney-relay

scp -P 15042 config\relay-speedtest.yaml config\intent.yaml config\enforce.yaml `
  root@103.135.147.226:/opt/chimney-protocol/config/

ssh -p 15042 root@103.135.147.226 "chmod +x /opt/chimney-protocol/chimney-relay"
```

### 7.4 写入 systemd service

远端文件：`/etc/systemd/system/chimney-relay.service`

```ini
[Unit]
Description=Chimney Relay Test Service
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=/opt/chimney-protocol
ExecStart=/opt/chimney-protocol/chimney-relay -config /opt/chimney-protocol/config/relay-speedtest.yaml
Restart=on-failure
RestartSec=2s
StandardOutput=append:/opt/chimney-protocol/logs/relay.out.log
StandardError=append:/opt/chimney-protocol/logs/relay.err.log

[Install]
WantedBy=multi-user.target
```

可直接用 PowerShell 写入：

```powershell
$unit = @'
[Unit]
Description=Chimney Relay Test Service
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=/opt/chimney-protocol
ExecStart=/opt/chimney-protocol/chimney-relay -config /opt/chimney-protocol/config/relay-speedtest.yaml
Restart=on-failure
RestartSec=2s
StandardOutput=append:/opt/chimney-protocol/logs/relay.out.log
StandardError=append:/opt/chimney-protocol/logs/relay.err.log

[Install]
WantedBy=multi-user.target
'@

$unit | ssh -p 15042 root@103.135.147.226 "cat > /etc/systemd/system/chimney-relay.service"
```

### 7.5 启动和检查 relay

```powershell
ssh -p 15042 root@103.135.147.226 "systemctl daemon-reload && systemctl enable chimney-relay.service && systemctl restart chimney-relay.service"
ssh -p 15042 root@103.135.147.226 "systemctl status chimney-relay.service --no-pager"
ssh -p 15042 root@103.135.147.226 "ss -ltnp | grep ':8444'"
```

远端健康检查：

```powershell
ssh -p 15042 root@103.135.147.226 "curl -I --connect-timeout 10 https://cloudflare.com"
ssh -p 15042 root@103.135.147.226 "curl -I --connect-timeout 10 http://speedtest.tokyo2.linode.com/100MB-tokyo2.bin"
```

查看日志：

```powershell
ssh -p 15042 root@103.135.147.226 "tail -100 /opt/chimney-protocol/logs/relay.out.log"
ssh -p 15042 root@103.135.147.226 "tail -100 /opt/chimney-protocol/logs/relay.err.log"
ssh -p 15042 root@103.135.147.226 "journalctl -u chimney-relay.service -n 100 --no-pager"
```

## 8. 本地连接远端 relay

### 8.1 前台启动

```powershell
.\build\bin\chimney-client.exe `
  -relay 103.135.147.226:8444 `
  -sni cloudflare.com `
  -dest 127.0.0.1:1 `
  -psk 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef `
  -listen 127.0.0.1:1080 `
  -fingerprint chrome
```

### 8.2 后台启动并写日志

```powershell
New-Item -ItemType Directory -Force build\logs | Out-Null

Start-Process `
  -FilePath .\build\bin\chimney-client.exe `
  -ArgumentList @(
    '-relay','103.135.147.226:8444',
    '-sni','cloudflare.com',
    '-dest','127.0.0.1:1',
    '-psk','0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
    '-listen','127.0.0.1:1080',
    '-fingerprint','chrome'
  ) `
  -RedirectStandardOutput .\build\logs\remote-client.out.log `
  -RedirectStandardError .\build\logs\remote-client.err.log `
  -WindowStyle Hidden
```

查看本地 client：

```powershell
Get-Process chimney-client -ErrorAction SilentlyContinue
netstat -ano | findstr :1080
Get-Content build\logs\remote-client.out.log -Tail 100
Get-Content build\logs\remote-client.err.log -Tail 100
```

停止本地 client：

```powershell
Get-Process chimney-client -ErrorAction SilentlyContinue | Stop-Process -Force
```

### 8.3 基础验证

```powershell
curl.exe -L --socks5-hostname 127.0.0.1:1080 https://www.cloudflare.com/cdn-cgi/trace
```

预期：

- curl 能返回 trace。
- relay 日志 `authenticated_swaps` 增加。
- relay 日志出现 `CONNECT` 目标。

### 8.4 100MB 速度测试

用户当前使用的测速命令：

```powershell
curl.exe -x socks5h://127.0.0.1:1080 -o NUL http://speedtest.tokyo2.linode.com/100MB-tokyo2.bin
```

Linux/macOS 对应：

```bash
curl -x socks5h://127.0.0.1:1080 -o /dev/null http://speedtest.tokyo2.linode.com/100MB-tokyo2.bin
```

测速时同时看 relay 统计：

```powershell
ssh -p 15042 root@103.135.147.226 "tail -f /opt/chimney-protocol/logs/relay.out.log"
```

## 9. CLI 参数完整说明

### 9.1 chimney-client

参数来自 `cmd/chimney-client/main.go`：

| 参数 | 默认值 | 必填 | 说明 |
| --- | --- | --- | --- |
| `-relay` | 空 | 是 | relay 地址，格式 `host:port` |
| `-sni` | 空 | 是 | TLS SNI，必须在 relay 白名单中 |
| `-dest` | 空 | 是 | 历史必填参数；SOCKS5 模式真实目标来自 CONNECT |
| `-psk` | 空 | 否 | hex PSK；为空时由 `-user-id` 派生 |
| `-user-id` | 空 | 否 | 用户标识；为空会使用 `default` |
| `-tag-len` | 16 | 否 | auth tag 长度，必须与 relay 一致 |
| `-listen` | `127.0.0.1:1080` | 否 | 本地 SOCKS5 监听地址 |
| `-fingerprint` | `chrome` | 否 | uTLS 指纹，支持逗号分隔轮换 |
| `-profile` | 空 | 否 | traffic profile JSON，启用 padding stream |
| `-padding-target` | 0 | 否 | 固定 padding 目标大小，0 表示使用 profile 分布 |
| `-dilution` | 空 | 否 | 预录制内容块 JSON，启用 dilution stream |

示例：

```powershell
.\build\bin\chimney-client.exe `
  -relay relay.example.com:8444 `
  -sni cloudflare.com `
  -dest 127.0.0.1:1 `
  -user-id 550e8400-e29b-41d4-a716-446655440000 `
  -listen 127.0.0.1:1080 `
  -fingerprint chrome,firefox,safari
```

### 9.2 chimney-relay

参数来自 `cmd/chimney-relay/main.go`：

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `-config` | `config/relay.yaml` | relay YAML 配置路径 |

示例：

```bash
/opt/chimney-protocol/chimney-relay -config /opt/chimney-protocol/config/relay-speedtest.yaml
```

### 9.3 socks_stress

源码位于 `cmd/socks_stress/main.go`。它用于通过 SOCKS5 做并发下载/上传字节校验。

常用命令：

```powershell
go build -o build\bin\socks_stress.exe .\cmd\socks_stress

.\build\bin\socks_stress.exe `
  -socks 127.0.0.1:1080 `
  -dl 12 `
  -ul 12 `
  -bytes 8388608 `
  -timeout 180s
```

用途：

- 检查多连接并发稳定性。
- 检查 H2 stream multiplexing 是否出现数据错乱。
- 检查 Windows 大流量下是否再次出现 record/H2 frame 边界问题。

## 10. 协议链路和日志判读

### 10.1 成功链路

```text
1. client TCP connect relay
2. client 使用 uTLS 发送 ClientHello，SNI = 白名单站点
3. relay 解析 ClientHello，检查 intent/enforce
4. relay 连接真实 SNI 站点并透明转发 TLS handshake
5. client 和 relay 都观察到 ClientRandom / ServerRandom
6. client 从底层 TCP 切换到 ChimneyRecord
7. client 发送 H2 preface + SETTINGS
8. relay 在 application_data 中扫描并找到可解密 ChimneyRecord
9. client/relay 完成 H2 SETTINGS/ACK
10. client 发送 H2 DATA，payload = key_hint + auth_tag
11. relay 验证 auth tag 成功，关闭真实站点连接
12. relay/client 进入 Chimney tunnel 模式
13. SOCKS5 CONNECT 被映射为 H2 DATA 命令 0x01
14. TCP payload 被映射为 H2 DATA 命令 0x02
15. 关闭被映射为命令 0x03
```

### 10.2 client 成功日志关键词

```text
fingerprint rotation configured
using TLS fingerprint
TLS handshake complete
codec created, sending H2 preface as ChimneyRecord
sent post-swap auth tag
Chimney tunnel established
tunnel established
SOCKS5 proxy listening
SOCKS5 connect
```

### 10.3 relay 成功日志关键词

```text
chimney relay started
found valid ChimneyRecord
post-swap auth verified successfully
swap complete, H2 tunnel established
CONNECT
relay statistics
```

### 10.4 relay 统计字段

`cmd/chimney-relay` 每 30 秒输出一次：

| 字段 | 含义 |
| --- | --- |
| `total_connections` | relay 接收过的连接总数 |
| `active_connections` | 当前活跃连接数 |
| `authenticated_swaps` | auth 成功并 swap 的次数 |
| `auth_failures` | auth 失败次数 |
| `whitelist_rejections` | SNI/CIDR 白名单拒绝次数 |
| `bytes_up` | 上行转发字节 |
| `bytes_down` | 下行转发字节 |

### 10.5 H2 tunnel 命令字

当前实现内部命令字：

| 命令 | 值 | 方向 | 含义 |
| --- | --- | --- | --- |
| CONNECT | `0x01` | client -> relay | payload 是目标 `host:port` |
| DATA | `0x02` | 双向 | payload 是 TCP 数据 |
| CLOSE | `0x03` | 双向 | 关闭 stream |
| UDP | `0x04` | 根包 API | UDP datagram，CLI SOCKS5 当前不支持 UDP ASSOCIATE |

注意：

- CLI client 只实现 SOCKS5 CONNECT。
- 根包 `Dialer.ListenPacket` 支持 `net.PacketConn` 形式的 UDP，但这不是 SOCKS5 UDP。

## 11. 自动重连和连接池

### 11.1 CLI client 自动重连

`cmd/chimney-client` 当前使用 `tunnelManager` 管理单条 tunnel。

行为：

- client 进程启动时建立 tunnel。
- 每次 SOCKS5 CONNECT 前调用 `manager.getTunnel()`。
- 如果旧 tunnel 的 dispatch goroutine 已退出，`isAlive()` 返回 false。
- manager 关闭旧 tunnel 并重新执行完整握手。
- 如果 `openStream` 失败，会强制重建 tunnel 并重试一次。

典型日志：

```text
tunnel is down, reconnecting
Chimney tunnel established
tunnel established
```

限制：

- client 不会在没有请求时主动心跳重连。
- 如果 tunnel 已断但没有新的 SOCKS5 请求，进程会继续活着，下一次请求时才重连。
- 如果 relay 长时间不可达，当前请求会失败；后续请求会继续尝试。

### 11.2 根包 Dialer 自动重连

`chimney.NewDialer` 默认建立 `PoolSize=4` 条 tunnel。

行为：

- `DialContext` 按 round-robin 选择 tunnel。
- 如果选中的 tunnel 已 dead，则 `ensureTunnel` 会尝试替换该 pool slot。
- 并发调用下，同一 slot 的重建由锁保护。
- 如果重建失败，会返回旧 dead tunnel，随后 `DialContext` 返回错误。

适用：

- 嵌入式 Go 集成。
- 高并发连接。
- 需要更好吞吐的场景。

### 11.3 重连验证步骤

1. 本地启动 client，远端启动 relay。
2. curl 验证成功。
3. 远端强制杀 relay：

```powershell
ssh -p 15042 root@103.135.147.226 "systemctl kill -s KILL chimney-relay.service"
```

4. 等 systemd 拉起或手动启动：

```powershell
ssh -p 15042 root@103.135.147.226 "systemctl start chimney-relay.service"
```

5. 本地不重启 client，再请求：

```powershell
curl.exe -L --socks5-hostname 127.0.0.1:1080 https://www.cloudflare.com/cdn-cgi/trace
```

6. 检查 client 日志：

```powershell
Get-Content build\logs\remote-client.out.log -Tail 100
```

预期看到 `tunnel is down, reconnecting` 和新的 `Chimney tunnel established`。

## 12. 测试和验收

### 12.1 基础测试

```powershell
go test ./...
```

### 12.2 vet

```powershell
go vet ./...
```

### 12.3 race 测试

Linux 或已安装 cgo 工具链的环境：

```bash
go test -race ./...
```

Windows 未安装 gcc/cgo 时不要把 `-race` 失败当成业务失败。

### 12.4 stress 测试

```powershell
go test -tags stress -run TestLocalMixedTrafficStress -count=1 -timeout 3m -v
```

### 12.5 真实二进制链路验收

本地 relay：

```powershell
.\build\bin\chimney-relay.exe -config .\config\relay-speedtest.yaml
```

本地 client：

```powershell
.\build\bin\chimney-client.exe `
  -relay 127.0.0.1:8444 `
  -sni cloudflare.com `
  -dest 127.0.0.1:1 `
  -psk 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef `
  -listen 127.0.0.1:1080 `
  -fingerprint chrome
```

SOCKS 压测：

```powershell
.\build\bin\socks_stress.exe -socks 127.0.0.1:1080 -dl 12 -ul 12 -bytes 8388608 -timeout 180s
```

远端公网验收：

```powershell
curl.exe -L --socks5-hostname 127.0.0.1:1080 https://www.cloudflare.com/cdn-cgi/trace
curl.exe -x socks5h://127.0.0.1:1080 -o NUL http://speedtest.tokyo2.linode.com/100MB-tokyo2.bin
```

### 12.6 验收标准

最低标准：

- `go test ./...` 通过。
- relay 能启动并监听目标端口。
- client 能建立 tunnel。
- curl 能通过 SOCKS5 访问 HTTPS 和 HTTP 目标。
- relay 日志出现 `authenticated_swaps` 增加。
- kill/restart relay 后，本地 client 不重启也能在下一次请求时自动重连。

更高标准：

- `go vet ./...` 通过。
- `socks_stress` 多线程压测无数据错误。
- 100MB 下载测试能完整结束。
- relay 日志无持续增长的 auth failure、bad record MAC 或 backend connect failed。

## 13. 常见故障排查

### 13.1 client 进程还活着，但隧道已关闭

现象：

```text
curl: cannot complete SOCKS5 connection
```

原因：

- client 是 SOCKS5 监听进程，进程活着不等于 tunnel 活着。
- tunnel 死亡后，当前实现会在下一次 SOCKS5 CONNECT 时懒重连。

排查：

```powershell
Get-Process chimney-client -ErrorAction SilentlyContinue
Get-Content build\logs\remote-client.out.log -Tail 100
```

预期：

```text
tunnel is down, reconnecting
```

如果没有出现，检查是否运行的是旧二进制。

### 13.2 SOCKS5 连接失败

检查本地监听：

```powershell
netstat -ano | findstr :1080
```

检查 curl 写法：

```powershell
curl.exe -x socks5h://127.0.0.1:1080 -I https://www.cloudflare.com/
```

检查 client 日志：

```powershell
Get-Content build\logs\remote-client.out.log -Tail 100
Get-Content build\logs\remote-client.err.log -Tail 100
```

常见原因：

- client 没启动。
- 端口 1080 被旧进程占用。
- relay 不可达。
- tunnel auth 失败。
- 后端目标不可达。

### 13.3 relay 没有 `swap complete`

检查点：

- `-sni` 是否在 `config/intent.yaml`。
- `config/enforce.yaml` 是否允许该 SNI 解析出的 IP。
- relay 是否能访问 `cloudflare.com:443`。
- client/relay PSK 是否一致。
- `tag_len` 是否一致。
- client 是否使用正确 fingerprint。

命令：

```powershell
ssh -p 15042 root@103.135.147.226 "tail -200 /opt/chimney-protocol/logs/relay.out.log"
ssh -p 15042 root@103.135.147.226 "curl -I --connect-timeout 10 https://cloudflare.com"
```

### 13.4 `CONNECT timeout`

含义：

- client 已发送 H2 CONNECT 命令。
- 10 秒内没有收到 relay 的 CONNECT_OK。

检查：

```powershell
ssh -p 15042 root@103.135.147.226 "tail -200 /opt/chimney-protocol/logs/relay.out.log"
ssh -p 15042 root@103.135.147.226 "curl -I --connect-timeout 10 http://speedtest.tokyo2.linode.com/100MB-tokyo2.bin"
```

可能原因：

- 目标 host:port 从 relay 侧不可达。
- relay 连接目标超时。
- pending stream 或 buffer 压力过高。
- tunnel 已半关闭，client 需要重建。

### 13.5 `bad record MAC`

含义：

- ChimneyRecord AEAD 解密失败。

可能原因：

- PSK 不一致。
- client/relay 观察到的 random 不一致。
- directional key 或 nonce 派生方向错。
- record sequence 不同步。
- H2 DATA frame 分片导致命令字边界处理错误。
- 传输层写入损坏。

相关文档：

```text
docs/windows-tcp-corruption.md
```

当前重要实现点：

- TCP tunnel 数据按 `16KiB - 1` 分片。
- 每个 H2 DATA payload 都保留 1 字节命令字。
- 这避免 H2 自动分片后后续裸 payload 被误判为命令。

### 13.6 systemd restart 卡在 deactivating

现象：

```bash
systemctl restart chimney-relay.service
```

长时间卡住。

临时开发处理：

```powershell
ssh -p 15042 root@103.135.147.226 "systemctl kill -s KILL chimney-relay.service && systemctl start chimney-relay.service"
```

后续工程改进：

- 梳理 relay `Stop()` 的 active connection drain 行为。
- 增加 shutdown timeout。
- 在 systemd unit 中配置合理的 `TimeoutStopSec`。

### 13.7 速度偏慢

先区分瓶颈：

```powershell
# 不走 Chimney，直接本机访问目标
curl.exe -o NUL http://speedtest.tokyo2.linode.com/100MB-tokyo2.bin

# 在远端服务器直接访问目标
ssh -p 15042 root@103.135.147.226 "curl -o /dev/null http://speedtest.tokyo2.linode.com/100MB-tokyo2.bin"

# 走 Chimney
curl.exe -x socks5h://127.0.0.1:1080 -o NUL http://speedtest.tokyo2.linode.com/100MB-tokyo2.bin
```

可能原因：

- 远端服务器到 Tokyo Linode 慢。
- 本地到 relay 慢。
- 单 tunnel/SOCKS CLI 只有一条 H2 tunnel，吞吐不如根包 pool。
- Windows 本地 TCP buffer、杀毒软件或代理栈影响。
- relay 端 CPU 或系统 buffer 限制。

调优方向：

- 用根包 `Dialer` 的 `PoolSize` 做高并发场景。
- 降低 debug 日志量，避免测速时 stdout 过多。
- 检查 relay CPU、带宽、丢包。
- 对比 `socks_stress` 和单 curl 结果，区分并发吞吐与单连接吞吐。

## 14. Admin API

如果 relay 配置了：

```yaml
metrics_addr: "127.0.0.1:8080"
metrics_token: "change-this-token"
```

会启动 HTTP admin API。

Admin 鉴权规则：

- `/health` 不需要 token。
- `/admin/*` 如果配置了 `metrics_token`，请求必须带 `Authorization: Bearer <token>` 或 `X-Admin-Token: <token>`。
- 如果 `metrics_token` 为空，`/admin/*` 只接受 loopback client。生产环境仍建议显式配置 token，并把 `metrics_addr` 绑定到 `127.0.0.1` 或放在带鉴权的内网入口后。

健康检查：

```bash
curl http://127.0.0.1:8080/health
```

统计：

```bash
curl http://127.0.0.1:8080/admin/stats
```

用户列表：

```bash
curl http://127.0.0.1:8080/admin/users
```

添加用户：

```bash
curl -X POST http://127.0.0.1:8080/admin/users \
  -H 'Content-Type: application/json' \
  -d '{"user_id":"550e8400-e29b-41d4-a716-446655440000"}'
```

删除用户：

```bash
curl -X DELETE http://127.0.0.1:8080/admin/users \
  -H 'Content-Type: application/json' \
  -d '{"user_id":"550e8400-e29b-41d4-a716-446655440000"}'
```

注意：

- Admin API 支持 token 鉴权；没有 token 时只允许 loopback client。生产环境不要直接裸露公网。
- `/admin/refresh-cidrs` 当前返回成功 JSON，但实际 refresh 逻辑仍需完善。
- `metrics_addr` 名称容易误解；当前返回 JSON，不是 Prometheus exposition format。

## 15. Go 库集成指南

根包导出 `chimney.Dialer`。

最小 TCP 示例：

```go
package main

import (
	"context"
	"crypto/tls"
	"io"
	"log"
	"net/http"
	"time"

	chimney "github.com/shuffleman/chimney-protocol"
)

func main() {
	d, err := chimney.NewDialer(chimney.Config{
		RelayAddr:        "103.135.147.226:8444",
		SNI:              "cloudflare.com",
		PSK:              "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		Fingerprint:      "chrome",
		ConnectTimeout:   10 * time.Second,
		HandshakeTimeout: 10 * time.Second,
		PoolSize:         4,
	})
	if err != nil {
		log.Fatal(err)
	}
	defer d.Close()

	tr := &http.Transport{
		DialContext: d.DialContext,
		TLSClientConfig: &tls.Config{
			ServerName: "www.cloudflare.com",
		},
	}

	client := &http.Client{Transport: tr}
	resp, err := client.Get("https://www.cloudflare.com/cdn-cgi/trace")
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
	io.Copy(log.Writer(), resp.Body)

	_ = context.Background()
}
```

`Config` 重点字段：

| 字段 | 说明 |
| --- | --- |
| `RelayAddr` | relay 地址，必填 |
| `SNI` | 借道站点，必填 |
| `PSK` | hex PSK；为空时可由 `UserID` 派生 |
| `UserID` | 多用户模式标识 |
| `TagLen` | 默认 16 |
| `Fingerprint` | 默认 `chrome` |
| `ProfilePath` | profile JSON |
| `PaddingTarget` | padding 目标大小 |
| `DilutionPath` | dilution JSON |
| `ConnectTimeout` | TCP 连接超时 |
| `HandshakeTimeout` | TLS/H2 握手超时 |
| `PoolSize` | tunnel 池大小，默认 4 |
| `TCPBufferSize` | 每条 TCP tunnel buffer，默认 256 KiB |

UDP：

```go
pc, err := d.ListenPacket(context.Background())
```

注意：

- `ListenPacket` 是根包 API，CLI SOCKS5 尚未实现 UDP ASSOCIATE。
- `DialContext` 的 `network` 当前基本按 TCP 使用，目标必须是 `host:port`。
- `Dialer.Close()` 会关闭 pool 中所有 tunnel。

## 16. 日志与文件位置

本地建议：

```text
build/logs/remote-client.out.log
build/logs/remote-client.err.log
```

远端建议：

```text
/opt/chimney-protocol/chimney-relay
/opt/chimney-protocol/config/relay-speedtest.yaml
/opt/chimney-protocol/config/intent.yaml
/opt/chimney-protocol/config/enforce.yaml
/opt/chimney-protocol/logs/relay.out.log
/opt/chimney-protocol/logs/relay.err.log
/etc/systemd/system/chimney-relay.service
```

常用查看：

```powershell
Get-Content build\logs\remote-client.out.log -Tail 100
ssh -p 15042 root@103.135.147.226 "tail -100 /opt/chimney-protocol/logs/relay.out.log"
ssh -p 15042 root@103.135.147.226 "journalctl -u chimney-relay.service -n 100 --no-pager"
```

## 17. 发布流程

发布前检查：

```powershell
go test ./...
go vet ./...
git status --short
```

确认不混入无关改动：

```powershell
git diff -- docs/developer-deployment-manual.md
git diff -- .spec-workflow/templates
```

常规提交：

```powershell
git add docs/developer-deployment-manual.md
git commit -m "docs: expand developer deployment manual"
git push origin master
```

发布 tag：

```powershell
git tag -a vX.Y.Z -m "vX.Y.Z"
git push origin vX.Y.Z
```

注意：

- 发布 tag 前确认 HEAD 是你要发布的提交。
- 如果工作区有 `.spec-workflow/templates/*` 之类无关修改，不要混入文档或功能提交。
- 若要发布二进制，先在干净环境构建，避免 GOOS/GOARCH 残留。

## 18. 当前实现边界

接手开发时尤其注意这些边界：

- CLI client 不读取 YAML config。
- CLI client 只提供 SOCKS5 CONNECT，不支持 SOCKS5 UDP ASSOCIATE。
- 根包支持 UDP `ListenPacket`，但这不是 CLI SOCKS UDP。
- CLI client 是单 tunnel；根包 Dialer 才有 `PoolSize` tunnel pool。
- `profile_dir` 字段存在，但 relay 端按站点 profile 加载仍不完整。
- dilution 当前由 client/root package 发送预录制内容块，relay 识别 reserved stream 后丢弃。
- Admin API 支持 token 鉴权；未配置 token 时只允许 loopback client。
- `/admin/refresh-cidrs` 当前仍偏占位。
- Makefile `run-client` 与当前 CLI 不匹配。
- README 中部分协议描述偏设计视角，真实实现以代码为准。
- `Chimney-完整设计与实现规格.md` 是设计规格，不保证每段都与当前实现同步。

## 19. 后续开发建议

优先级从高到低：

1. 给 `cmd/chimney-client` 增加 `-config`，复用 `internal/config.ClientConfig`。
2. 更新 Makefile `run-client`，避免继续使用不存在的 `-config` 参数。
3. 让 CLI client 可选复用根包 `Dialer`，减少两套 tunnel 管理逻辑。
4. 给 CLI client 增加主动健康检查或 idle keepalive，让断线不必等下一次请求才发现。
5. 增加自动化集成测试：启动真实 relay/client，kill relay，确认 client 自动重连。
6. 完善 relay graceful shutdown，避免 systemd restart 长时间 deactivating。
7. 给 admin API 增加更完整的权限模型、审计日志和限流。
8. 实现真实 CIDR refresh，并让 `/admin/refresh-cidrs` 调用实际逻辑。
9. 明确 profile 加载策略，让 `intent.yaml` 的 SETTINGS/profile 与 H2 engine 配置闭环。
10. 如需代理 UDP，给 CLI SOCKS5 实现 UDP ASSOCIATE 并映射到根包 UDP stream。

## 20. 新开发者接手检查清单

第一次接手建议按顺序执行：

```powershell
git status --short
go version
go mod download
go test ./...
go build -o build\bin\chimney-relay.exe .\cmd\chimney-relay
go build -o build\bin\chimney-client.exe .\cmd\chimney-client
```

本地链路：

```powershell
.\build\bin\chimney-relay.exe -config .\config\relay-speedtest.yaml
.\build\bin\chimney-client.exe -relay 127.0.0.1:8444 -sni cloudflare.com -dest 127.0.0.1:1 -psk 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef -listen 127.0.0.1:1080 -fingerprint chrome
curl.exe -L --socks5-hostname 127.0.0.1:1080 https://www.cloudflare.com/cdn-cgi/trace
```

远端链路：

```powershell
ssh -p 15042 root@103.135.147.226 "systemctl status chimney-relay.service --no-pager"
.\build\bin\chimney-client.exe -relay 103.135.147.226:8444 -sni cloudflare.com -dest 127.0.0.1:1 -psk 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef -listen 127.0.0.1:1080 -fingerprint chrome
curl.exe -x socks5h://127.0.0.1:1080 -o NUL http://speedtest.tokyo2.linode.com/100MB-tokyo2.bin
```

读代码顺序：

```text
cmd/chimney-client/main.go
cmd/chimney-relay/main.go
internal/relay/relay.go
chimney.go
internal/h2engine/h2engine.go
internal/record/record.go
internal/auth/auth.go
internal/keyderiv/keyderiv.go
internal/whitelist/whitelist.go
```

完成以上步骤后，再看 `README.md` 和 `Chimney-完整设计与实现规格.md`。遇到文档和代码不一致，以代码为准，并同步更新本文档。
