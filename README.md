# Chimney — 行为不可区分的会话寄生传输协议

> Behaviorally Indistinguishable Session-Parasitic Transport

[![Go Version](https://img.shields.io/badge/Go-1.23+-00ADD8?style=flat&logo=go)](https://go.dev/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Version](https://img.shields.io/badge/version-v0.0.1-blue)](https://github.com/shuffleman/chimney-protocol/releases/tag/v0.0.1)

Chimney 协议的 Go 实现 — 一种隐蔽传输系统，使得隐蔽通信在行为上与指向真实网站的正常 HTTPS 流量不可区分。

A Go implementation of the Chimney protocol — a covert transport system that makes hidden communication behaviorally indistinguishable from normal HTTPS traffic to real websites.

---

## 概述 / Overview

Chimney 是一种专为抵抗高级流量分析系统检测而设计的传输协议。与试图"看起来像"HTTPS 的传统代理协议不同，Chimney **寄生**于真实 HTTPS 会话 — 借用合法网站的实际 TLS 握手，并维持与真实浏览器行为匹配的记录级流量特征。

Chimney is a transport protocol designed to resist detection by advanced traffic analysis systems. Unlike traditional proxy protocols that attempt to "look like" HTTPS, Chimney **parasitizes** real HTTPS sessions — borrowing actual TLS handshakes from legitimate websites and maintaining record-level traffic characteristics that match real browser behavior.

### 核心特性 / Key Features

- **真实 TLS 握手借用 / Real TLS Handshake Borrowing**：使用与真实网站的真正 TLS 握手 — 中继透明转发握手，客户端使用 uTLS 模拟真实浏览器指纹。
  Uses genuine TLS handshakes with real websites — the relay forwards the handshake transparently, and the client uses uTLS to mimic real browser fingerprints.

- **零可区分失败路径 (P1) / Zero-Distinguishable Failure Path**：失败的认证与正常浏览器连接不可区分 — 流量被简单地转发到真实网站。
  Failed authentication is indistinguishable from a normal browser connection — traffic is simply forwarded to the real website.

- **真实 SETTINGS 的 H2 帧封装 / H2 Framing with Real SETTINGS**：内部使用 HTTP/2 帧封装，SETTINGS 值来自真实白名单站点捕获的数据，而非库默认值。
  Internally uses HTTP/2 framing with SETTINGS values captured from the real whitelisted site, not library defaults.

- **TLS-in-TLS 指纹消除 / TLS-in-TLS Fingerprint Elimination**：在初始握手窗口（约 10 条记录）中塑造流量，消除嵌套 TLS 握手的大小序列签名。
  Shapes traffic in the initial handshake window (~10 records) to eliminate the size-sequence signature of nested TLS handshakes.

- **流量 Profile 节奏控制 / Traffic Profile Pacing**：根据从 pcap 捕获校准的真实网站流量 profile，塑造记录大小、突发模式和时序。
  Shapes record sizes, burst patterns, and timing to match real website traffic profiles calibrated from pcap captures.

- **双层白名单 / Two-Layer Whitelist**：意图层（站点名称）+ 执行层（云端 CIDR 块），确保中继仅连接到同一云区域内的目的地。
  Intent layer (site names) + enforce layer (cloud CIDR blocks) ensures the relay only connects to destinations within the same cloud region.

---

## 架构 / Architecture

```
Client         Relay               Real Site (whitelist_i)
  |              |                        |
  |--- TLS ---->|                        |
  |  Handshake   |---- TCP Forward ----->|
  |  (SNI=site_i)|  (transparent relay)   |-- Real Cert --+
  |              |                        |               |
  |<-------------|<-----------------------|<--------------+
  |              |  (ServerHello w/ ServerRandom observed)
  |              |                        |
  |-- AppData -->|                        |
  |  (auth_tag   |  Extract tag, verify   |
  |   + H2 open) |                        |
  |              |  Tag matches?          |
  |              |  YES: CUT real site,   |
  |              |       take over with   |
  |              |       K_sess           |
  |              |  NO:  forward to       |
  |              |       real site        |
  |              |       (zero distinction)|
  |              |                        |
  |<== H2 Tunnel=| (Chimney mode)         |
  |  (DATA frames |                        |
  |   + pacing)  |                        |
```

---

## 项目结构 / Project Structure

```
chimney/
├── cmd/
│   ├── chimney-relay/          # 中继服务器 / Relay server binary
│   └── chimney-client/         # 客户端 (SOCKS5 代理) / Client binary
├── internal/
│   ├── auth/                   # 认证标签生成/验证 / Auth tag
│   ├── config/                 # 配置加载 / Configuration loading
│   ├── dilution/               # Dilution 流真实内容块 / Content blocks
│   ├── h2engine/               # HTTP/2 帧引擎 / H2 framing engine
│   ├── keyderiv/               # HKDF 密钥派生 / Key derivation
│   ├── pcap/                   # PCAP 解析器 / PCAP parser
│   ├── profile/                # 流量 Profile 与节奏控制 / Pacing
│   ├── record/                 # ChimneyRecord 编解码 (AEAD) / Codec
│   ├── relay/                  # 核心中继逻辑 / Core relay logic
│   └── whitelist/              # 双层白名单 / Two-layer whitelist
├── config/
│   ├── intent.yaml             # 意图白名单 (站点名称) / Intent
│   └── enforce.yaml            # 执行层 CIDR 白名单 / Enforce
├── go.mod
├── Makefile
└── README.md
```

---

## 快速开始 / Quick Start

### 前置条件 / Prerequisites

- Go 1.23 或更高版本 / Go 1.23 or later
- Linux/Unix 环境 (构建用) / Linux/Unix environment

### 构建 / Building

```bash
# 克隆仓库 / Clone
git clone https://github.com/shuffleman/chimney-protocol.git
cd chimney

# 下载依赖 / Download dependencies
go mod download

# 构建全部 / Build both binaries
make build

# 或单独构建 / Or build individually
make build-relay
make build-client
```

### 生成 PSK / Generate a PSK

```bash
make genkey
# 输出: 64 字符十六进制字符串 (256 bits)
# Output: 64-character hex string (256 bits)
```

### 运行中继 / Running the Relay

1. 配置 `config/intent.yaml` 填入白名单站点 / Configure with your whitelisted sites
2. 配置 `config/enforce.yaml` 填入云区域 CIDR / Configure with your cloud region CIDRs
3. 运行中继 / Run:

```bash
./build/bin/chimney-relay -config config/relay.yaml
```

`config/relay.yaml` 示例 / Example:

```yaml
listen_addr: ":443"
psk: "your-64-char-hex-psk-here"
tag_len: 16
intent_file: "config/intent.yaml"
enforce_file: "config/enforce.yaml"
cloud_region: "us-east-1"
handshake_timeout: 10s
auth_read_timeout: 5s
log_level: "info"
```

### 运行客户端 / Running the Client

```bash
./build/bin/chimney-client \
  -relay relay.example.com:443 \
  -sni real-site.com \
  -dest final-destination.com:443 \
  -psk your-64-char-hex-psk-here \
  -fingerprint chrome,firefox,safari \
  -profile profiles/example.com.profile.json \
  -dilution blocks/example.com.blocks.json
```

客户端将在 `127.0.0.1:1080` 启动 SOCKS5 代理。将应用程序配置为使用此代理。

The client starts a SOCKS5 proxy on `127.0.0.1:1080`. Configure your applications to use this proxy.

**`-fingerprint`**：逗号分隔的 TLS 指纹列表，用于轮换。每个新连接使用序列中的下一个指纹。可用指纹：`chrome`、`firefox`、`safari`、`ios`、`edge`、`android`、`360`、`qq`、`randomized`、`golang`。可追加版本号（如 `chrome-120`、`firefox-105`）。

Comma-separated TLS fingerprints for rotation. Each new connection uses the next fingerprint in sequence. Available: `chrome`, `firefox`, `safari`, `ios`, `edge`, `android`, `360`, `qq`, `randomized`, `golang`. Append version for specific browser versions (e.g. `chrome-120`).

**`-profile`**：加载流量 profile JSON（由校准工具生成），启用 padding 流。记录被填充虚拟 H2 DATA 帧以匹配站点的记录大小分布。使用 `-padding-target` 覆盖固定大小。

Loads a traffic profile JSON (generated by the calibration tool), enabling the padding stream. Records are padded with dummy H2 DATA frames to match the site's record size distribution. Use `-padding-target` to override.

**`-dilution`**：加载预录制内容块（从真实站点捕获的 base64 编码 HTTP 响应片段），启用 dilution 流。Dilution 帧携带语义上有意义的内容而非随机字节，使流量能够抵抗基于熵的 DPI 分析。

Loads pre-recorded content blocks (base64-encoded HTTP response fragments captured from the real site), enabling the dilution stream. Dilution frames carry semantically meaningful content instead of random bytes, resisting entropy-based DPI.

---

## 配置 / Configuration

### 意图白名单 / Intent Whitelist (`config/intent.yaml`)

意图层列出允许的 SNI 值。每个条目应包含从真实站点捕获的 HTTP/2 SETTINGS：

The intent layer lists allowed SNI values. Each entry should have captured HTTP/2 SETTINGS from the real site:

```yaml
version: 1
entries:
  example.com:
    sni: example.com
    description: "Example CDN site"
    settings_snapshot:
      HEADER_TABLE_SIZE: 4096
      ENABLE_PUSH: 0
      MAX_CONCURRENT_STREAMS: 100
      INITIAL_WINDOW_SIZE: 65535
      MAX_FRAME_SIZE: 16384
      MAX_HEADER_LIST_SIZE: 16384
```

### 执行层白名单 / Enforce Whitelist (`config/enforce.yaml`)

执行层定义允许的目标 IP CIDR。这是安全关键层：

The enforce layer defines allowed destination IP CIDRs. This is the security-critical layer:

```yaml
version: 1
entries:
  - cidr: "52.0.0.0/11"
    provider: "aws"
    region: "us-east-1"
```

自动刷新 AWS CIDR / Refresh CIDRs from AWS:

```bash
curl -X POST http://relay:8080/admin/refresh-cidrs
```

### 站点校准 / Site Calibration

将站点添加到白名单之前，必须先捕获其真实流量 profile：

Before adding a site to the whitelist, you must capture its real traffic profile:

```bash
# 1. 使用真实浏览器捕获 HTTPS 流量 / Capture HTTPS traffic
tcpdump -i eth0 -w site_capture.pcap 'host example.com and port 443'

# 2. 使用校准工具提取 SETTINGS 和 profile / Extract SETTINGS and profile
go run ./cmd/calibrate -pcap site_capture.pcap -site example.com

# 3. 将生成的 profile 添加到 config/intent.yaml
```

---

## 安全原则 / Security Principles

Chimney 协议围绕四个安全原则设计：

The Chimney protocol is designed around four security principles:

1. **P1 — 无可区分失败路径 / No Distinguishable Failure Path**：
   认证失败流量被转发到真实站点。无错误码、无提前断开、无时序差异。
   Failed auth is forwarded to the real site. No error codes, no early disconnect, no timing differences.

2. **P2 — 无语义不连续性 / No Semantic Discontinuity**：
   Swap 之后，记录大小和时序与真实浏览器访问白名单站点产生的流量一致。
   After the swap, record sizes and timing match what a real browser visiting the whitelisted site would produce.

3. **P3 — 无可观察协议转换 / No Observable Protocol Transition**：
   从真实 TLS 到 Chimney 模式的转换不可见 — 仅记录大小/时序可观察，而这些与站点 profile 匹配。
   The transition from real TLS to Chimney mode is invisible — only record sizes/timing are observable, and those match the site profile.

4. **P4 — 所有未认证流量保持合法 / All Unauthenticated Traffic Stays Legitimate**：
   任何无有效认证标签的流量被转发到真实站点并获得真实站点的真实响应。
   Any traffic without a valid auth tag is forwarded to the real site and receives the real site's genuine response.

---

## 实现状态 / Implementation Status

| 组件 / Component | 状态 / Status |
|-----------|--------|
| Record 编解码 (AEAD) / Record codec | ✅ 完成 / Complete |
| 密钥派生 (HKDF) / Key derivation | ✅ 完成 / Complete |
| H2 帧引擎 / H2 framing engine | ✅ 完成 / Complete |
| 认证标签 (HMAC) / Auth tag | ✅ 完成 / Complete |
| TCP 中继 + 握手转发 / TCP relay + handshake | ✅ 完成 / Complete |
| Swap 机制 / Swap mechanism | ✅ 完成 / Complete |
| 白名单 (意图 + 执行) / Whitelist | ✅ 完成 / Complete |
| 流量 Profile + 节奏控制 / Pacing | ✅ 完成 / Complete |
| 中继服务器 / Relay server | ✅ 完成 / Complete |
| 客户端 (SOCKS5) / Client | ✅ 完成 / Complete |
| 站点校准工具 / Calibration tool | ✅ 完成 / Complete |
| uTLS 指纹轮换 / Fingerprint rotation | ✅ 完成 / Complete |
| Padding 流 / Padding stream | ✅ 完成 / Complete |
| Real content dilution | ✅ 完成 / Complete |

---

## 协议规范 / Protocol Specification

本实现遵循 Chimney 协议规范 (v0.1)。关键密码学操作：

This implementation follows the Chimney protocol specification (v0.1). Key cryptographic operations:

```
K_auth = HKDF(PSK, label="chimney-auth", info=ServerRandom)
tag    = HMAC(K_auth, ServerRandom || recordBytes)[:TAG_LEN]

K_sess = HKDF(PSK, label="chimney-sess", info=ServerRandom || ClientRandom)
```

认证标签嵌入 TLS 握手后的第一个 application_data 记录中。中继在不解密 TLS 记录的情况下验证标签 — 它在握手转发期间观察 ServerRandom，并从共享 PSK 派生 K_auth。

The auth tag is embedded in the first application_data record after the TLS handshake. The relay verifies the tag without decrypting the TLS record — it observes ServerRandom during handshake forwarding and derives K_auth from the shared PSK.

---

## 测试 / Testing

```bash
# 运行全部测试 / Run all tests
make test

# 运行覆盖率测试 / Run with coverage
make test-coverage

# 运行基准测试 / Run benchmarks
make bench

# 运行 CI 流水线 (fmt, vet, test, build)
make ci
```

---

## 安全注意事项 / Security Considerations

**这是一个研究性实现。** 生产部署前 / **This is a research implementation.** Before production deployment:

1. 在校准工具中实现 TLS 解密（keylog 支持）以获取精确的 SETTINGS /
   Implement TLS decryption in calibration tool (keylog support)

2. 将 Pacer 与隧道数据流集成以实现自动节奏控制 /
   Integrate Pacer with tunnel data flow for automatic pacing

3. 审查并加固 H2 引擎以覆盖所有边界情况 /
   Review and harden the H2 engine for all edge cases

4. 对完整系统进行正式安全分析 /
   Conduct formal security analysis of the complete system

---

## 许可证 / License

MIT License — 详见 / see [LICENSE](LICENSE) 文件。

---

## 致谢 / Acknowledgments

本实现基于 Chimney 协议规范，建立在 ShadowTLS v3 和 REALITY 的基础上。核心创新是 swap 后的流量塑造，维持了与真实 HTTPS 会话的行为不可区分性。

This implementation is based on the Chimney protocol specification, building upon the foundations of ShadowTLS v3 and REALITY. The key innovation is post-swap traffic shaping that maintains behavioral indistinguishability from real HTTPS sessions.
