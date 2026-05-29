# Chimney — 行为不可区分的会话寄生传输协议

> Behaviorally Indistinguishable Session-Parasitic Transport

[![Go Version](https://img.shields.io/badge/Go-1.23+-00ADD8?style=flat&logo=go)](https://go.dev/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Version](https://img.shields.io/badge/version-v0.1.0-blue)](https://github.com/shuffleman/chimney-protocol/releases)

Chimney 协议的 Go 实现 — 一种隐蔽传输系统，使得隐蔽通信在行为上与指向真实网站的正常 HTTPS 流量不可区分。

A Go implementation of the Chimney protocol — a covert transport system that makes hidden communication behaviorally indistinguishable from normal HTTPS traffic to real websites.

---

## 目录 / Table of Contents

- [概述 / Overview](#概述--overview)
- [架构 / Architecture](#架构--architecture)
- [快速开始 / Quick Start](#快速开始--quick-start)
- [配置 / Configuration](#配置--configuration)
- [多用户认证 (UUID) / Multi-User Auth](#多用户认证-uuid--multi-user-auth)
- [库集成 (sing-box / Xray-core) / Library Integration](#库集成-sing-box--xray-core--library-integration)
- [安全原则 / Security Principles](#安全原则--security-principles)
- [协议规范 / Protocol Specification](#协议规范--protocol-specification)
- [项目结构 / Project Structure](#项目结构--project-structure)
- [测试 / Testing](#测试--testing)
- [安全注意事项 / Security Considerations](#安全注意事项--security-considerations)

---

## 概述 / Overview

Chimney 是一种专为抵抗高级流量分析系统检测而设计的传输协议。与试图"看起来像"HTTPS 的传统代理协议不同，Chimney **寄生**于真实 HTTPS 会话 — 借用合法网站的实际 TLS 握手，并维持与真实浏览器行为匹配的记录级流量特征。

Chimney is a transport protocol designed to resist detection by advanced traffic analysis systems. Unlike traditional proxy protocols that attempt to "look like" HTTPS, Chimney **parasitizes** real HTTPS sessions — borrowing actual TLS handshakes from legitimate websites and maintaining record-level traffic characteristics that match real browser behavior.

### 核心特性 / Key Features

- **真实 TLS 握手借用 / Real TLS Handshake Borrowing**：使用与真实网站的真正 TLS 握手 — 中继透明转发握手，客户端使用 uTLS 模拟真实浏览器指纹。

- **零可区分失败路径 (P1) / Zero-Distinguishable Failure Path**：失败的认证与正常浏览器连接不可区分 — 流量被简单地转发到真实网站。

- **真实 SETTINGS 的 H2 帧封装 / H2 Framing with Real SETTINGS**：内部使用 HTTP/2 帧封装，SETTINGS 值来自真实白名单站点捕获的数据，而非库默认值。

- **TLS-in-TLS 指纹消除 / TLS-in-TLS Fingerprint Elimination**：在初始握手窗口中塑造流量，消除嵌套 TLS 握手的大小序列签名。

- **流量 Profile 节奏控制 / Traffic Profile Pacing**：根据从 pcap 捕获校准的真实网站流量 profile，塑造记录大小、突发模式和时序。

- **双层白名单 / Two-Layer Whitelist**：意图层（站点名称）+ 执行层（云端 CIDR 块），确保中继仅连接到同一云区域内的目的地。

- **多用户 UUID 认证 / Multi-User UUID Auth**：每个用户一个 UUID — PSK 自动派生，无需管理独立密钥。Relay 通过 4 字节 key hint 在 O(1) 时间内查找用户。

- **可导出 Dialer API / Exportable Dialer API**：`chimney.Dialer` + `chimney.DialContext()` 返回标准 `net.Conn`，可直接集成到 sing-box、Xray-core 等代理框架。

---

## 架构 / Architecture

```
Client                Relay                    Real Site (whitelist_i)
  |                     |                             |
  |--- TLS ClientHello ->|                            |
  |   (SNI=site_i,       |--- TCP Forward ---------->|
  |    uTLS fingerprint) |   (transparent relay)       |-- Real TLS -----+
  |                      |                             |   Handshake     |
  |<--------------------|<----------------------------|<----------------+
  |   ServerHello        |  (observe ServerRandom)     |
  |   (ServerRandom      |                             |
  |    observed by       |                             |
  |    relay)            |                             |
  |                      |                             |
  |--- AppData (0x17) ->|                             |
  |   [key_hint(4)]      |  Extract hint, lookup user  |
  |   [auth tag(N)]      |  Verify HMAC tag            |
  |   [H2 preface]       |                             |
  |                      |  Tag valid?                 |
  |                      |  YES: CUT real site,        |
  |                      |       take over with        |
  |                      |       K_sess                 |
  |                      |  NO:  forward to real site  |
  |                      |       (zero distinction)     |
  |                      |                             |
  |<==== H2 Tunnel =====>| (Chimney mode)              |
  |  DATA frames with    |                             |
  |  padding + dilution  |                             |
  |  + pacing            |                             |
```

### 协议流程 / Protocol Flow

1. Client 发起到 Relay 的 TCP 连接，使用 uTLS 模拟浏览器 TLS 指纹
2. Relay 提取 ClientHello 中的 SNI，检查白名单
3. Relay 将 TLS 握手**透明转发**到真实站点（不解密）
4. Relay 在转发过程中**观察** ServerHello 中的 ServerRandom（TLS 1.3 明文）
5. TLS 握手完成后，Client 发送第一个 Application Data 记录，内含 `[key_hint(4)][auth_tag(N)]`
6. Relay 提取 key_hint，O(1) 查找用户 → 派生 K_auth → 验证 HMAC 标签
7. **调包 (Swap)**：认证成功 → Relay 切断真实站点连接，切换到 Chimney H2 隧道
8. 认证失败 → Relay 继续透明转发到真实站点（零可区分性）

---

## 快速开始 / Quick Start

### 前置条件 / Prerequisites

- Go 1.23 或更高版本 / Go 1.23 or later
- Linux/Unix 环境 / Linux/Unix environment

### 构建 / Building

```bash
git clone https://github.com/shuffleman/chimney-protocol.git
cd chimney
go mod download
make build        # 构建 relay + client 二进制文件
```

### 运行 Relay / Running the Relay

```bash
# 1. 创建配置文件 config/relay.yaml
cat > config/relay.yaml << 'EOF'
listen_addr: ":443"
tag_len: 16
user_ids:
  - "550e8400-e29b-41d4-a716-446655440000"
intent_file: "config/intent.yaml"
enforce_file: "config/enforce.yaml"
cloud_region: "us-east-1"
handshake_timeout: 10s
auth_read_timeout: 5s
log_level: "debug"
EOF

# 2. 启动 relay（需要 root 权限监听 443 端口）
sudo ./build/bin/chimney-relay -config config/relay.yaml
```

### 运行 Client / Running the Client

```bash
# 使用 UUID 认证（推荐）
./build/bin/chimney-client \
  -relay relay.example.com:443 \
  -sni cloudflare.com \
  -dest api.example.com:443 \
  -user-id "550e8400-e29b-41d4-a716-446655440000" \
  -fingerprint chrome

# 或使用显式 PSK（向后兼容）
./build/bin/chimney-client \
  -relay relay.example.com:443 \
  -sni cloudflare.com \
  -dest api.example.com:443 \
  -psk "your-64-char-hex-psk" \
  -fingerprint chrome
```

Client 在 `127.0.0.1:1080` 启动 SOCKS5 代理。配置你的应用使用此代理即可。

The client starts a SOCKS5 proxy on `127.0.0.1:1080`. Configure your applications to use this proxy.

### CLI 参数 / CLI Flags

| Flag | 默认值 | 说明 |
|------|--------|------|
| `-relay` | (必需) | Relay 服务器地址 `host:port` |
| `-sni` | (必需) | 白名单内的 SNI |
| `-dest` | (必需) | 最终目标地址 `host:port` |
| `-user-id` | `"default"` | 用户 UUID（自动派生 PSK） |
| `-psk` | (从 user-id 派生) | 显式预共享密钥（hex） |
| `-fingerprint` | `chrome` | uTLS 指纹，逗号分隔支持轮换 |
| `-profile` | (可选) | 流量 profile JSON（启用 padding） |
| `-dilution` | (可选) | 预录制内容块 JSON（启用 dilution） |
| `-padding-target` | `0` | 覆盖 padding 固定大小 |
| `-listen` | `127.0.0.1:1080` | 本地 SOCKS5 监听地址 |
| `-tag-len` | `16` | 认证标签长度 |

---

## 配置 / Configuration

### Relay 完整配置 / Full Relay Config

```yaml
listen_addr: ":443"

# ── 认证（三选一） / Authentication (pick one) ──

# 模式 A（推荐）：UUID 列表
# PSK = SHA256(UUID)，无需额外管理密钥
user_ids:
  - "550e8400-e29b-41d4-a716-446655440000"
  - "660e8400-e29b-41d4-a716-446655440001"

# 模式 B：显式 userID → PSK 映射
# users:
#   "user1": "hex-psk-64-chars..."
#   "user2": "hex-psk-64-chars..."

# 模式 C：单一 PSK（向后兼容）
# psk: "your-64-char-hex-psk"

tag_len: 16
intent_file: "config/intent.yaml"
enforce_file: "config/enforce.yaml"
cloud_region: "us-east-1"
default_backend: ""
handshake_timeout: 10s
auth_read_timeout: 5s
enable_profiling: true
profile_dir: "profiles"
cidr_refresh_interval: 24h
log_level: "info"
metrics_addr: ":8080"
```

### 意图白名单 / Intent Whitelist (`config/intent.yaml`)

```yaml
version: 1
entries:
  cloudflare.com:
    sni: cloudflare.com
    description: "Cloudflare CDN"
    settings_snapshot:
      HEADER_TABLE_SIZE: 4096
      ENABLE_PUSH: 0
      MAX_CONCURRENT_STREAMS: 100
      INITIAL_WINDOW_SIZE: 65535
      MAX_FRAME_SIZE: 16384
      MAX_HEADER_LIST_SIZE: 16384
```

### 执行层白名单 / Enforce Whitelist (`config/enforce.yaml`)

```yaml
version: 1
entries:
  - cidr: "104.16.0.0/12"
    provider: "cloudflare"
    region: "global"
```

---

## 多用户认证 (UUID) / Multi-User Auth

### 设计 / Design

Chimney v0.1 引入基于 UUID 的多用户认证。每个用户拥有一个 UUID，PSK 通过确定性派生得到：

```
PSK     = SHA256(UUID)           // 256-bit 密钥材料
KeyHint = SHA256(UUID)[0:4]      // 4-byte 查表索引
K_auth  = HKDF(PSK, "chimney-auth", ServerRandom)
Tag     = HMAC(K_auth, ServerRandom || ClientRandom)[:16]
```

### Auth Frame 格式 / Auth Frame Format

```
扩展格式（新）:
┌──────────────┬─────────────────────┐
│ key_hint (4) │ auth_tag (tagLen)   │
└──────────────┴─────────────────────┘

旧格式（向后兼容，单用户）:
┌─────────────────────┐
│ auth_tag (tagLen)   │
└─────────────────────┘
```

### Relay 侧 / Relay Side

`UserStore` 维护 `hint → {UserID, PSK}` 的 O(1) 哈希表：

```go
// 3 种构建方式
store, _ := auth.NewUserStoreFromIDs([]string{"uuid-1", "uuid-2"}, 16)
store, _ := auth.NewUserStore(map[string]string{"user1": "psk1"}, 16)
store, _ := auth.NewUserStore(map[string]string{"default": psk}, 16)  // 单用户
```

收到 auth frame 后：

1. `ExtractKeyHint(payload)` — 提取前 4 字节
2. `store.byHint[hint]` — O(1) 查找 `UserEntry`
3. `entry.Deriver.VerifyAuthTag(...)` — 验证 HMAC

### Client 侧 / Client Side

```go
// 根包 chimney.go — 自动派生
config := chimney.Config{
    RelayAddr:  "relay:443",
    SNI:        "cloudflare.com",
    UserID:     "550e8400-e29b-41d4-a716-446655440000",  // PSK 自动派生
}
d, _ := chimney.NewDialer(config)
```

```bash
# CLI — -psk 可选
chimney-client -user-id "550e8400-e29b-41d4-a716-446655440000" ...
```

### Key Hint 碰撞 / Collision Handling

4 字节 hint 的碰撞概率约为 `n² / 2³³`。对于 1000 个用户，碰撞概率约 10⁻⁴。如果发生碰撞，`NewUserStore` 会返回错误。解决方案：更改其中之一的 userID（添加后缀即可）。

---

## 库集成 (sing-box / Xray-core) / Library Integration

`chimney` 根包导出一个 `Dialer`，实现 `DialContext(ctx, network, addr) (net.Conn, error)` — 与 sing-box 的 `V2RayClientTransport` 和 Xray-core 的 `internet.Dialer` 接口兼容。

### API 参考 / API Reference

```go
import "github.com/shuffleman/chimney-protocol"
```

#### `Config`

```go
type Config struct {
    // ── 必需 / Required ──
    RelayAddr string   // relay 地址 "host:port"
    SNI       string   // TLS SNI（白名单站点）

    // ── 认证 / Authentication ──
    PSK    string       // 预共享密钥 hex（可选：有 UserID 时自动派生）
    UserID string       // 用户 UUID（可选：默认 "default"）
    TagLen int          // 认证标签长度（默认 16）

    // ── 指纹 / Fingerprint ──
    Fingerprint string  // uTLS 指纹名称（默认 "chrome"）
    // 可选: chrome, firefox, safari, ios, edge, android, 360, qq,
    //       randomized, golang — 可追加版本号如 "chrome-120"

    // ── 流量塑造 / Traffic Shaping（可选）──
    ProfilePath   string // 流量 profile JSON（padding 流）
    PaddingTarget int    // 覆盖 padding 固定大小（0 = 使用 profile 分布）
    DilutionPath  string // 预录制内容块 JSON（dilution 流）

    // ── 超时 / Timeouts ──
    ConnectTimeout   time.Duration  // TCP 连接超时（默认 10s）
    HandshakeTimeout time.Duration  // TLS+H2 握手超时（默认 10s）
}
```

#### `NewDialer`

```go
func NewDialer(config Config) (*Dialer, error)
```

建立到 Relay 的完整 Chimney 隧道。内部自动完成：TCP 连接 → uTLS 握手 → AEAD 密钥派生 → H2 协商 → 认证。

#### `DialContext`

```go
func (d *Dialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error)
```

在已建立的隧道上打开新的 H2 虚拟流。返回的 `net.Conn` 是 `*streamConn` — 支持 `Read`、`Write`、`Close`、`SetDeadline` 等完整接口。

多个 goroutine 可以并发调用 `DialContext`，每个调用打开独立的 H2 流，复用同一条 TLS 连接。

#### `Close`

```go
func (d *Dialer) Close() error
```

关闭隧道及所有活跃流。

### 最小示例 / Minimal Example

```go
package main

import (
    "context"
    "io"
    "log"
    "net/http"

    chimney "github.com/shuffleman/chimney-protocol"
)

func main() {
    // 1. 建立隧道
    d, err := chimney.NewDialer(chimney.Config{
        RelayAddr: "my-relay.example.com:443",
        SNI:       "cloudflare.com",
        UserID:    "550e8400-e29b-41d4-a716-446655440000",
    })
    if err != nil {
        log.Fatal(err)
    }
    defer d.Close()

    // 2. 通过隧道发起 HTTP 请求
    conn, err := d.DialContext(context.Background(), "tcp", "api.github.com:443")
    if err != nil {
        log.Fatal(err)
    }

    // 3. 使用标准 net.Conn（TLS 在隧道内处理）
    client := &http.Client{
        Transport: &http.Transport{
            DialContext: d.DialContext,
        },
    }
    resp, _ := client.Get("https://api.github.com/zen")
    io.Copy(log.Writer(), resp.Body)
    resp.Body.Close()
}
```

### 集成到 sing-box / Integrate with sing-box

sing-box 的 `V2RayClientTransport` 接口：

```go
// sing-box 接口定义
type V2RayClientTransport interface {
    DialContext(ctx context.Context) (net.Conn, error)
}

// Chimney 适配器
type ChimneyTransport struct {
    dialer *chimney.Dialer
    addr   string  // 目标地址
}

func (t *ChimneyTransport) DialContext(ctx context.Context) (net.Conn, error) {
    return t.dialer.DialContext(ctx, "tcp", t.addr)
}
```

在 sing-box 配置中将 `chimney.Dialer` 注册为出站传输即可。

### 集成到 Xray-core / Integrate with Xray-core

Xray-core 的 `internet.Dialer` 接口：

```go
// Xray-core 接口定义
type Dialer interface {
    Dial(ctx context.Context, dest net.Destination) (stat.Connection, error)
}

// Chimney 适配器
func (d *Dialer) Dial(ctx context.Context, dest net.Destination) (stat.Connection, error) {
    netConn, err := d.dialer.DialContext(ctx, "tcp", dest.NetAddr())
    if err != nil {
        return nil, err
    }
    return stat.ConnectionFromNetConn(netConn), nil
}
```

---

## 安全原则 / Security Principles

1. **P1 — 无可区分失败路径 / No Distinguishable Failure Path**
2. **P2 — 无语义不连续性 / No Semantic Discontinuity**
3. **P3 — 无可观察协议转换 / No Observable Protocol Transition**
4. **P4 — 所有未认证流量保持合法 / All Unauthenticated Traffic Stays Legitimate**

---

## 协议规范 / Protocol Specification

本实现遵循 Chimney 协议规范 (v0.1)。关键密码学操作：

### 密钥派生 / Key Derivation

```
K_auth = HKDF(PSK, label="chimney-auth", info=ServerRandom)
Tag    = HMAC(K_auth, ServerRandom || ClientRandom)[:TagLen]

K_sess_send = HKDF(PSK, label="chimney-sess-send", info=SR || CR)
K_sess_recv = HKDF(PSK, label="chimney-sess-recv", info=SR || CR)
NonceBase   = HKDF(PSK, label="chimney-nonce",     info=SR || CR)
```

### 认证帧结构 / Auth Frame Structure

认证标签嵌入 TLS 握手后的第一个 Application Data 记录中。帧格式：

```
扩展帧（v0.1）:
┌──────────┬──────────┐
│ key_hint │ auth_tag │
│  4 bytes │ tagLen B │
└──────────┴──────────┘

key_hint = SHA256(UserID)[0:4]
auth_tag = HMAC(K_auth, ServerRandom || ClientRandom)[:TagLen]
```

Relay 在不解密 TLS 记录的情况下验证标签 — 它在握手转发期间观察 ServerRandom，从 key_hint 查找用户 PSK，派生 K_auth 后验证 HMAC。

### 流标识符 / Stream Identifiers

| Stream ID | 用途 |
|-----------|------|
| 1, 3, 5, ... | 客户端打开的隧道流 / Tunnel streams |
| `0x0FFFFFFD` | Dilution 流（真实 HTTP 内容） |
| `0x0FFFFFFF` | Padding 流（占位填充） |

---

## 项目结构 / Project Structure

```
chimney/
├── chimney.go                   # 导出 Dialer API
├── chimney_test.go              # Dialer 测试
├── cmd/
│   ├── chimney-relay/           # Relay 服务器二进制
│   └── chimney-client/          # Client 二进制 (SOCKS5)
├── internal/
│   ├── auth/                    # 认证标签 + UserStore
│   ├── config/                  # YAML 配置加载
│   ├── dilution/                # Dilution 流真实内容
│   ├── h2engine/                # HTTP/2 帧引擎
│   ├── keyderiv/                # HKDF 密钥派生 + KeyHint
│   ├── pcap/                    # PCAP 解析器
│   ├── profile/                 # 流量 Profile + 节奏控制
│   ├── record/                  # ChimneyRecord AEAD 编解码
│   ├── relay/                   # 核心 Relay 逻辑
│   └── whitelist/               # 双层白名单
├── config/
│   ├── relay.yaml.example       # Relay 配置模板
│   ├── client.yaml.example      # Client 配置模板
│   ├── intent.yaml              # 意图白名单
│   └── enforce.yaml             # 执行层 CIDR
├── go.mod
├── Makefile
└── README.md
```

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
| Relay 服务器 / Relay server | ✅ 完成 / Complete |
| Client (SOCKS5) / Client | ✅ 完成 / Complete |
| 站点校准工具 / Calibration tool | ✅ 完成 / Complete |
| uTLS 指纹轮换 / Fingerprint rotation | ✅ 完成 / Complete |
| Padding 流 / Padding stream | ✅ 完成 / Complete |
| Real content dilution | ✅ 完成 / Complete |
| **多用户 UUID 认证 / Multi-user auth** | ✅ 完成 / Complete |
| **导出 Dialer API / Exportable Dialer** | ✅ 完成 / Complete |

---

## 测试 / Testing

```bash
make test           # 全部测试
make test-coverage  # 覆盖率测试
make bench          # 基准测试
make ci             # CI 流水线 (fmt + vet + test + build)
```

---

## 安全注意事项 / Security Considerations

**这是一个研究性实现。** 生产部署前 / **This is a research implementation.** Before production deployment:

1. 在校准工具中实现 TLS 解密（keylog 支持）以获取精确的 SETTINGS
2. 审查并加固 H2 引擎以覆盖所有边界情况
3. 对完整系统进行正式安全分析
4. UUID 派生 PSK 的熵受限于 UUID 的随机性（v4 UUID ≈ 122 bits），如需 256-bit 安全强度请使用显式 PSK

---

## 许可证 / License

MIT License — 详见 [LICENSE](LICENSE) 文件。

---

## 致谢 / Acknowledgments

本实现基于 Chimney 协议规范，建立在 ShadowTLS v3 和 REALITY 的基础上。核心创新是 swap 后的流量塑造，维持了与真实 HTTPS 会话的行为不可区分性。
