# Chimney 项目代码理解手册

本文档面向之后接手 `chimney-protocol` 的开发者，目标不是再写一份 README，而是帮助读者理解这个项目的核心思想、代码分层、协议状态机，以及维护时最容易踩错的地方。

本文基于当前代码事实整理。若本文与早期规格文档、README 或注释冲突，应优先以代码和测试为准。

最后更新：2026-06-04

## 1. 一句话理解这个项目

Chimney 是一个“会话寄生式”传输原型。它不是简单把代理流量伪装成 TLS，而是先借用一个真实网站的 TLS 握手，让外部观察者看到一段真实、可解释的 HTTPS 连接；随后客户端和 relay 在这条 TCP 连接上切换到 Chimney 自己的加密记录层，把内部 HTTP/2 帧当作数据复用载体，承载多路 TCP/UDP 子流。

这个项目的核心不是“加密”，而是“失败路径和成功路径在行为上尽量不可区分”。

普通代理的常见问题是：认证失败、协议不匹配、探测请求、TLS 指纹、连接关闭时序都会暴露“这里不是一个正常网站”。Chimney 的思想是：如果不能确认对方是合法客户端，就继续像一个透明转发器一样把连接交给真实站点；只有在捕获到可解密的 ChimneyRecord 并完成 H2 内认证后，relay 才接管连接。

## 2. 项目思想

### 2.1 借来的真实 TLS

客户端连接 relay 时，TLS ClientHello 里的 SNI 不是 relay 自己的域名，而是一个白名单真实站点，例如 `cloudflare.com`。relay 不终止 TLS，也不生成证书，而是把 ClientHello 转发给真实站点，再把真实站点的 ServerHello 等握手字节转发回客户端。

这带来几个效果：

- 外部看到的是客户端和一个地址建立 TLS 会话，握手参数来自真实站点。
- relay 可以旁路观察 TLS 1.3 ServerHello 中明文可见的 `ServerRandom`。
- 客户端本地 uTLS 也能拿到 `ClientRandom` 和 `ServerRandom`。
- 双方用这些随机数和预共享密钥派生出 Chimney 会话密钥。

### 2.2 先混入，再接管

TLS 握手后，客户端从 uTLS 对象拿到底层 TCP 连接，开始写 ChimneyRecord。ChimneyRecord 外观是 TLS application_data 记录：

```text
type    = 0x17
version = 0x0303
length  = ciphertext length
payload = AES-GCM ciphertext
```

relay 在握手转发时捕获客户端第一个或前几个 `0x17` TLS application_data 记录，然后尝试用候选用户密钥解密。如果解不开，就把这些数据继续转发给真实站点，让失败路径看起来像正常浏览器或异常客户端与真实站点交互。

如果能解开，relay 才进入 swap：关闭真实站点连接，把客户端连接改为 ChimneyRecord + H2 tunnel。

### 2.3 认证延后到 H2 DATA

旧设计可能会让人误以为 auth tag 在 TLS application_data 的固定偏移里。当前代码不是这样。

当前真实流程是：

1. relay 先扫描到一个可解密的 ChimneyRecord。
2. client 和 relay 完成内部 H2 preface/SETTINGS 交换。
3. client 在一个 H2 DATA frame 里发送认证 payload：

```text
[ key_hint: 4 bytes ][ auth_tag: tagLen bytes ]
```

`key_hint = SHA256(userID)[:4]`，用于 relay 快速定位用户。`auth_tag` 是基于 `ServerRandom || ClientRandom` 的 HMAC 截断值。

### 2.4 伪装不只在握手，还在流量形态

项目里有三层流量形态相关机制：

- uTLS fingerprint：让 ClientHello 形态接近真实浏览器。
- H2 SETTINGS：内部 H2 设置尽量对齐真实站点 SETTINGS。
- profile / padding / dilution：控制记录大小、节奏、保留流上的填充和预录制内容。

这些机制还没有全部达到生产级，但代码结构已经为它们留出了位置。

## 3. 仓库结构总览

```text
.
├── chimney.go                         # 根包，导出 Dialer API
├── cmd/
│   ├── chimney-client/                # 本地 SOCKS5 客户端
│   ├── chimney-relay/                 # relay 服务端入口
│   ├── h2probe/                       # 探测真实站点 H2 SETTINGS
│   ├── calibrate/                     # 从 pcap/keylog 推导 SETTINGS/profile
│   ├── socks_stress/                  # SOCKS5 端到端压测工具
│   ├── remote-throughputtest/         # 根包 Dialer 吞吐测试
│   ├── speedtest/                     # HTTP 代理测速辅助
│   └── upload_debug/                  # 上传/record 诊断工具
├── internal/
│   ├── auth/                          # 用户表、auth tag、key hint
│   ├── config/                        # YAML 配置结构和校验
│   ├── dilution/                      # 预录制内容块
│   ├── h2engine/                      # HTTP/2 frame 编解码和 record I/O
│   ├── keyderiv/                      # HKDF 派生
│   ├── pcap/                          # pcap 解析和 TLS record 提取
│   ├── profile/                       # 流量 profile 和 pacing
│   ├── record/                        # ChimneyRecord AEAD 层
│   ├── relay/                         # relay 核心协议状态机
│   └── whitelist/                     # intent + enforce 双层白名单
├── config/                            # 示例配置
├── docs/                              # 文档
├── docker/                            # Dockerfile 和 compose 示例
└── Makefile
```

接手时建议按下面顺序读代码：

1. `cmd/chimney-relay/main.go`：看 relay 怎样启动、加载配置、暴露 admin API。
2. `internal/relay/relay.go`：看协议状态机和后端连接管理。
3. `cmd/chimney-client/main.go`：看 CLI SOCKS5 client 的隧道建立和重连。
4. `chimney.go`：看库版 Dialer、连接池和 `net.Conn` 抽象。
5. `internal/record`、`internal/h2engine`、`internal/keyderiv`、`internal/auth`：看底层协议组件。

## 4. 三个入口的真实职责

### 4.1 `cmd/chimney-relay`

relay 二进制负责：

- 加载 YAML relay config。
- 创建 `internal/relay.Server`。
- 启动 TCP listener。
- 可选启动 admin API。
- 定时打印统计。
- 响应 SIGINT/SIGTERM 并等待连接退出。

入口文件只做组装，核心协议不在这里。admin API 目前是 JSON API，不是 Prometheus exporter。

admin 端点：

- `GET /health`：不鉴权。
- `GET /admin/stats`：需要 token；无 token 时只允许 loopback。
- `GET /admin/users`：列用户。
- `POST /admin/users`：动态添加用户。
- `DELETE /admin/users`：删除用户。
- `POST /admin/refresh-cidrs`：当前只是占位返回 OK。

`metrics_token` 或环境变量 `CHIMNEY_ADMIN_TOKEN` 用于 admin 鉴权。比较逻辑使用常量时间比较。

### 4.2 `cmd/chimney-client`

CLI client 是一个本地 SOCKS5 代理：

```text
本地程序 -> 127.0.0.1:1080 SOCKS5 -> chimney-client -> relay -> 目标地址
```

它的职责：

- 用 uTLS 指纹连接 relay。
- 以 `-sni` 发起真实 TLS 握手。
- 切换到底层 TCP + ChimneyRecord。
- 完成内部 H2 握手和 H2 DATA auth。
- 本地监听 SOCKS5。
- 每个 SOCKS5 CONNECT 映射成一个 H2 stream。
- tunnel 死亡时，在下一次 CONNECT 或 open stream 失败后重连。

注意：`cmd/chimney-client` 当前只读 CLI flags，不读 `config/client.yaml.example`。

### 4.3 根包 `chimney.go`

根包面向其他 Go 程序集成，导出：

- `Config`
- `NewDialer`
- `Dialer.DialContext`
- `Dialer.ListenPacket`
- `RelayConfig`
- `NewRelayServer`

根包 Dialer 与 CLI client 不是同一份实现：

- 根包有 tunnel pool，默认 `PoolSize=4`。
- CLI client 是单 tunnel + SOCKS5。
- 根包支持 `net.Conn` deadline。
- 根包支持 UDP `net.PacketConn`。

维护时要小心双实现漂移：如果修了 CLI tunnel backpressure，通常也要检查根包 `dispatchFrames`；反过来也一样。

## 5. relay 核心状态机

relay 的核心在 `internal/relay/relay.go`。

### 5.1 启动

`NewServer` 做这些事：

- 补默认超时。
- 加载 whitelist。
- 创建 `auth.UserStore`。
- 创建全局 dial/connection semaphore。

`Start` 创建 TCP listener，进入 `acceptLoop`。每个连接一个 goroutine 执行 `handleConnection`。

### 5.2 `handleConnection`

主流程：

```text
readClientHello
  -> resolveDestination
  -> whitelist.CheckDestination
  -> dial real site
  -> forward ClientHello
  -> relayHandshake
  -> inspect first app data
  -> performSwap or forwardToSite
```

关键点：

- 读 ClientHello 前设置 `HandshakeTimeout`，防慢连接占 goroutine。
- `readClientHello` 只读一个 TLS record，并从其中提取 SNI 和 ClientRandom。
- 白名单失败时走 `passiveFallback`。
- `resolveDestination` 用 `net.LookupHost(sni)`，取第一个 IP。
- 连接真实站点固定使用 443 端口。

### 5.3 `relayHandshake`

这个函数同时跑两个方向的转发：

- server -> client：转发真实站点数据，并从 ServerHello 提取 ServerRandom。
- client -> server：转发握手/CCS，一旦看到客户端第一个 `0x17` application_data，就停止转发并把后续短时间内到达的数据一并捕获。

捕获到 `firstAppData` 后，relay 不立刻认为它是 Chimney。它只是把这些 bytes 交给 `performSwap` 尝试解密。

### 5.4 `performSwap`

这是 Chimney 的“门槛”函数。

它做这些事：

1. 从配置 PSK 和 `UserStore` 里收集候选 deriver。
2. 调 `findChimneyRecord` 扫描 `firstAppData`。
3. 如果初始数据太短，短暂继续从客户端读一些数据再扫描。
4. 找不到 ChimneyRecord：返回错误，调用方继续透明转发。
5. 找到 ChimneyRecord：派生方向密钥和 nonce。
6. 把非 Chimney 的 prelude records 转发给真实站点。
7. 用 `prependConn` 把已经读出来的 ChimneyRecord 重新塞回 record reader。
8. 创建 `record.Reader/Writer` 和 `h2engine.Engine`。
9. `AcceptAsServer` 读取 H2 preface + client SETTINGS。
10. 读取 client SETTINGS ACK。
11. 读取 H2 DATA auth frame。
12. 用 `UserStore.VerifyTag` 验证。
13. 成功后关闭真实站点连接，进入 `handleTunnel`。

这里最重要的安全性质是：认证失败之前，真实站点连接仍然活着，失败路径可以继续转发。

### 5.5 `handleTunnel`

swap 成功后，relay 进入 H2 tunnel loop：

```text
ReadFrame
  -> reserved stream: discard
  -> DATA:
       existing TCP stream -> write channel
       existing UDP stream -> UDP socket
       new UDP command -> create UDP backend
       pending TCP stream -> buffer or cancel
       CONNECT -> async dial backend
  -> RST_STREAM -> closeStream
  -> GOAWAY -> return
```

TCP 后端连接管理由 `tunnelConnPool` 负责。

关键并发保护：

- `MaxConcurrentBackendDials = 64`：限制同时拨号数量。
- `MaxBackendConnsGlobal = 128`：限制全局后端连接数。
- `maxPendingStreams = 256`：限制等待后端连接的 stream 数。
- `maxPendingBytesPerStream = 256 KiB`：限制 CONNECT 未完成前的数据缓存。
- pending stream 有 context，RST/CLOSE/overflow/closeAll 都会取消等待 slot 或正在拨号的 goroutine。

## 6. client 核心状态机

CLI client 在 `cmd/chimney-client/main.go`。

### 6.1 `establishTunnel`

主流程：

```text
net.DialTimeout(relay)
  -> uTLS Handshake(SNI)
  -> extract randoms
  -> derive tag, key hint, directional keys
  -> drain stale TCP bytes
  -> create RecordReader/Writer
  -> send H2 preface + SETTINGS as ChimneyRecord
  -> completeH2Handshake
  -> send H2 DATA auth frame
  -> newTunnelConn
```

`InsecureSkipVerify: true` 是有意的：客户端不是要验证真实站点证书来访问该站点，而是借用握手参数建立外观。这里的安全边界来自 PSK/HMAC 和 relay 白名单，不来自 WebPKI。

### 6.2 `tunnelManager`

CLI client 的 tunnelManager 保证：

- 初次运行先建立 tunnel。
- 如果 tunnel dead，下一次请求会重建。
- 如果 open stream 失败，会强制重建 tunnel 并重试一次。

它不是后台自动无限重连。实际语义是“按需重连”：没有新 SOCKS 请求时，进程可以活着但不主动重连。

### 6.3 SOCKS5 映射

`runSOCKS5` 监听本地地址。每个本地 TCP 连接：

1. SOCKS5 no-auth handshake。
2. 只支持 CONNECT，不支持 UDP ASSOCIATE。
3. 解析目标地址。
4. `openStream(targetAddr)`。
5. 返回 SOCKS5 success。
6. 双向 `io.Copy`。

握手和请求阶段设置了 deadline，避免本地半连接长期占 goroutine。进入转发前清除 deadline。

### 6.4 `tunnelConn.dispatchFrames`

dispatcher 从 H2 engine 读 frame，再投递到对应 stream channel。这里不能丢帧，因为 TCP byte stream 的任意丢失都会导致上层连接损坏。

当前策略：

- channel 有空间：直接投递。
- channel 满：等待。
- 等待超过 `tunnelIdleTimeout`：关闭底层连接，标记 tunnel dead，后续请求触发重连。

## 7. 根包库 API

根包 `chimney.go` 是给其他 Go 项目集成的 API。

对外稳定入口：

- `Config`
- `DefaultConfig`
- `ConfigFromYAML`
- `LoadConfigFile`
- `Config.Normalize`
- `NewDialer`
- `Dialer.DialContext`
- `Dialer.ListenPacket`
- `Dialer.Close`
- `Dialer.IsDead`
- `Dialer.LastError`
- `Dialer.Diagnostics`

三方项目接入时只应 import 根包：

```go
import chimney "github.com/shuffleman/chimney-protocol"
```

不要 import `internal/config` 或其他 `internal/*` 包；根包已经提供 YAML 加载、默认值和校验能力。

### 7.1 配置入口

`Config` 中的关键字段：

- relay/SNI/auth：`RelayAddr`、`SNI`、`PSK`、`UserID`、`TagLen`
- 指纹：`Fingerprint`
- profile/dilution：`ProfilePath`、`PaddingTarget`、`DilutionPath`
- timeout/pool：`ConnectTimeout`、`HandshakeTimeout`、`PoolSize`、`TCPBufferSize`

`Normalize` 会补默认值、从 `UserID` 派生 PSK，并校验 PSK、tag length、fingerprint。三方项目可以直接构造 `Config`，也可以用 `LoadConfigFile` 从 YAML 加载。

### 7.2 `NewDialer`

初始化逻辑：

- 调用 `Config.Normalize` 补默认值和校验配置。
- 如果没有显式 PSK，但有 UserID，则 `PSK = SHA256(UserID)`。
- 如果 PSK 和 UserID 都没有，直接报错。
- 可选加载 profile/dilution。
- 创建 `PoolSize` 条 tunnel。

### 7.3 `newTunnel`

和 CLI 的 `establishTunnel` 类似，但根包是库形态：

- TCP dial。
- uTLS handshake。
- 派生方向密钥。
- 切到底层 TCP。
- 发送 H2 opening。
- 完成 H2 握手。
- 发送 auth DATA frame。
- 启动 `dispatchFrames`。

### 7.4 `DialContext`

每次调用：

- 检查 Dialer 是否关闭。
- round-robin 选择 tunnel。
- 如果 tunnel dead，`ensureTunnel` 懒重建。
- 在 tunnel 上打开 H2 stream。
- 发送 `0x01 + addr` CONNECT。
- 等 relay 返回 `0x01` CONNECT_OK。
- 返回 `streamConn`。

`streamConn` 实现 `net.Conn`，支持 deadline。读写时会处理 Chimney 子协议命令：

- `0x02`：数据。
- `0x03`：EOF。

### 7.5 UDP

根包提供 `ListenPacket(ctx)`：

- 一个 Dialer 只允许一个 UDP PacketConn。
- 使用固定 `udpStreamID = 0x40000001`。
- datagram 在 H2 DATA frame 中保留边界。
- relay 为 UDP stream 创建 UDP socket。

CLI SOCKS5 目前没有实现 UDP ASSOCIATE，因此普通命令行客户端暂不暴露 UDP。

## 8. 底层模块

### 8.1 `internal/keyderiv`

负责 HKDF：

```text
K_auth       = HKDF(PSK, "chimney-auth", ServerRandom)
sendKey      = HKDF(PSK, "chimney-sess-send", ServerRandom || ClientRandom)
recvKey      = HKDF(PSK, "chimney-sess-recv", ServerRandom || ClientRandom)
nonceBase    = HKDF(PSK, "chimney-nonce", ServerRandom || ClientRandom)
key_hint     = SHA256(userID)[:4]
```

当前显式 hex PSK 必须解码为 32 bytes。

### 8.2 `internal/auth`

负责认证语义：

- `Authenticator`：单 PSK auth tag。
- `UserStore`：多用户 key hint 到 deriver 的映射。
- `DerivePSKFromID`：`SHA256(userID)`。
- `ExtractKeyHint` / `ExtractTagFromHintFrame`：解析 H2 auth payload。
- `ClientRandomExtractor` / `ServerRandomExtractor`：从 TLS handshake bytes 提取 random。

`UserStore` 会检查 key hint 碰撞。4 字节 hint 对大量用户存在碰撞概率，所以用户规模扩大时需要监控和测试。

### 8.3 `internal/record`

负责 ChimneyRecord：

- AES-GCM seal/open。
- TLS-like 5 字节 record header。
- sequence nonce。
- read buffer 和 record 边界恢复。
- `RecordWriter` 串行化写入，避免 record interleaving。
- Windows 下限制单次写入 chunk，规避历史 TCP 写入腐败问题。

注意：`NewSealerChaCha20Poly1305` 目前实际不可用，会返回提示并最终使用 AES-GCM 路径。不要误以为项目当前支持 ChaCha20-Poly1305。

### 8.4 `internal/h2engine`

负责最小 H2 frame 层：

- SETTINGS 编码/解码。
- DATA/RST/WINDOW_UPDATE 等 frame 构造。
- client opening sequence。
- server accept sequence。
- record reader/writer 上的 frame read/write。
- padding/dilution reserved stream。

这不是完整 HTTP/2 协议栈。它只是借用 HTTP/2 frame 格式做 tunnel multiplexing 和流量形态伪装。

### 8.5 `internal/whitelist`

两层白名单：

- intent layer：SNI 名称列表。
- enforce layer：CIDR 列表。

`CheckDestination(sni, ip)` 要求两层都通过。

注意：这个白名单控制的是借用 TLS 握手时的 SNI/真实站点 IP。swap 成功后的 CONNECT 目标由 relay 的 CONNECT ACL 控制：

- `connect_deny_private`：拒绝 private、loopback、link-local、multicast、unspecified 地址。
- `connect_allow_cidrs`：非空时，CONNECT 目标必须落在 allow CIDR 内。
- `connect_deny_cidrs`：deny 优先级高于 allow。

代码会在认证后的 CONNECT 阶段解析目标 host，选择通过 ACL 的 IP，并使用该 IP 拨号。

### 8.6 `internal/profile`

建模记录大小、burst、gap、方向比例和 burst 内 pacing。

当前使用方式：

- 根包/CLI client 可加载 profile，用于 padding。
- relay 开启 profiling 时使用默认模型做简单 sleep pacing。
- `profile_dir` 配置字段存在，但当前 relay 未按站点加载 profile 文件。

### 8.7 `internal/dilution`

加载预录制内容块，用于向 reserved dilution stream 写入内容。relay 看到 reserved stream 后丢弃，不转发给真实站点。

### 8.8 `internal/pcap`

提供简单 pcap parser、TCP packet 提取、TLS record 提取、NSS key log 解析等，主要服务 `cmd/calibrate`。

## 9. 内部 wire format

### 9.1 ChimneyRecord

```text
0               1               3               5
+---------------+---------------+---------------+
| type = 0x17   | version=0303  | length        |
+---------------+---------------+---------------+
| AES-GCM ciphertext ...                         |
+------------------------------------------------+
```

AEAD additional data 是 5 字节 header。

### 9.2 H2 DATA payload 命令

```text
TCP CONNECT:
[0x01][dest string bytes]

CONNECT_OK:
[0x01]

TCP DATA:
[0x02][raw bytes]

CLOSE:
[0x03]

UDP:
[0x04][addrType][addr][port][payload]
```

TCP 大块写入必须按 `maxTunnelDataChunk = 16*1024-1` 分片，保证每个 H2 DATA frame 都有命令字。不要依赖“后续 fragment 没有命令字”的旧兼容逻辑。

## 10. 代码里最重要的约束

### 10.1 不要破坏失败路径

relay 在认证失败前应尽量保持透明转发语义。不要为了“快速失败”返回特殊错误、提前 RST、打印对外可见行为或改变时序太明显。

### 10.2 不要在多个 goroutine 直接写同一个 record writer

`RecordWriter` 自身有 mutex，但 H2/frame/stream 级别仍需要理解 backpressure。随意新增 goroutine 写 H2 frame，可能造成时序、队列和关闭路径问题。

### 10.3 frame 不能丢

H2 DATA 承载 TCP byte stream。任何静默丢帧都会造成上层 TLS/HTTP/下载流损坏。channel 满时应等待、施加 backpressure，或者判定 tunnel 死亡，不能 `default` 丢弃。

### 10.4 pending CONNECT 必须可取消

CONNECT 后端拨号可能卡在：

- 全局连接 slot。
- 全局 dial semaphore。
- TCP dial。

如果客户端已经 RST/CLOSE，必须取消 pending context，否则高并发取消会泄漏 goroutine、后端连接或 semaphore。

### 10.5 PSK 长度必须严格

显式 PSK 必须是 64 hex chars，解码后 32 bytes。不要重新引入任意长度 raw PSK 的兼容逻辑到主路径。

### 10.6 CLI client 与根包 Dialer 需要同步维护

现在存在两份 tunnel 实现。改动以下逻辑时要双向检查：

- H2 opening。
- auth frame。
- stream command prefix。
- frame dispatch backpressure。
- close/dead/reconnect。
- padding/dilution。

## 11. 当前实现边界

这些不是 bug，而是当前代码事实：

- CLI client 支持 YAML `-config`，CLI flags 会覆盖 YAML 字段。
- CLI SOCKS5 只支持 CONNECT，不支持 UDP ASSOCIATE。
- 根包支持 UDP `ListenPacket`，但只允许一个 UDP PacketConn。
- relay 的 `profile_dir` 未真正按站点加载。
- `/admin/refresh-cidrs` 是占位。
- `default_backend` 为空时，失败连接自然关闭。
- relay 对 swap 后 CONNECT 目标已有基础 ACL；生产配置建议开启 `connect_deny_private` 并按需配置 allow/deny CIDR。
- `InsecureSkipVerify` 是协议设计的一部分，不是普通 HTTPS client 的安全模型。
- `README` 中部分版本号和命令可能落后，部署以 `docs/developer-deployment-manual.md` 和代码为准。

## 12. 测试体系

常规检查：

```powershell
go test ./...
go vet ./...
staticcheck ./...
```

race 测试：

```powershell
$env:CGO_ENABLED='1'
go test -race ./...
```

Windows 上如果没有 gcc，`-race` 会因 cgo 工具链缺失失败。

重点测试文件：

- `chimney_test.go`：根包 net.Conn/deadline/ListenPacket 基础测试。
- `chimney_stress_test.go`：本地混合流量压测，需要指定 stress tag。
- `cmd/chimney-client/main_test.go`：CLI frame backpressure。
- `cmd/chimney-relay/main_test.go`：admin 鉴权。
- `internal/relay/relay_test.go`：pending stream 取消。
- `internal/record/record_test.go`：record codec。
- `internal/h2engine/h2engine_test.go`：H2 frame。
- `internal/auth`、`internal/keyderiv`、`internal/config`、`internal/whitelist`：基础安全组件测试。

stress 测试示例：

```powershell
go test -tags stress -run TestLocalMixedTrafficStress -count=1 -timeout 3m -v
```

真实链路速度测试示例：

```powershell
curl.exe -x socks5h://127.0.0.1:1080 -o NUL http://speedtest.tokyo2.linode.com/100MB-tokyo2.bin
```

## 13. 常见排障思路

### 13.1 client 进程活着但 curl 不通

先判断 tunnel 是否 dead：

- CLI client 不是后台无限重连，而是在下一次 SOCKS CONNECT 或 openStream 失败时重连。
- 如果 dispatcher 因读超时或 stream 堵塞标记 dead，下一次请求应触发重建。

检查：

```powershell
Get-Process chimney-client
curl.exe -x socks5h://127.0.0.1:1080 -v http://example.com/
```

### 13.2 relay 日志出现 auth failed

可能原因：

- client 和 relay PSK/UserID 不一致。
- SNI 不在 intent 白名单。
- enforce CIDR 没覆盖 SNI 解析出的 IP。
- uTLS 握手后的 stale bytes/drain 或 record 序号不同步。

### 13.3 bad record MAC

通常是 record 序号或方向密钥不同步：

- 检查 client/relay 是否都使用 directional keys。
- 检查是否有 frame/record 丢失。
- 检查 WriteRecord 是否出现部分写失败。
- 检查是否误把非 Chimney application_data 当作 tunnelPrefix。

### 13.4 高并发下卡死

重点看：

- `tunnelIdleTimeout`。
- per-stream channel 是否被消费者读走。
- relay `connSem` 是否达到 `MaxBackendConnsGlobal`。
- pending stream 是否被取消。
- 后端目标是否慢连接或拒绝连接。

## 14. 后续演进建议

优先级较高：

- 合并或抽象 CLI client 与根包 Dialer 的重复 tunnel 逻辑。
- 给 CLI client 增加 YAML config。
- 给 relay swap 后 CONNECT 目标加可选 ACL。
- 为 relay kill / network drop / client reconnect 增加自动集成测试。
- 实现真实 `refresh-cidrs`。

中期：

- relay 按 SNI 加载 `profile_dir`。
- 完善 H2 flow control，而不是只使用 frame 容器。
- 完善 UDP 暴露方式，支持 SOCKS5 UDP ASSOCIATE。
- 把 calibration 输出和 intent.yaml/settings_snapshot 串起来。

长期：

- 用更正式的威胁模型描述“行为不可区分”边界。
- 引入更真实的流量 profile 和站点内容 dilution。
- 对 key hint 碰撞和多用户管理做更完整的运维支持。
- 对 active probing、timing side-channel、资源耗尽做系统性测试。

## 15. 开发者心智模型

维护这个项目时，可以把它想成四层：

```text
外观层：真实 TLS 握手 + uTLS 指纹 + 白名单站点
认证层：ServerRandom/ClientRandom + PSK/UserID + H2 auth DATA
记录层：伪 TLS application_data + AES-GCM ChimneyRecord
隧道层：H2 frame + Chimney cmd + TCP/UDP backend
```

任何改动都要问四个问题：

1. 这会不会让失败路径变得更特殊？
2. 这会不会破坏 record/H2/frame 的边界？
3. 这会不会让某个 goroutine、连接、semaphore 在取消路径泄漏？
4. CLI client 和根包 Dialer 是否也要同步修改？

如果能一直用这四个问题约束代码，这个项目会变得容易维护得多。
