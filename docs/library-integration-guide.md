# Chimney 三方库接入手册

本文档面向把 `github.com/shuffleman/chimney-protocol` 作为 Go 三方库接入其他代理项目的开发者，典型目标包括 sing-box、Xray-core、自研代理内核或网关程序。

最后更新：2026-06-04

## 1. 接入目标

Chimney 作为库接入时只暴露一个稳定核心：

```go
import chimney "github.com/shuffleman/chimney-protocol"

d, err := chimney.NewDialer(chimney.Config{...})
conn, err := d.DialContext(ctx, "tcp", "example.com:443")
```

`DialContext` 返回标准 `net.Conn`。这意味着接入方可以把 Chimney 放在任何接受 `func(context.Context, string, string) (net.Conn, error)` 或 `net.Conn` 的位置，例如：

- `http.Transport.DialContext`
- 自研 outbound dialer
- sing-box outbound transport adapter
- Xray-core transport/dialer adapter

## 2. 稳定公共 API

当前建议第三方项目只依赖根包：

```go
github.com/shuffleman/chimney-protocol
```

不要 import：

```go
github.com/shuffleman/chimney-protocol/internal/...
```

`internal/` 包受 Go 语言规则保护，外部项目不能稳定导入，也不应该作为集成边界。

sing-box 和 Xray-core 自身维护接入层，Chimney 仓库不提供也不发布独立 adapter 包。下游接入层直接依赖根模块版本，例如 `github.com/shuffleman/chimney-protocol@vX.Y.Z`。

公共 API：

```go
type Config struct { ... }

func DefaultConfig() Config
func ConfigFromYAML(data []byte) (Config, error)
func LoadConfigFile(path string) (Config, error)
func (c *Config) Normalize() error

func NewDialer(config Config) (*Dialer, error)
func (d *Dialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error)
func (d *Dialer) ListenPacket(ctx context.Context) (net.PacketConn, error)
func (d *Dialer) Close() error
func (d *Dialer) IsDead() bool
func (d *Dialer) LastError() error
func (d *Dialer) Diagnostics() string
```

## 3. 配置模型

最小配置：

```go
cfg := chimney.Config{
    RelayAddr: "relay.example.com:443",
    SNI:       "cloudflare.com",
    UserID:    "550e8400-e29b-41d4-a716-446655440000",
}
```

显式 PSK：

```go
cfg := chimney.Config{
    RelayAddr: "relay.example.com:443",
    SNI:       "cloudflare.com",
    PSK:       "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
}
```

YAML：

```yaml
relay_addr: "relay.example.com:443"
sni: "cloudflare.com"
user_id: "550e8400-e29b-41d4-a716-446655440000"
tag_len: 16
fingerprint: "chrome"
pool_size: 4
tcp_buffer_size: 262144
connect_timeout: 10s
handshake_timeout: 10s
```

加载：

```go
cfg, err := chimney.LoadConfigFile("chimney.yaml")
if err != nil {
    return err
}
d, err := chimney.NewDialer(cfg)
```

`Normalize()` 会：

- 填充默认值。
- 当 `PSK` 为空且 `UserID` 非空时派生 PSK。
- 校验 `relay_addr`、`sni`、PSK、`tag_len`、fingerprint。

## 4. 生命周期

推荐由上层 outbound 管理一个长期 `Dialer`：

```go
type Outbound struct {
    dialer *chimney.Dialer
}

func NewOutbound(cfg chimney.Config) (*Outbound, error) {
    d, err := chimney.NewDialer(cfg)
    if err != nil {
        return nil, err
    }
    return &Outbound{dialer: d}, nil
}

func (o *Outbound) Close() error {
    return o.dialer.Close()
}
```

不要为每个目标请求创建一个新的 `Dialer`。`NewDialer` 会建立 `PoolSize` 条到 relay 的 TLS+H2 tunnel，适合作为长期连接池使用。每次代理请求只调用：

```go
conn, err := dialer.DialContext(ctx, "tcp", target)
```

## 5. TCP 接入模式

最常见模式是把 Chimney 当成 outbound dialer：

```go
func (o *Outbound) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
    if network != "tcp" && network != "tcp4" && network != "tcp6" {
        return nil, fmt.Errorf("unsupported network: %s", network)
    }
    return o.dialer.DialContext(ctx, "tcp", addr)
}
```

`addr` 必须是 `host:port`。DNS 策略通常由上层项目决定：

- 如果上层传入域名，relay 侧按 CONNECT 目标解析。
- 如果上层已经解析为 IP，Chimney 直接转发该 IP 目标。

## 6. UDP 接入模式

根包提供：

```go
pc, err := dialer.ListenPacket(ctx)
```

当前边界：

- `ListenPacket` 是 `net.PacketConn` 形态。
- 同一个 `Dialer` 可以并发创建多个 UDP `PacketConn`，每个 `PacketConn` 对应一个独立 H2 stream。
- CLI SOCKS5 尚未实现 UDP ASSOCIATE。
- sing-box/Xray 接 UDP 时应在 adapter 层评估目标框架需要的是 packet API、session API 还是 per-destination UDP conn。

## 7. sing-box 接入建议

建议在 sing-box 侧新增一个 outbound transport adapter，把 Chimney 包装为项目内部的 dialer/transport，而不是修改 Chimney 根包去依赖 sing-box。

示意：

```go
type ChimneyOutbound struct {
    dialer *chimney.Dialer
}

func NewChimneyOutbound(options ChimneyOptions) (*ChimneyOutbound, error) {
    cfg := chimney.Config{
        RelayAddr: options.RelayAddr,
        SNI:       options.SNI,
        UserID:    options.UserID,
        PSK:       options.PSK,
        PoolSize:  options.PoolSize,
    }
    d, err := chimney.NewDialer(cfg)
    if err != nil {
        return nil, err
    }
    return &ChimneyOutbound{dialer: d}, nil
}

func (o *ChimneyOutbound) DialContext(ctx context.Context, network, destination string) (net.Conn, error) {
    return o.dialer.DialContext(ctx, network, destination)
}
```

实际 sing-box 接口会随版本变化。接入时以目标 sing-box 版本的 outbound adapter、transport 或 dialer interface 为准，保持 Chimney 只作为下层 `net.Conn` provider。

## 8. Xray-core 接入建议

建议在 Xray-core 侧实现一个 transport/dialer adapter，把 Xray 的 destination/session 转成 `host:port`，然后调用 Chimney：

```go
func (d *ChimneyDialer) Dial(ctx context.Context, destination string) (net.Conn, error) {
    return d.dialer.DialContext(ctx, "tcp", destination)
}
```

如果目标接口要求返回 Xray 自己的连接包装类型，应在 Xray adapter 层完成包装。Chimney 根包不应 import Xray 的 `stat`、`net`、`transport` 包，否则会把三方库变成单一项目插件，破坏通用性。

## 9. 错误处理和重连

`Dialer` 会在下一次 `DialContext` 时懒重建 dead tunnel。上层项目建议：

- 对单次 `DialContext` 错误按普通 outbound dial 失败处理。
- 长期失败时查看 `dialer.LastError()` 或 `dialer.Diagnostics()`。
- 进程退出、配置 reload、用户禁用时调用 `Close()`。

示例：

```go
conn, err := d.DialContext(ctx, "tcp", target)
if err != nil {
    if last := d.LastError(); last != nil {
        logger.Warn("chimney tunnel error", "error", last)
    }
    return nil, err
}
```

## 10. 接入方不要做的事

- 不要每个请求都 `NewDialer`。
- 不要 import `internal/*`。
- 不要假设底层是普通 TLS 到目标站点；`InsecureSkipVerify` 是协议外观设计的一部分。
- 不要在 adapter 层吞掉 `ctx.Done()`；取消信号必须传入 `DialContext`。
- 不要绕过 `Close()` 直接关闭内部 tunnel。
- 不要在多个项目 adapter 中复制协议实现；协议逻辑应留在 Chimney 根包。

## 11. 后续库级路线

为了更好接入 sing-box/Xray，下一批优先事项：

1. 抽取 CLI client 与根包 Dialer 的共享 tunnel core，避免双实现漂移。
2. 增加库级集成测试：根包 Dialer 真实 relay 重启恢复。
3. 明确 UDP adapter 语义，决定是否暴露 per-destination UDP helper。
4. 给 Config 增加版本化字段和兼容策略。
5. 增加小型 adapter 伪代码示例，但不引入 sing-box/Xray 作为直接依赖，也不维护 adapter 包。
