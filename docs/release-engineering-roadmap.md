# Chimney 发布级工程路线图

本文档用于把 `chimney-protocol` 从当前研究/原型状态推进到可发布、可运维、可维护的企业级工程。它不是愿望清单，而是后续开发的执行索引：每个阶段都有明确目标、交付物和验收标准。

最后更新：2026-06-04

## 1. 发布级定义

本项目达到发布级，至少需要满足下面标准：

- 构建可重复：本地、CI、Docker、多平台 release artifact 都能稳定生成。
- 测试可信：单元测试、集成测试、压力测试、断线重连测试、配置校验测试可自动运行。
- 安全边界清晰：凭据、admin API、CONNECT 出口、白名单、失败路径有明确策略和测试。
- 运维可见：日志、健康检查、统计、错误诊断、部署手册完整。
- 配置一致：README、Makefile、Docker、示例 YAML、代码 CLI flags 不互相矛盾。
- 发布可回滚：版本号、tag、变更日志、二进制校验和、Docker image tag 清晰。
- 代码可演进：核心协议层、CLI、根包 Dialer 的重复实现有收敛计划，新增行为有测试。
- 三方库可接入：根包 API 稳定，配置加载公开，外部项目无需依赖 `internal/*`，可通过 adapter 接入 sing-box、Xray-core 等项目。

## 2. 当前基线

当前已经具备：

- relay 服务端、CLI SOCKS5 client、根包 Dialer。
- 根包 `chimney.Config`、`NewDialer`、`DialContext`、`ListenPacket`。
- 根包公开配置入口：`DefaultConfig`、`ConfigFromYAML`、`LoadConfigFile`、`Normalize`。
- ChimneyRecord、H2 frame、auth、key derivation、白名单、profile/dilution 基础模块。
- 多用户认证和 admin token 基础防护。
- CI workflow、Makefile 质量门禁、跨平台 build 入口、Docker compose 基础校准。
- CLI client 支持 YAML `-config`，且 CLI flags 可覆盖配置文件字段。
- relay 支持认证后 CONNECT 出口 ACL：allow CIDR、deny CIDR、deny private/loopback/link-local。
- 本地真实二进制集成 harness：构建 relay/client/socks_stress，启动真实进程并通过 SOCKS5 混合传输。
- 本地 relay 重启恢复 harness：client 进程不重启，relay 重启后新 SOCKS5 请求可恢复。
- `socks_stress` 支持 JSON 输出，便于 CI、发布报告和远端压测采集。
- tag 触发的 release workflow 初版：多平台二进制、SHA256SUMS、GitHub Release。
- 基础测试、`go vet`、`staticcheck` 当前可通过。
- 代码理解手册和部署手册。
- 三方库接入手册：`docs/library-integration-guide.md`。

当前主要缺口：

- CLI client 与根包 Dialer 存在重复 tunnel 实现。
- sing-box/Xray 的真实 adapter 示例还没有落到示例目录。
- 根包 Dialer 与 CLI client 仍存在重复 tunnel 实现，这是库接入长期维护的主要风险。
- relay 的 CONNECT 出口 ACL 已有基础实现，但还缺更完整的生产模板、审计日志和集成测试。
- admin API 还缺少完整权限模型、审计和真实 refresh-cidrs。
- release artifact 和 checksums 已有 GitHub Actions 初版；SBOM、changelog、签名还没有自动化。
- sing-box/Xray 接入层由各自项目维护；Chimney 只发布根模块 API。
- 真实网络场景的集成测试和 soak/stress 体系还不完整。
- 断线重连已有本地二进制 smoke 测试；还缺长时间 soak 和远端公网自动化。

## 3. 阶段规划

### 阶段 0：工程底座校准

目标：让当前代码库具备可靠的日常开发入口。

交付物：

- Makefile 与当前 CLI/config 行为一致。已完成。
- 增加标准检查目标：`check = fmt/check + vet + staticcheck + test`。已完成。
- 增加跨平台 build 目标，产出 Windows/Linux/macOS relay/client。已完成。
- 校准 Dockerfile 和 compose 示例。基础完成，仍需 Docker build 纳入 CI。
- 新增 CI workflow。已完成。

验收标准：

- `go test ./...` 通过。
- `go vet ./...` 通过。
- `staticcheck ./...` 通过。
- 本地 `make` 或等价命令可以构建 relay/client。
- CI 在 push/PR 上自动运行测试和构建。

### 阶段 1：配置与启动体验收敛

目标：统一 CLI、YAML、Docker、文档的配置模型。

交付物：

- `cmd/chimney-client` 支持 `-config`，同时保留 flags 覆盖。已完成。
- `cmd/chimney-relay` 支持环境变量覆盖关键字段。
- 示例配置拆分为开发、本地测试、生产模板。
- 配置校验错误更明确，并覆盖测试。部分完成：client config 与 CONNECT ACL CIDR 已覆盖。
- 统一 `metrics_addr`/admin API 的命名和文档。

验收标准：

- client 可用 flags 启动，也可用 YAML 启动。
- Docker client/relay 能使用示例 compose 启动到健康状态。
- 配置错误能在启动时 fail fast。

### 阶段 2：安全发布基线

目标：把“可用代理”推进到可控企业服务。

交付物：

- relay swap 后 CONNECT 出口 ACL：支持 deny private/loopback/link-local、allow CIDR、deny CIDR。基础完成；生产示例默认建议开启 `connect_deny_private`，代码默认保持兼容。
- admin API 分离只读/写权限，增加审计日志。
- 用户管理持久化方案或明确外部控制面接口。
- 密钥轮换和用户禁用流程。
- 安全测试覆盖：弱配置、admin 鉴权、出口 ACL、白名单失败路径。

验收标准：

- 未授权用户不能访问 admin 写端点。
- 凭据泄漏场景下默认不能探测 relay 内网。
- 安全相关配置默认值保守。

### 阶段 3：可靠性和压力体系

目标：证明长时间、大流量、多并发、断线场景可靠。

交付物：

- 自动化本地集成测试：relay + client + backend + SOCKS5 curl-like 流量。基础完成：`scripts/test-local-binaries.ps1`。
- 自动化断线重连测试：kill relay、重启 relay、验证 client 新请求恢复。基础完成：`scripts/test-local-binaries.ps1 -ReconnectCheck`。
- soak/stress 工具标准化输出 JSON。基础完成：`cmd/socks_stress -json`。
- 性能基线：吞吐、连接数、延迟、CPU、内存。
- race 测试进入 CI 的 Linux job。

验收标准：

- 指定并发和流量规模下无数据损坏。
- relay 重启后 client 新连接可恢复。
- 长时间 soak 后 goroutine/连接/内存无持续泄漏趋势。

### 阶段 4：协议实现收敛

目标：减少重复实现和协议漂移，让 Chimney 根包成为 sing-box、Xray、自研代理可长期依赖的稳定库。

交付物：

- 抽取共享 tunnel/client core，使 CLI client 和根包 Dialer 复用关键逻辑。
- 明确公共 API 兼容策略：哪些字段/方法进入稳定面，哪些仍是实验能力。
- 增加 adapter 示例：标准 `net/http.Transport`、sing-box 风格 outbound、Xray 风格 dialer。
- 明确 H2 engine 是“frame 容器”还是要实现更多 flow control。
- 统一 padding/dilution/profile 行为。
- 明确 UDP 生产路径：SOCKS5 UDP ASSOCIATE 或独立 UDP API。

验收标准：

- auth frame、record、dispatch、close/reconnect 只保留一个核心实现或共享测试。
- 新协议行为只需在一处核心逻辑中修改。
- 三方项目只 import 根包，不需要复制协议实现或引用 `internal/*`。

### 阶段 5：运维与发布自动化

目标：具备企业部署和版本发布能力。

交付物：

- systemd unit 模板。
- Docker image 版本 tag。
- release workflow：构建多平台二进制、checksums、SBOM、release notes。基础完成：二进制、checksums、GitHub Release；SBOM/release notes 仍需增强。
- CHANGELOG。
- 运行手册：部署、升级、回滚、故障排查。

验收标准：

- tag push 后自动产出 release artifact。
- artifact 可校验。
- 生产部署文档能从空机器走通。

## 4. 任务优先级

第一批立刻做：

1. 修正 Makefile 与当前 CLI 不一致的问题。已完成。
2. 增加 `check`、`test-race`、`build-all` 等工程入口。已完成。
3. 增加 GitHub Actions CI。已完成。
4. 校准 Docker compose 示例。已完成基础版。
5. 为 client `-config` 做设计并实现。已完成。

第二批：

1. relay CONNECT 出口 ACL。基础完成，后续补集成测试和审计。
2. 本地集成测试 harness。基础完成。
3. 断线重连自动化测试。
4. release workflow 初版。已完成。

第三批：

1. CLI/root Dialer 核心逻辑收敛。
2. sing-box/Xray 接入层兼容性文档和库级兼容测试。
3. UDP 暴露路径完善。
4. profile_dir 真正按站点加载。
5. admin API 权限模型和审计。

## 5. 每阶段开发流程

每个阶段都按下面节奏推进：

1. 写下阶段目标和验收标准。
2. 开小步 PR/commit，不混入无关重构。
3. 每步都跑 `go test ./...`、`go vet ./...`、`staticcheck ./...`。
4. 涉及并发/网络时补回归测试。
5. 更新文档。
6. 提交、推送、打 tag 或更新 release notes。

## 6. 风险登记

| 风险 | 影响 | 处理策略 |
| --- | --- | --- |
| CLI client 与根包 Dialer 双实现漂移 | 修复只覆盖一边，线上行为不一致 | 阶段 4 抽 core，阶段 0/1 先补共享行为测试 |
| 三方项目误用 internal 包 | 升级时 break，无法作为稳定库 | 根包公开配置加载和文档，adapter 只依赖根包 |
| 失败路径可区分 | 协议核心目标失效 | 所有 auth/whitelist 改动必须审查 fallback 行为 |
| CONNECT 出口无限制 | 凭据泄漏后可被滥用 | 已加入基础 CONNECT ACL；生产配置开启 `connect_deny_private`，后续补集成测试和审计 |
| Docker/Makefile 文档漂移 | 新开发者无法复现 | 阶段 0 统一入口，CI 固化 |
| 真实网络测试不可复现 | 发布质量不可证明 | 阶段 3 建本地集成测试和可选远程测试 |
| profile/dilution 语义未完成 | 隐蔽性弱于设计 | 阶段 4/5 明确能力边界和后续实现 |

## 7. 当前下一步

下一步进入阶段 3 的自动化验证：

- 建本地集成测试 harness：relay + client + backend + SOCKS5 流量。
- 把 CONNECT ACL 纳入集成测试，覆盖公网允许、内网拒绝、deny CIDR 优先。
- 补断线重连测试：relay 退出、重启、client 新请求恢复。
- 增强 release workflow：SBOM、签名、CHANGELOG/release notes。
