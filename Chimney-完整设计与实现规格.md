# Chimney — 完整设计与实现规格 (v0.1)

> 一种**行为不可区分的会话寄生式隐匿传输系统**。
> 目标：让隐匿通信的可观测形态，与真实互联网行为不可区分。
>
> 本文是自包含的完整规格：Part I 定位与哲学，Part II 架构与高层流程，Part III 帧级实现，Part IV 能力边界，附录为标定流程与路线图。

---

# Part I — 协议定位与设计哲学

## 1. 协议定位

```
Behaviorally Indistinguishable Session-Parasitic Transport
（行为不可区分的会话寄生式隐匿传输）
```

Chimney 不试图「伪装成」一个协议，而是把隐匿通信**寄生**进真实互联网会话的可观测形态里。它的四根支柱：

```
真实入口  +  隐蔽认证  +  连续语义  +  行为拟真
```

## 2. 核心思想：从「会话寄生」到「行为寄生」的修正

设计早期有一个最激进的设想：**让隐匿数据真的流经一个真实第三方源站的会话**。这条路在密码学上是死的，必须先讲清楚为什么，因为它决定了 Chimney 的最终形态。

**死结一（TLS 1.3 两方密钥定理）**：握手完成后，会话密钥只由两个端点持有。一个不参与握手的中间节点，永远推不出会话密钥。

**死结二（注入不可能）**：TLS record 有序列号、Finished 有 MAC。任何第三方往一个两方会话里塞字节，对端的序列号/完整性校验立刻失败，会话直接崩。

**死结三（数据无处可去 —— 真正致命的一条）**：

> 在一个通往「不配合源站」的真实端到端会话上，**无法承载任何隐蔽载荷**——因为数据的唯一去处就是那个不配合的源站，而它收到不认识的数据只会报错/断开。

因此「真实源站参与握手 + 中间节点不终止 TLS + 认证后切隐匿模式」这三件事**不可能同时成立**。

**修正后的定位**（可行，且恰好踩在 ShadowTLS/REALITY 的空白上）：

> 把「寄生」从**会话层**（不可能）搬到**行为层**（可行）。
> 借真实第三方握手 → 认证 → **调包**（踢开真实站、由中继接管）→ 维持可观测形态的**语义连续与行为拟真**。

承载隐蔽数据的那一端，**必须是你控制的端点**（中继在调包后成为 TLS 端点）。这一点绕不开，但它同时一举消解了两个工程难题：

- **「中继嗅探不到加密流量」**：中继是调包后的端点，本就持有信道密钥，无需嗅探。
- **「TLS-in-TLS」**：隐蔽数据作为 H2 帧跑在中继控制的**那唯一一层**封装里，对内层 TLS 指纹做整形（见 Part III）。

## 3. 与 ShadowTLS / REALITY 的关系与差异化

地基（借握手 / 调包 / 认证 / 失败透传）与 ShadowTLS v3 同源，**应照抄，不创新**——那里每一处都是被主动探测攻击反复验证过的，改动只会重蹈 v1/v2 的覆辙。

Chimney 的**全部增量**，集中在调包**之后**：

| | ShadowTLS v3 | REALITY | **Chimney** |
|---|---|---|---|
| 真实握手 | ✅ 借 | ✅ 借 | ✅ 借 |
| 抗主动探测 | ✅ | ✅ | ✅ |
| 调包后承载 | ❌ 不透明代理流 | ❌ 不透明 VLESS 流 | ✅ **维持 record-profile 连续** |
| TLS-in-TLS 整形 | ❌ 零处理 | ❌ 零处理 | ✅ **主动整形** |
| 行为级 pacing | ❌ | ❌ | ✅ **按借用站画像** |

> ShadowTLS / REALITY 都解决了「握手像」，没解决「握手后还像」与 TLS-in-TLS。Chimney 的护城河 = **修复 Semantic Discontinuity + 整形内层指纹**。

## 4. 设计约束与安全原则

**约束 ①（身份）**：中继**无身份**，必须借用一个它**不拥有**的真实第三方站（不自建域名/不挂自己的证书）。

**四条安全原则**：

```
P1  No distinguishable failure path        没有可区分的失败路径
P2  No semantic discontinuity              没有协议语义中断
P3  No observable protocol transition       没有可观测的协议切换
P4  All unauthenticated traffic stays legit  所有未认证流量保持合法
```

---

# Part II — 架构与高层流程

## 5. 角色与威胁模型

```
Client ──────── Relay ──────── 借用站_i（真实第三方，仅供握手）
              （无身份）       ──────── 真实目标（用户实际想访问的站，tunnel 终点）
```

**观察者（审查者）位于 Client ↔ Relay 路径上。** 这决定了一切。它能观测的，与不能观测的：

| 威胁面 | 观察者位置 | 应对 |
|---|---|---|
| 1. 被动流量分析（record size/timing、TLS-in-TLS） | Client↔Relay 路径 | Part III §整形/§pacing（**主战场**） |
| 2. 主动探测（连 RelayIP 看像不像站_i） | 主动连接 | §8 auth 门 + §11 失败透传 |
| 3. IP 信誉 / SNI-IP 一致性（查 RelayIP 归属） | 查 RelayIP | §10 同云同区托管 |
| 4. 中继出站观测 | 审查边界**外** | 标准威胁模型下**基本非问题**（次要） |

> **关键校准**：调包后线路上是 `TLS_record_header || 密文`，密文用 Chimney 自有密钥加密，观察者**无法解密**。它**唯一**能拿到的是 **record 的长度 / 方向 / 时序 profile**。H2 帧、HTTP 语义、tunnel 内容一概不可见。
>
> **核心推论（贯穿全文）**：调包后的防御目标**不是**「让数据真的是 H2」，而是**让 record 的 size/direction/timing profile 匹配真实浏览器访问站_i 的 HTTPS profile**。内部跑真 H2 是**手段**（产生真实尺寸 + 干净多路复用），不是目的。把「我们说真 H2」误当成「我们骗过了 DPI」，是会做出一个自以为隐蔽、实则不隐蔽的工具的根本错误。

## 6. 整体数据流

```
阶段 1  Client 用 uTLS 发 ClientHello（SNI=站_i，指纹=站_i 对应真实浏览器）
阶段 2  Relay 纯 TCP 转发握手给站_i，站_i 完成真实 TLS 握手
阶段 3  握手后 Client 切到底层 TCP 的 ChimneyRecord，发送 H2 preface + SETTINGS
阶段 4  Relay 在首批 application_data 中扫描可用 K_sess 解开的 ChimneyRecord：
          找不到 → 透传给站_i，零区分点
          找到   → 进入 ChimneyRecord/H2 握手，但暂不切断站_i
阶段 5  Client 用 H2 DATA frame 发送 [key_hint(4)][auth_tag]
阶段 6  Relay 验证 auth_tag：
          通过 → 调包，切断站_i，进入 Chimney 模式（Part III）
          失败 → 透传给站_i，零区分点
阶段 7  Chimney 模式：H2 多路复用承载 tunnel，整形 + pacing
```

## 7. 真实入口：借第三方握手（为何无需密钥）

握手期间，Relay 扮演**透明 TCP 中继**：不解析、不应答，把 ClientHello/ServerHello/Certificate/Finished 的字节原样搬运。

> 借的是**握手报文的真实性**，不是密钥。观察者只看得到明文握手报文，而这些报文确实由站_i 亲手签出（真证书链、真 ServerHello）。密钥归谁，观察者看不见也不关心。

## 8. 隐蔽认证：auth_tag 密钥验证（非特征判别）

**真浏览器与代理客户端，在握手阶段必须长得一模一样。** 如果 Relay 能从握手区分它们，DPI 也能 → 全盘暴露。所以 Relay **不「判断」，而「验证一个密钥证明」**：

```
PSK = 用户共享口令（带外配置）
K_auth = HKDF(PSK, label="chimney-auth", info = ServerRandom)

当前实现中，客户端先发送可由 `K_sess` 解开的 ChimneyRecord，完成 H2 开场序列后，在一个 H2 DATA frame payload 中发送：
  [key_hint(4)] [auth_tag(TAG_LEN)]

当前实现的 tag 计算为：
  tag = HMAC(K_auth, ServerRandom || ClientRandom)[:TAG_LEN]

Relay：先用首批 application_data 中的 ChimneyRecord 验证自己人候选，再从 H2 DATA frame 中提取 key_hint 查表并独立计算同一 tag
  ├─ 命中 → 自己人（持有 PSK 的密码学证据）→ 调包
  └─ 未命中 / 非 tag → 真浏览器或探测者 → 透传
```

- `ServerRandom` 在 TLS 1.3 的 ServerHello 中**明文**，Relay 转发时已观测 → 可独立计算，**无需 TLS 会话密钥**。
- tag 是 HMAC 输出，对没有 PSK 的观察者与随机密文不可区分；只有持 PSK 才能预测它，且绑定 `ServerRandom` 与 `ClientRandom` → **每会话唯一、抗重放**。

> 这是 P1（No distinguishable failure path）与抗主动探测的实现：判别依据是**外部不可获得的密码学证据**，而非任何可观测特征。

## 9. 调包（swap）：密钥交接

真实握手的 TLS 会话密钥只在 Client↔站_i，Relay 没有。调包后：

- **TLS 会话密钥从此弃用**（它只服务了握手这场表演）。
- Client 与 Relay 改用双方都能独立导出的信道密钥：
  ```
  K_sess = HKDF(PSK, label="chimney-sess", info = ServerRandom || ClientRandom)
  ```
- Relay 只有在 H2 DATA auth frame 验证通过后才掐断到站_i 的后端连接。验证通过前，站_i 后端保持连接，以便失败分支继续透明透传。后续数据用 `K_sess` 的 AEAD 加密，封装成假 TLS application_data record（Part III §2.4）。

## 10. 回源 B：同云收敛白名单

**一处对早期论证的纠正**：曾用「中继出站收敛、像 CDN 边缘」来论证 B —— 机制错了。审查者在 Client↔Relay 路径上，**观测不到中继到真实目标的出站**（在审查边界外，威胁面 4）。

真正可查的是 **中继自身 IP 的信誉 / SNI-IP 一致性**（威胁面 3）：

```
审查者看到：Client → RelayIP，SNI = 站_i
审查者可查：站_i 的真实 IP（DNS 可解析）
潜在破绽：SNI 声称连站_i，但 RelayIP 不属于站_i、也不可能服务站_i
```

**B 成立的正确条件**：

> **中继必须与白名单内的站托管在同一朵云的同一区域**，使 RelayIP 落在该云该区的公开 IP 段内。云内 IP↔域名不透明、多对多、随时漂移，审查者**无法证明**「这个 AWS us-east-1 的 IP 不服务站_i」。当审查者主动连 RelayIP 时，Relay 转发握手给站_i 并返回站_i 的**真证书** → 「RelayIP 真的服务站_i」与「RelayIP 转发到站_i」无法区分。

**两层结构**：

```
intent 层（配置，随手维护）：
  whitelist: [站名列表]            ← 写错顶多那站用不了，不致命

enforce 层（强制执法，B 的命根子）：
  cloud_region_cidrs:
    provider/region              ← 云厂商官方 ip-ranges.json，定时刷新，不手写
  规则：无论 SNI 写什么，回源目的 IP 必须 ∈ 该区段，否则拒绝
```

**IP 漂移与守门**：站会扩容/迁移/套 CDN，其 IP 漂出区段时 B 会悄悄失守。两道防线：

- 机制 1（客户端，可选）：选站前 `dig` 校验站_i 当前 IP 仍在区段内，否则换站。
- 机制 2（中继，**必须**）：回源前校验「即将连接的目的 IP ∈ 区段」，否则拒绝。这是最后防线——无论客户端判断如何、站如何漂移，中继物理上只对区段内目的放行，**出站画像恒定**。

> 加站前用 `dig + ASN + 比对官方区段` 确认该站当前落在目标区段（这一步从「安全把关」降级为「确认这站能不能用」；安全已由 enforce 层接管）。

## 11. 失败 / 探测分支（P1：No distinguishable failure path）

```
收到 ClientHello（含明文 SNI）：
关卡 A（intent） SNI ∈ whitelist?
关卡 B（enforce）目的 IP ∈ 云区段 CIDR?
  ── 任一不过 → 按「真站对未知请求」处理（透传默认后端 / 或如真站拒绝）

A、B 均过 → 纯 TCP 转发握手给站_i
握手后看第一批 application_data：
  ├─ 找到可解密 ChimneyRecord → 完成 H2 开场，读取 H2 DATA auth frame
  │    ├─ auth_tag 命中 → 调包（Part III）
  │    └─ auth_tag 未命中 → 继续透传给站_i
  └─ 找不到 ChimneyRecord（真浏览器/探测者）→ 继续透传给站_i
        → 探测者拿到真站_i 的真实响应，逐字节一致，零区分点
```

> 失败分支**必须与「这台 IP 真的是站_i 后端」逐字节一致**：不返回特殊错误、不提前断连、不改变时序。

## 12. 完整时序图

```
1. Client ──uTLS ClientHello(SNI=站_i, 指纹=对应浏览器)──▶ Relay
2. Relay ──[关卡 A/B 通过]── 纯 TCP 转发 ──▶ 站_i
       站_i ──真实 TLS 握手(真证书/真 ServerHello)──▶ Client
       ── 观察者：去站_i 的无可挑剔真实 HTTPS；RelayIP 在站_i 同云区段，IP 信誉自洽 ──
3. Client ──握手后第一批 AppData：ChimneyRecord(H2 preface + SETTINGS)──▶ Relay
4. Relay 扫描 ChimneyRecord：
   ├─ 找不到 → 透传站_i，零区分点
   └─ 找到   → 完成 H2 SETTINGS/ACK 交换，暂不切断站_i
5. Client ──H2 DATA: [key_hint(4)][auth_tag]──▶ Relay
6. Relay 验证 auth_tag：
   ├─ 命中 → 【调包】掐断站_i 后端，用 K_sess 接管
   │         · tunnel 数据走 H2 DATA 帧
   │         · 前 ~10 帧整形，抹掉内层 TLS-in-TLS 指纹
   │         · 稳态按站_i 画像 pacing
   └─ 未命中 → 透传站_i，零区分点
```

---

# Part III — 帧级实现规格（调包之后）

## §1. 调包后的密码学状态与记录封装

### 1.1 密钥归属

真实握手由站_i 完成，TLS 会话密钥只在 Client↔站_i，**Relay 没有**。调包后双方用 `K_sess`（§9 派生，含双方 Random → 每会话唯一）。

### 1.2 假 TLS 记录封装（调包后每一条 record）

```
struct ChimneyRecord {
    uint8   type    = 0x17;     // application_data
    uint16  version = 0x0303;   // TLS1.2 legacy（与 TLS1.3 记录层一致）
    uint16  length;
    opaque  payload[length];    // = AEAD_seal(K_sess, nonce, inner_chunk)
}
// inner_chunk 解密后 = 一段 H2 帧字节流
// nonce：每方独立递增 seq 计数器，双方各维护一个
```

**Relay 读取**：剥 5 字节头 → `K_sess` + seq AEAD 解密 → 得 H2 帧 → 内部 H2 解析 → tunnel 到真实目标。

## §2. H2 承载（内部真 H2，给你三样东西）

内部跑真 H2 状态机，免费获得：(1) 真实记录尺寸（preface/SETTINGS/HEADERS/DATA 是协议天然产生）；(2) 干净多路复用（tunnel/padding/可选真实内容各占一 stream）；(3) 自洽流控（WINDOW_UPDATE 节奏真实）。

### 2.1 开场序列（当前实现）

```
方向   内容                                        典型明文大小
C→R   H2 preface(24B 固定) + SETTINGS              24 + (6×N+9)
R→C   SETTINGS                                     6×M+9
R→C   SETTINGS ACK                                 9
C→R   SETTINGS ACK                                 9
C→R   DATA(auth): [key_hint(4)][auth_tag]           9 + 4 + TAG_LEN
C→R   HEADERS(首请求) ; R→C  HEADERS+DATA(响应)     变长
```
preface = `PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n`（24 字节，内部真实生成）。

当前代码在 auth DATA 验证通过后才真正关闭站_i 后端连接。因此 H2 开场发生在“候选 Chimney 模式”内，swap 完成点是 auth DATA 通过之后。

### 2.2 SETTINGS 取值来源（**必须抓站_i 真值，别用库默认**）

库默认 SETTINGS 组合本身就是指纹（Go/nginx/envoy 一眼可辨）。抓站_i 真实响应：

| Setting | ID | 说明 |
|---|---|---|
| HEADER_TABLE_SIZE | 0x1 | 默认 4096 |
| ENABLE_PUSH | 0x2 | 默认 1 |
| MAX_CONCURRENT_STREAMS | 0x3 | **取站_i 真值** |
| INITIAL_WINDOW_SIZE | 0x4 | **取站_i 真值** |
| MAX_FRAME_SIZE | 0x5 | 默认 16384 |
| MAX_HEADER_LIST_SIZE | 0x6 | **取站_i 真值** |

抓取：`cmd/h2probe` / nghttp / pcap 解 SETTINGS 帧。**白名单每站存一份 SETTINGS 快照**，当前 relay 会在 `intent.yaml` 条目的 `settings_snapshot` 存在时按当前站_i 加载；缺失时退回内置默认值。

### 2.3 隐蔽数据 → DATA 帧 → record

```
tunnel 字节流 → H2 DATA 帧(隐蔽 stream_id，遵 MAX_FRAME_SIZE 与流控)
            → §3 整形(决定 record 尺寸/时序) → AEAD_seal → ChimneyRecord
```

## §3. TLS-in-TLS 指纹消除（核心护城河）

### 3.0 先讲实话

> tunnel 模式下，**用户浏览器对真实目标的内层 TLS 不可消除**（物理必然，REALITY 同样逃不掉）。能做的是抹掉它的尺寸/方向/时序指纹。这击败**当前的 size-sequence 分类器**（强于零处理的 REALITY/ShadowTLS），但**非信息论不可区分**。
>
> 为何 tunnel 模式而非 fetch 模式（中继终止内层 TLS、彻底消除）：fetch 模式需中继主动连**用户点名的任意目标**（非站_i）→ 出站发散，且要求中继看见全部明文、只支持 HTTP。tunnel 模式保端到端、支持任意 TCP，是 ① 下更一致的选择。

### 3.1 签名长什么样（要打掉的目标）

内层 TLS 1.3 握手在数据期开头 ~1 RTT 的 record 序列（内层尺寸）：

| 序 | 方向 | 内层消息 | 典型大小 |
|---|---|---|---|
| 1 | ↑ | 内层 ClientHello（uTLS Chrome） | ~500–700 B |
| 2 | ↓ | ServerHello | ~90–150 B |
| 3 | ↓ | EncryptedExtensions+**Certificate**+CertVerify+Finished | **~2.5–6 KB** |
| 4 | ↑ | 内层 Finished | ~50 B |

指纹 = `↑小(~600) → ↓大(~3-6K) → ↑小(~50)` 且 RTT 锁步。TLS1.3 record 开销 = 内层 +22B（5 头 +1 type +16 tag），naive tunnel 直接透传这串尺寸。

### 3.2 四类整形（对**前 ~10 条 record** 强制施加）

**a. 记录尺寸：分布匹配（不是固定尺寸）**
全等长 record 流本身是新指纹。让 record 长度序列**抽样自站_i 真实 profile 的长度分布**，把内层握手的特征长度重写成「一次站_i 页面加载」的长度序列。

**b. 大帧分片 + 小帧合并**
把内层 Certificate 那个 3-6KB 下行大块拆成多条（遵 MAX_FRAME_SIZE、长度服从站_i 分布）；小块合并/padding 进正常 record。消灭「大小大小」聚类。

**c. 方向交错（多路复用稀释）**
内层握手是单流锁步。用 H2 多路复用让上下行 record 交错（隐蔽 stream 上行 DATA 与 padding/可选真实 stream 下行 DATA 穿插），破坏锁步往返。

**d. 时序 pacing**
注入 pacing，使到达间隔匹配站_i 的多并发资源加载时序，而非单流握手 RTT 锁步。

**开销取舍**：仅作用于开头握手窗口，代价可控；稳态后整形强度下降。整形帧数 N、padding 目标分布做成可配参数。

## §4. 稳态拟真与 pacing

### 4.1 站_i profile 标定（一次性，每站一份）

```
1. 用真实浏览器(uTLS 对应款)访问站_i 典型路径，pcap 多次多页面抓包
2. 提取观测特征(只取看得见的)：record 长度分布 / 突发结构 / burst 间 gap / 上下行比
3. 拟合：ProfileModel{ size_dist, burst_size_dist, intra_burst_seq, gap_dist, dir_ratio }
4. 与 SETTINGS 快照一起存进白名单条目
```

当前实现状态：client CLI 和根包可以显式加载 `-profile` / `ProfilePath` JSON；relay 端的 `profile_dir` 字段尚未按站点加载 profile，启用 profiling 时使用 `profile.DefaultModel()`。

### 4.2 pacing 算法（稳态）

```
loop:
  burst_len ~ burst_size_dist
  repeat burst_len:
     target ~ size_dist；凑/截 tunnel|padding 到 target，封 record 发送
     sleep(intra_burst_pacing)
  gap ~ gap_dist；sleep(gap)        // think time
  按 dir_ratio 调度上下行
```
tunnel 不足用 padding stream 的 DATA 补足目标尺寸；过剩按窗口/MAX_FRAME_SIZE 自然拆分。

### 4.3 可选：真实内容稀释

> 注意：**不能在同一条调包后连接上请求站_i 真实资源**（调包已切断站_i 后端，对端是 Relay）。
> 正确做法：**Relay 侧并联**一条到站_i 的真实连接，把站_i 真实响应经隐蔽 stream 喂回客户端，使内部 H2 流含货真价实的站_i 内容。代价：Relay 增加到站_i 出站（站_i 是预期目标，可接受）+ 延迟。作为可配增强项，不进核心路径。

当前实现状态：已有的是“预录制内容块 dilution”。client/根包从 JSON 读取内容块，在 reserved dilution stream 上发送；relay 识别 reserved stream 后丢弃，以维持 record 形态。relay 并联真实站点实时取内容尚未实现。

## §5. 失败 / 探测分支记录级行为

同 Part II §11：关卡 A/B → 转发握手 → auth 命中调包 / 未命中透传站_i，逐字节一致。失败分支不返回特殊错误、不提前断连、不改时序。

## §6. 关键参数表

| 参数 | 取值来源 | 默认/建议 |
|---|---|---|
| PSK | 带外配置 | 高熵随机 |
| K_auth/K_sess | HKDF(PSK,…,ServerRandom[/ClientRandom]) | §8/§9 |
| TAG_LEN | 固定 | 8–16 B |
| AEAD | 固定 | ChaCha20-Poly1305 或 AES-128-GCM |
| 站_i SETTINGS 快照 | 抓站_i 真值 | 每站一份 |
| 站_i ProfileModel | pcap 标定 | 每站一份 |
| 整形帧数 N | 调参 | ~8–12 |
| padding 目标分布 | = 站_i size_dist | — |
| 云区段 CIDR | 云厂商官方 JSON，定时刷新 | 强制校验 |
| uTLS 指纹 | 与站_i 匹配的真实浏览器 | 必配 |

## §7. 实现里最容易错的 5 个点

1. **用库默认 SETTINGS/窗口** → 一眼认出底层库。抓站_i 真值。
2. **整形成全等长 record** → 全等长本身是指纹。要分布匹配。
3. **uTLS 指纹与 SNI 不一致** → SNI=站_i 却带非对应浏览器 ClientHello，先于一切暴露。
4. **失败分支有任何细微差异**（错误码/断连时机/时序）→ 违反 P1。
5. **以为「跑真 H2」=「骗过 DPI」** → DPI 看不见 H2，只看 record profile。真 H2 是手段。

---

# Part IV — 能力边界与诚实评估

- **TLS-in-TLS 整形**：击败当前 size-sequence 分类器，**强于 REALITY/ShadowTLS（零处理）**，但**非信息论不可区分**；fine-grained timing / 熵 / 高阶统计的检测者可能仍有统计边际。
- **同云同区托管**：击败 SNI-IP 一致性检查（云内 IP 不透明），但**云厂商配合审查方**或**精细 IP 情报**可能收窄空间。
- **抗主动探测**：auth 绑定 ServerRandom（防重放）+ 失败透传真站，强；但**运维层**（IP 复用被标记、流量体量异常、站漂移未及时剔除）往往是比协议更现实的暴露源。
- **真实增量**集中于：**调包后维持 record-profile 连续（修复 Semantic Discontinuity）+ TLS-in-TLS 主动整形 + 行为 pacing**。地基照抄 ShadowTLS v3，不创新。

> 一句话：Chimney 不提供「不可检测」的保证，它提供的是**把检测门槛抬到显著高于 REALITY/ShadowTLS**，且把暴露点从「协议形态」推向「运维与高阶统计」。

---

# 附录

## A. 术语表

| 术语 | 含义 |
|---|---|
| 调包 (swap) | auth 通过后，中继掐断到站_i 的后端、改用 K_sess 接管连接 |
| 借用站 站_i | 仅供握手的真实第三方站；调包后被踢出，不在数据路径 |
| Semantic Discontinuity | 「前面像 HTTPS、后面突然不像」的协议语义突变 |
| record profile | 观察者唯一可见的信号：record 的长度/方向/时序分布 |
| intent / enforce 层 | 白名单的意图层（配置站名）/ 执法层（云区段强制） |

## B. 标定清单（每个白名单站必须产出两份数据）

```
① SETTINGS 快照     —— curl --http2 -v / nghttp，存 6 个 SETTINGS 真值
② ProfileModel      —— pcap 真实浏览器访问，拟合 size/burst/gap/dir 分布
（缺这两份，§3 整形与 §4 pacing 没有对齐目标，只能瞎调）
```

## C. 实现路线图

```
阶段 1  地基跑通：借握手 + auth(K_auth) + 调包 + 失败透传站_i + B 双层(intent/enforce)
        —— 此时 ≈ 加固版 ShadowTLS v3，可用
阶段 2  调包后真实 H2 多路复用承载（§1–§2）+ 标定 SETTINGS/Profile
        —— 拿下连续语义，开始超越 REALITY
阶段 3  TLS-in-TLS 整形（§3）+ uTLS + 画像 pacing（§4）
        —— 拿下指纹压制 + 行为拟真，护城河成形
```

## D. 起手建议

进代码从 **§1 记录编解码 + §2 H2 开场序列**起手（骨架），跑通后再叠 §3/§4。两份标定数据（附录 B）与之并行准备。

---

*v0.1 — 自包含完整规格。后续修订聚焦：§3 整形参数实测调优、§4 ProfileModel 拟合方法、阶段 2 帧编解码参考实现。*
