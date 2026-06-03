# Windows TCP Write Corruption 问题分析与修复

## 现象

Windows 客户端与远程 Linux relay (103.135.147.226:8443) 进行高吞吐测试时，
relay 端反复出现 `bad record MAC` 错误，表明 AEAD 解密失败 ——
密文在传输过程中被损坏。

## 诊断过程

### 1. SHA256 交叉比对（决定性证据）

在客户端 `EncodeRecord` 时计算 `sha256(record)`，通过 `RecordTraceHook` 输出；
relay 端在 decode 失败时同样计算 `sha256(receivedBytes)`。

**结果**：每次 MAC 错误，两端的 SHA256 都不匹配。确认密文在客户端发送后、
relay 接收前发生了变化。

### 2. 排除法

| 假设 | 结论 |
|------|------|
| AEAD nonce 不匹配 | ❌ 排除 — 同一连接前 N-1 个 record 正常 |
| Buffer pool 竞态 | ❌ 排除 — `DataFrame()` 在 `WriteRecord` 前复制数据 |
| Nagle 算法 | ❌ 排除 — `TCP_NODELAY` 已设置 |
| TLS 层干扰 | ❌ 排除 — 连接已 swap 为原始 TCP |
| Go 并发写 socket | ❌ 排除 — `WriteRecord` 持有 mutex |
| Linux 端问题 | ❌ 排除 — Linux→Linux 700 Mbps / 0 错误 |

### 3. 定位：Windows TCP 写入损坏

核心证据链：
- Linux→Linux 测试：0 错误，排除 relay 端问题
- 减小 `maxWriteChunk` 错误率下降但不归零，证明与写入大小和频率相关
- SHA256 在发送前就已计算，证明损坏发生在 `conn.Write()` 之后

### 4. maxWriteChunk 分片方案测试（commit 172ba2a）

`record_delay_windows.go` 将 record 拆分为 ≤8192 字节的 chunk 写入，
每个 chunk 之间有 10μs 延迟。

| maxWriteChunk | writeDelay | MAC 错误率 | 首次错误 seq |
|---------------|------------|-----------|-------------|
| 0（不分片）     | 无         | ~20%      | 3~6 |
| 8192          | 10μs       | ~2.5%     | 39~53 |
| 8192          | 500μs      | ~2.5%     | 41~43 |
| 4096          | 10μs       | ~1.6%     | 62 |

关键发现：方案是为 **loopback** 设计的（"Windows TCP loopback driver corrupts
the second half of writes larger than 8192 bytes"），但远程连接同样受影响，
且错误率虽然下降但始终无法归零。

### 5. 根因假设

分片方案无法完全消除问题，因为多个 goroutine 通过同一个 socket 发送时，
record A 的最后一个 chunk 和 record B 的第一个 chunk 之间没有 barrier。
Windows TCP 栈在高吞吐场景下可能合并或重排这些连续的小写入。

## 最终方案

**将 `MaxFrameSizeActual` 从 16384 降到 4096。**

```
文件: internal/h2engine/h2engine.go:149
修改: MaxFrameSizeActual: 16384 → 4096
```

### 原理

每个 record 的大小 = 5 (TLS header) + 9 (H2 frame header) + payload + 16 (GCM tag)
= 30 + payload

- 当 payload = 4096 时，record = 4126 字节，**一次 `Write()` 完成**
- 不需要分片，不会触发 Windows TCP 的写入损坏问题
- Mutex 保证每个 record 原子写入

### 协议兼容性

HTTP/2 的 `SETTINGS_MAX_FRAME_SIZE` 通告的是接收能力，不是发送能力。
减小 `MaxFrameSizeActual`（客户端实际发送的帧大小）完全符合 RFC 7540，
对端无需任何修改。

## 验证结果

Windows 客户端 → 远程 Linux relay (103.135.147.226:8443)

| 指标 | 修复前 | 修复后 |
|------|--------|--------|
| MAC 错误 | ~2.5% (seq 53, 62) | **0** |
| 上传吞吐 | ~8 Mbps | **46 Mbps** |
| 测试条件 | 2UL, 5s | 4UL, 15s |

## 附带影响

帧大小降低 4 倍 → 帧开销增加。每个 record 固定开销 30 字节：
- 16384: 开销比例 30/16414 = 0.18%
- 4096: 开销比例 30/4126 = 0.73%

影响可忽略。如需优化，可在 4096~8162 之间二分查找最大安全值。
