# 调试笔记:agent ~3KB 命令帧边界(未修复,接手必读)

> 状态:未修复。本文记录已排除的假设、已确认的事实、误导过排查的坑,
> 以及建议的修复路径。接手修这个 bug 前,先读完本文可以少走弯路。

## 现象(干净环境下的可靠数据)

单 agent、PLAIN_TCP(`gateway -dev`)、单命令经
`SendCommand(file_write, [path, hex])`:

| payload 尺寸 | hex 字符数 | 结果 |
|---|---|---|
| ≤ ~2036 B | ≤ 2000 | 稳定完成(2/20/100/500/1000/2000 全过) |
| ≥ ~4036 B | ≥ 4000 | 稳定失败(sandbox 管道异常帧) |

- 失败时 agent 回传 exception 帧(`len=20`),**没有 exec_return**
- 沙箱直连同尺寸(7KB payload 直写)**通过** → 问题不在沙箱,
  在 `entry.asm` 的 agent↔sandbox 管道转发代码

## 已排除的假设

1. **TLS 流状态** — PLAIN 模式同样失败,与 TLS 无关
2. **沙箱堆耗尽** — 已修(命令间堆重置),20×process_list 压测全绿,
   且失败尺寸远小于堆容量
3. **网络接收半帧** — mid-frame 轮询修复把可靠边界从 ~500 推到 ~2KB,
   但 4KB 仍失败,说明还有第二层问题
4. **go_core 重试累积 payload** — 日志中的"神秘 10035/14035 字节载荷"
   曾被怀疑为重试拼接 bug,实际是**我自己的探针笔误**:
   `strings.Repeat("41", n)` 生成 2n 个字符,测的尺寸是预期的两倍

## 已确认的坑(排查时踩过,别再踩)

1. **两条错误消息同长**:`sandbox_send_failed` 与 `sandbox_recv_failed`
   都是 19 字符,exception 帧 `len=20` 无法区分方向。
   **修复前先把消息改成不同长度**(如 `sb-send-fail` / `sb-recv-fail`)
2. **多 agent 污染**:测试时若有残留 agent 进程用同一 agent_id 心跳,
   会互相顶掉网关会话,命令静默丢失,症状与随机 bug 一致。
   每轮测试前 `tasklist | grep agent` 确认只有一个
3. **构建前先杀进程**:lld-link 对正在运行的 exe 输出会报
   LNK1104/LNK1181,失败后旧二进制继续跑,容易误判"修复无效"

## 建议修复路径

1. 改错误消息长度(区分 send/recv),重建,单命令复现 4000-hex 用例
2. 若是 send 失败:聚焦 `sandbox_send` 的 `WriteFile`——匿名管道默认
   ~4KB 缓冲,payload ≥4KB 时分块写(4096/块)与沙箱端
   `NtReadFile` 循环读的时序;阻塞写在 agent 单线程主循环里与
   10s 超时的竞争
3. 若是 recv 失败:聚焦 `sandbox_recv_exact` 的 PeekNamedPipe 轮询,
   特别是响应帧跨管道缓冲边界的情况
4. 每轮验证:尺寸探针(注意 Repeat 语义!)→ `/api/tasks` 解码结果,
   而不是只看 "Command queued"

## 复现环境(已验证可重现)

```
nats-server -p 4222
bin/control_plane.exe -nats nats://127.0.0.1:4222
bin/gateway.exe -listen 127.0.0.1:4433 -dev -nats nats://127.0.0.1:4222
# agent: entry.asm 注入 PSK 后 -DPLAIN_TCP 构建,心跳 2s,单进程
# 探针:tools/ 下 Go 客户端 SendCommand file_write,参数 [path, hex]
```
