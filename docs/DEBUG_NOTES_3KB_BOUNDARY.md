# 调试笔记:agent ~3KB 命令帧边界(已解决)

> 状态:**已修复**(2026-08-17)。原来记为"~3KB 边界"的 bug 实际上是
> 五个互相叠加的独立缺陷,任何一个都足以让大帧/大响应失败或让 agent
> 静默失联。本文保留完整根因与排查方法,作为汇编层管道/流处理的坑册。

## 最终验证(全部通过)

| 项目 | 结果 |
|---|---|
| file_write 500–16000 hex(真实写盘) | 全部秒回 `{"bytes_written":N}` |
| process_list(~10KB 响应,多块管道回传) | 完整 exec_return |
| 超长帧(>16KB)拒收 → 后续命令 | 立即恢复,不再静默丢命令 |
| 100KB 分块上传 | 3.0s,md5 与源一致(块 900B→7000B) |
| 4KB 文件下载 | md5 一致 |
| 100KB 文件读(超预算响应) | 秒拒 `sbx-resp-too-big`,管道排空,后续命令正常 |
| 空闲后首条命令延迟 | ~0.2s(原平均 ~15s,最坏 30s) |
| crypto 互操作 / 沙箱直连 | 6/6、7/7 不变 |

## 五个根因

1. **`sandbox_send` 循环内不重载 rcx(真正的"3KB 边界")**。
   WriteFile 句柄放在 rcx 里循环外加载一次;rcx 是 Win64 易失寄存器,
   第一块(≤4096B)写完后被破坏,第二块 WriteFile 拿垃圾句柄立刻失败。
   所以一切 >4096 字节的 payload 必挂。对照 `sandbox_recv_exact`:它在
   每轮 poll 里重载 rcx,唯独 send 漏了。**教训:跨 call 复用的参数放
   易失寄存器 = 必炸;每轮迭代重载。**

2. **超长命令帧造成 TCP 流投毒**。payload>MAX_AGENT_PAYLOAD(16KB)时
   `.rc_nodata` 把暂存偏移回滚到帧头之前——但帧体还在 socket 里,
   解析器永远卡在同一个超长帧头,之后**所有**命令静默丢弃(心跳照常,
   完全无法察觉)。修复:拒收时按 header 声明长度消费掉整个帧体再继续,
   并回发 `gateway-frame-too-big` 异常。

3. **SO_RCVTIMEO 的 optval 放进了 r9 的 home slot**。为了让空闲 recv
   停泊内核、命令即到即醒,把非阻塞轮询改成 `setsockopt(SO_RCVTIMEO)`;
   optval 暂存在 `[rsp+24]`——这正是被调函数序言溢写 r9 的参数 home
   slot,ws2_32!setsockopt 先把指针写进去再解引用,选项值变成垃圾→
   超时为 0→recv 无限阻塞→心跳全停。C 编译器自动把局部变量放参数区
   之外所以同样的调用没事;Python ctypes 测试也过,唯独手写 ASM 炸。
   **教训:任何 API 的 by-pointer 出参/入参缓冲不要放在调用帧的
   [rsp+0..31] home 区;放 .data/.bss。** 复现器:`agents/x64_asm/testsock.asm`。

4. **沙箱 `write_all` 忽略 NtWriteFile 短写**。管道写超过缓冲区(≈64KB)
   时 NtWriteFile 是短写:状态成功但 `iosb.information` < 请求长度。
   原实现只查状态不查 information,大响应(如 100KB 文件的 hex 读回)
   只写了一截就"成功"。修复:按 information 循环推进。

5. **拒收超预算响应后不排空管道**。agent 读到 4 字节前缀 >16KB 直接
   报 `sbx-resp-too-big`,但声明的响应字节还在管道里;下一条命令的
   "长度前缀"读到的是残留 hex 字符→所有后续命令永远超预算。修复:
   拒收时按声明长度从管道读弃(4KB/块),配合根因 4 的修复彻底闭环。

## go_core 侧配套修复

- 下载/内联结果没有解开 NATS JSON 传输给 `[]byte` 加的 base64 层
  (`json.Marshal` 把 []byte 编码为 base64 字符串)→ 加 `decodeTaskResult`
  (响应是 `{` 开头的 JSON,永不误伤)。
- 异常帧到达时把最近的 sent 任务标为 failed(原来只能等 60s 超时)。
- >16KB payload 在 SendCommand 入口预拒,带明确错误,不再发必死帧。
- UploadFile 分块 900B(绕过旧 bug 的权宜值)→ 7000B。

## 排查方法存档(下次少走弯路)

1. **先让错误会说话**:五条异常消息(`sbx-send-fail` 等)各不相同长度,
   网关日志的 exception len 直接指出失败阶段。同长度消息=盲查。
2. **最小复现脱离全栈**:piperepro(Go)按 agent 的分块写法直打沙箱,
   几分钟排除一半假设;testsock(纯 NASM)隔离出 home-slot 问题。
3. **进程内存取证**:64 位 Python + ReadProcessMemory 读运行中 agent 的
   .data 指针槽,和 `GetProcAddress` 实地址对拍,一行确认解析正确
   (注意 ASLR:先枚举模块拿真实基址)。
4. **"无异常也无响应"= 卡在带内阻塞**(recv/WriteFile),不是丢包;
   心跳节奏是否被打乱是判断主循环死活的第一信号。
5. 帧体消费与暂存回滚必须成对:要么全消费,要么确定回滚点安全,
   任何"读一半就放弃"的路径都是投毒点(TCP 流和管道同理)。

## 复现/验证环境

```
nats-server -p 4222
bin/control_plane.exe -nats nats://127.0.0.1:4222
bin/gateway.exe -listen 127.0.0.1:4433 -dev -nats nats://127.0.0.1:4222
# agent: entry.asm 注入 PSK 后 -DPLAIN_TCP 构建(单进程,沙箱同目录)
# 探针:tools/cmdprobe(-sweep / -upload / -download)
# 沙箱直连:tools/sandboxtest、tools/piperepro(READ= 环境变量测 file_read)
```
