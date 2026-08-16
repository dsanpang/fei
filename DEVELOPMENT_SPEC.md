# "蜚" (Fei) 红队 C2 框架 — 工程规范白皮书

**Version:** 3.1.0 (2026-08,修订版)

**Classification:** Internal Technical Standard

> 本文档是项目最初的开发白皮书的**修订版**,与仓库实际实现逐项对齐。
> 原版(2026-05)中已过时或从未落地的设计在本版中直接修正;未实现的部分
> 明确标注为路线图。**任何模块设计与本文冲突时,以代码和 README 的
> Known issues 为准,并回改本文。**

**Design Core:** 控制面微服务化(Tauri + Go),数据面物理隔离(Go Gateway
+ NATS),端点极小化常驻(x64 ASM 内核)与子进程沙箱执行(Rust no_std)。

**使用约束:** 本框架仅限书面授权下的红队作业、对抗演练与防御研究,见
`DISCLAIMER.md`。

---

## 一、 系统分层与职责(与代码对齐)

```
+-------------------------------------------------------------+
| 1. 操作控制端 control-tauri (Tauri 1.x + Vue 3)              |
|    已实现: agent 列表/详情、命令下发、目录浏览、系统信息、    |
|             任务状态轮询(get_task)、agent 生成表单、         |
|             凭证 OS Keyring 托管                             |
|    路线图: 拓扑图、多用户协同、插件打包                       |
+------------------------------+------------------------------+
                               | gRPC (proto/fei_control.proto, 11 RPC)
                               v
+-------------------------------------------------------------+
| 2. 中枢控制面 control-plane/go_core (Go + NATS)              |
|    已实现: 会话/任务状态机、结果按 task_id 关联回填、         |
|             JSON 快照持久化、命令到沙箱帧的映射、             |
|             ListDirectory/Upload/Download 带结果等待          |
+------------------------------+------------------------------+
                               | NATS (fei.event.* / fei.cmd.*)
                               v
+-------------------------------------------------------------+
| 3. 前线接入节点 gateway/go_gateway (Go)                       |
|    已实现: TLS 1.2/1.3 终结(证书已正确加载)、                |
|             -mtls-mode require|request|none、-dev 明文模式、  |
|             帧编解码+AEAD、每会话防重放(seq 严格递增)、      |
|             TxSeq/RxSeq 分离、NATS 桥接                      |
+------------------------------+------------------------------+
                               | FEI v3 二进制协议(全帧密封)
                               v
+-------------------------------------------------------------+
| 4. 植入端 agents/x64_asm (NASM) + rust_no_std_sandbox        |
|    已实现: PEB 动态解析、Schannel TLS、ChaCha20-Poly1305     |
|             全帧密封、随机 padding、连接监督重连、            |
|             沙箱管道投递、管道读 10s 超时、退出前密钥擦除      |
|    路线图: TLS 模式收包流状态(见 Known issues)               |
+-------------------------------------------------------------+
```

NATS 总线(`gateway/nats_bus`)是**审计消费者**而非内嵌 server,部署时需
外部 `nats-server`。

---

## 二、 FEI v3 网络协议(实现即规范)

36 字节包头,除 timestamp 外全部小端:

| 偏移 | 宽度 | 字段 | 说明 |
|------|------|------|------|
| 0x00 | 4 | magic | `0x46454900` ("FEI\0") |
| 0x04 | 2 | proto_ver | `0x0300` |
| 0x06 | 2 | type | 0x01 心跳 / 0x02 plugin_load / 0x03 exec_return / 0x04 exception / 0x05 destroy |
| 0x08 | 4 | seq | 单调递增,参与 nonce 派生 |
| 0x0C | 4 | length | 解密后载荷长度 |
| 0x10 | 2 | padding_len | 0..128 随机尾部垃圾长度 |
| 0x12 | 8 | agent_id | 设备指纹 |
| 0x1A | 8 | timestamp | 大端毫秒时间戳 |
| 0x22 | 2 | (保留) | 恒为 0,两实现一致,作为 AAD 一部分 |

**内层 AEAD(与 RFC 8439 / Go x/crypto 逐字节互通,由
`agents/x64_asm/test.asm` + `tools/aeadtest` 六项测试锁定):**

- ChaCha20-Poly1305,key = 32 字节 PSK
- nonce = `le32(seq) || agent_id`(12 字节,确定性派生,两端一致)
- AAD = 完整 36 字节包头(含 2 保留字节)
- MAC 数据 = `pad0(header) || pad0(ciphertext) || le64(36) || le64(len)`
  (RFC 8439 §2.8 布局;**没有**明文心跳快捷路径——v3.1 起每帧含 tag)
- 密文后跟 padding_len 字节随机垃圾(ASM 端用 RDTSC,流量整形用途)

**防重放:** 网关每会话维护 RxSeq,`seq <= RxSeq` 的帧丢弃并记日志。
网关自身下发(ACK/命令)使用独立 TxSeq,不污染接收侧判定。

**已知限制:** 单一全局 PSK,无 per-agent 派生与轮换;nonce 确定性派生
意味着 seq 回绕即密钥流重用——升级 PSK 体系时必须同步改两端。

---

## 三、 植入端开发规范

### 主内核(x64 NASM,目标 <15KB,实测 12-13KB)

- 纯 NASM,`/NODEFAULTLIB`,自建 kernel32 导入库(`kernel32.def` +
  `lib.exe /def:` 生成,随仓库分发 def 源)。
- 函数解析:先 `LoadLibraryA("ws2_32.dll")` 再 PEB 遍历
  (InLoadOrderModuleList,`gs:[0x60]` → Ldr+0x10;BaseDllName 比较
  按字符数,DllBase 在 +0x30)。
- SSPI 调用注意:`InitializeSecurityContextA` 栈参数从 +32 起每 8 字节
  一槽;`DecryptMessage(phContext, pMessage, seq, pfQOP)` 的参数顺序
  **与 EncryptMessage 不同**(pMessage 是第 2 参)——这是历史踩坑点,
  改动前先看 `entry.asm` 内注释。
- 栈对齐:任何含 API 调用的函数,调用瞬间 rsp 必须模 16 为 0。植入端
  历史上四个崩溃(Schannel、EncryptMessage、PeekNamedPipe 路径)全部
  源于对齐错误——push 数量 + sub 总量必须凑成 16 的倍数。
- 指针运算:对 resd 变量做 `add reg, [dword变量]` 会把相邻 4 字节当
  高位并入指针——一律先 `mov eax, [var]` 再 `add reg, rax`。
- 帧接收:staging 采用**追加式**填充 + 帧边界压缩 + 半帧回滚
  (`recv_saved_off`),半包到达时回滚 offset 重试而不是错位。
- 连接监督:连续 3 次发送失败 → 拆链(cleanup_tls + cleanup_stream)→
  冷却 3 秒重连。PSK 不随会话销毁擦除(监督器还要用),最终由进程退出
  回收。
- 构建模式:默认 Schannel TLS;`-D PLAIN_TCP` 编译明文传输版(配合
  网关 `-dev`,内层 AEAD 仍然全帧密封)。**当前发布默认走 PLAIN_TCP**,
  TLS 模式收包流状态待修(见 Known issues)。

### 执行沙箱(Rust no_std,~11KB exe)

- **禁止裸 syscall 号**(v3.0 的硬编码号跨版本即碎,且内联汇编写栈参数
  与 Rust prologue 相互破坏)。一律通过 PEB 解析 ntdll 导出调用:
  `NtReadFile/NtWriteFile/NtClose/NtQuerySystemInformation/NtOpenFile/
  NtCreateFile/NtQueryDirectoryFile/NtTerminateProcess`。
- 同步文件句柄的 DesiredAccess 必须含 `SYNCHRONIZE`
  (0x00100000),否则 NtOpenFile 直接拒。
- 目录枚举:`ReturnSingleEntry=1` 逐条循环,终止状态是
  **STATUS_NO_MORE_FILES (0x80000006)** ——不是 NO_MORE_ENTRIES
  (0x8000001A),两者容易搞混(本项目真实踩坑)。
- 管道协议(与主内核对齐):
  - 请求 `[cmd u8][len u32 LE][payload]`
  - 响应 `[resp_len u32 LE][resp bytes]`(单次写,JSON)
  - cmd: 0x01 sysinfo / 0x02 process_list / 0x03 dir_list /
    0x04 file_read / 0x05 file_write / 0x06 execute
- `execute`:PEB 解析 kernel32!CreateProcessA,stdout 管道捕获,
  **30 秒上限后 TerminateProcess**,输出捕获上限 64KB。
- panic 处理器**禁止 `loop {}`**(历史上把 CPU 打到 100%):panic 时
  向管道写 `[[PANIC]] line:N` 标记后走三级退出链
  (NtTerminateProcess → ExitProcess → ud2)。
- 堆:静态 4MB bump allocator(process_list 的重试缓冲需要 ~2MB,
  1MB 必然耗尽——真实事故)。
- 验证:`tools/sandboxtest` 七项直连测试 + EOF 干净退出,提交前必须全绿。

---

## 四、 控制面与网关规范

- 网关 TLS:MinVersion TLS1.2(Win10 Schannel 客户端上限)/ Max 1.3;
  服务器证书**必须**真实加载进 tls.Config(历史致命 bug:`-cert` 参数
  定义了却从未使用,生产模式握手必败)。
- `fei.cmd.<agentID>` 回调**不得**在持有 session.mu 的状态下再调用会
  内部加锁同一互斥锁的处理函数(Go mutex 不可重入——本项目曾因此
  死锁全部命令投递而不报任何错)。
- go_core 命令映射:语义命令名 → 沙箱帧,经 plugin_load(0x02)通道;
  destroy(0x05)除外。ListDirectory/Upload/Download 带 5-8s 结果等待,
  超时返回 queued 语义。

---

## 五、 编译流水线(compiler_worker)规范

- `-emit-pe`(默认):自研 COFF→PE64 链接器(`pelinker.go`)输出独立
  exe。关键实现约束(全部真实踩坑):
  - COFF 重定位项步长 **10 字节**(VA+Index+Type 紧密打包)
  - PE32+ 栈/堆四字段是 **8 字节**
  - IMAGE_IMPORT_DESCRIPTOR 是 **20 字节** 结构(Name@+12,
    FirstThunk@+16),名字符串放 rdata 尾部、+12 处放 RVA
  - PE 头一律**偏移寻址写入**,不按顺序 append(顺序法错过一次 16 字节)
- 混淆变换的正确性纪律:
  - XOR 常数拆分必须生成 `c = orig^a^b` 且**发射前自校验**
    `(c^a)^b == orig`(旧实现直接静默改错常数,把 C2 地址改成了随机
    外网 IP)
  - NASM 局部标签(`.` 开头)不得重命名(跨函数撞名)
  - 控制流平坦化默认关闭(`-flatten`),其局部标签 dispatcher 无法
    通过多函数汇编
- **二进制多态**:仅靠源码级改写(等长标签、XOR 拆分)会被 NASM 折叠
  回逐字节相同的机器码。真正的哈希差异来自:变长标签名 + 指令间随机
  NOP 插入。每次构建的产物必须通过活体命令电池验证(已验证混淆 PE
  心跳 + sysinfo 回传)。

---

## 六、 交付前验证清单(提交门禁)

1. `tools/aeadtest` 生成向量 → `test.asm` 六项全绿
2. `tools/sandboxtest` 七项全绿 + EOF 干净退出
3. `gateway/go_gateway` `go test` 全过
4. 活体栈(nats + control_plane + gateway -dev + agent):
   心跳 30s 稳定、sysinfo/process_list/dir_list/shell 回传、
   任务状态 completed
5. compiler_worker 连续三次构建 → 三个不同 SHA256,且最新构建过活体电池

---

## 七、 路线图(未实现,禁止在文档中当成已有能力宣传)

- 植入端 TLS 模式收包流状态(DecryptMessage 参数已修,流状态待查)
- PSK 体系升级(per-agent 派生 / 轮换)
- 模板库 + 容器化 nasm 的全自动生成服务
- 控制台拓扑图、多用户协同、插件加密打包
- 分块文件传输(当前单发 ≤7KB)
