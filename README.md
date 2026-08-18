# 蜚 (Fei) — Red Team C2 Framework

**Version:** 3.0.0 (open-source release)

Fei is a compact, multi-layer command-and-control framework for **authorized
red team engagements and security research**: a pure x64 NASM implant with a
ChaCha20-Poly1305 inner protocol, a Go gateway and control plane connected by
NATS, and a Tauri (Rust + Vue 3) operator UI.

> **Authorized use only.** This toolset is published for penetration testers
> operating under written authorization, for detection engineering, and for
> defensive research. Attacking systems you are not authorized to test is
> illegal in most jurisdictions. See `DISCLAIMER.md`.

## Architecture

```
+-------------------------------------------------------------+
| 1. Operator console (Tauri + Vue 3)                          |
|    agent list, file browser, command console, generator      |
+------------------------------+------------------------------+
                               | gRPC (Protobuf)
                               v
+-------------------------------------------------------------+
| 2. Control plane (Go)                                        |
|    sessions, task queue/state machine, JSON snapshot store   |
+------------------------------+------------------------------+
                               | NATS
                               v
+-------------------------------------------------------------+
| 3. Gateway (Go)                                              |
|    TLS termination, frame codec, per-agent event/command     |
+------------------------------+------------------------------+
                               | FEI v3 binary protocol
                               v
+-------------------------------------------------------------+
| 4. Implant (x64 NASM kernel + Rust no_std sandbox)           |
|    heartbeat loop, AEAD framing, sandboxed task execution    |
+-------------------------------------------------------------+
```

## FEI v3 wire protocol

36-byte header, little-endian fields unless noted:

| Offset | Size | Field | Notes |
|--------|------|-------|-------|
| 0x00 | 4 | magic | `0x46454900` ("FEI\0") |
| 0x04 | 2 | proto_ver | `0x0300` |
| 0x06 | 2 | type | 0x01 heartbeat, 0x02 plugin_load, 0x03 exec_return, 0x04 exception, 0x05 destroy |
| 0x08 | 4 | seq | per-agent sequence, feeds the AEAD nonce |
| 0x0C | 4 | length | decrypted payload length |
| 0x10 | 2 | padding_len | 0..128 bytes of random trailing garbage |
| 0x12 | 8 | agent_id | device fingerprint |
| 0x1A | 8 | timestamp | big-endian unix milliseconds |

* **Inner layer:** ChaCha20-Poly1305 with the full 36-byte header as AAD,
  nonce = `le32(seq) || agent_id`. Interop between the NASM implementation and
  Go's `x/crypto` is covered by `agents/x64_asm/test.asm` against vectors from
  `tools/aeadtest` (RFC 8439 vectors plus cross-implementation seal/open).
* **Heartbeat fast path:** heartbeat frames with `length == 0 && padding == 0`
  are sent as a bare header (matching the gateway's read path).
* **Transport:** TLS 1.2/1.3 (mTLS with client certificates supported for
  Go-based components), or `-dev` plain TCP where the inner AEAD still applies.
  The NASM implant is currently built in plain-TCP mode; see Known issues.

## Repository layout

| Path | Description |
|------|-------------|
| `agents/x64_asm/` | NASM implant: PEB walking, Schannel TLS, AEAD framing, sandbox supervisor (~12 KB exe) |
| `agents/rust_no_std_sandbox/` | no_std sandbox: NT-native sysinfo/process/dir/file ops, file write, command execution via PEB-resolved kernel32 |
| `agents/win_wdm_driver/` | Windows WDM kernel endpoint (VS2010 + WDK7600): PID spoof, nsiproxy TCP hiding (x64/x86/WoW64), MiniFilter path hiding, registry hiding, shutdown write-back, DriverObject clone spoof |
| `agents/linux_lkm/` | Linux LKM endpoint (2.6–6.x): syscall-table + ftrace dual-channel hooks, prefix/file/process/module/port hiding, root elevation, reboot write-back persistence |
| `azure-wdm-agent-prompt.md`, `crimson-kmod-agent-prompt.md` | implementation specs for the two kernel endpoints above |
| `gateway/go_gateway/` | TLS listener, frame codec, NATS bridge, per-agent sessions |
| `gateway/nats_bus/` | NATS audit/monitor consumer for `fei.event.>` |
| `control-plane/go_core/` | gRPC API, task state machine, NATS event ingestion, snapshot persistence |
| `control-plane/compiler_worker/` | NASM obfuscation pipeline: label renaming, constant rewriting, control-flow flattening |
| `control-tauri/` | Operator console (Rust core + Vue 3 frontend) |
| `tools/certgen/` | CA / mTLS certificate and PSK generator |
| `tools/aeadtest/` | AEAD reference-vector generator for the implant test harness |
| `tools/inject_psk/` | PSK/agent-id injector for implant builds |
| `proto/fei_control.proto` | gRPC contract |

## Building

Requirements: Go 1.21+, Rust (MSVC toolchain), Node.js, NASM, an MSVC linker
(or lld-link) and a NATS server.

```
:: Go services + tools
build.bat

:: Rust no_std sandbox (sandbox.exe)
cd agents\rust_no_std_sandbox
cargo build --release --target x86_64-pc-windows-msvc

:: NASM implant (see the header of the script for linker paths)
cd agents\x64_asm
build_agent.bat

:: Implant crypto test harness (verify against Go vectors first):
cd tools\aeadtest && go run . ..\..\agents\x64_asm\open_vectors.inc
cd agents\x64_asm
nasm -f win64 test.asm -o test.obj && link ... test.obj kernel32.lib
test.exe
```

Gateway options:

```
gateway.exe -listen :443 [-mtls-mode require|request|none] [-dev]
```

`-dev` selects plain TCP (inner AEAD still enforced); `-mtls-mode none`
accepts clients without certificates (server-auth TLS only).

## Running an engagement lab

```
nats-server -p 4222
bin\control_plane.exe -nats nats://127.0.0.1:4222
bin\gateway.exe -listen 127.0.0.1:4433 -dev -nats nats://127.0.0.1:4222
:: implant (inject PSK + agent id, set gateway port first):
agents\x64_asm\agent.exe
```

Sandbox commands (via the gRPC `SendCommand` or the console):

| command | payload | sandbox op |
|---------|---------|------------|
| `sysinfo` | — | OS version, working-set summary |
| `process_list` | — | NtQuerySystemInformation walk |
| `dir_list` | path | NtQueryDirectoryFile listing |
| `file_read` | path | hex content (≤64 KB) |
| `file_write` | path, hex | NtCreateFile overwrite (≤ ~7 KB single shot) |
| `shell` | command line | CreateProcessA with captured stdout |
| `destroy` | — | terminate implant |

## Security properties

* Inner AEAD over every payload; header bound as AAD (tamper detection
  covered by gateway unit tests).
* Random 0..128-byte trailing padding on every sealed frame.
* Implant wipes PSK, cipher state and buffers on exit; task execution is
  isolated in a child process with piped stdio.
* Operator credentials/certificates stored via the OS keyring
  (`control-tauri` credential store).
* `compiler_worker` produces structurally distinct implant builds
  (randomized labels/constants, control-flow flattening) for blue-team
  detection engineering.

## Known issues (honest status)

This is an early open-source release; the following are open:

1. **Schannel TLS receive path**: the implant's TLS handshake and
   `EncryptMessage` work and `DecryptMessage` now has correct argument
   ordering, but stream-state tracking across interleaved records is still
   unstable — the TLS-mode implant stalls after a few frames. The shipped
   default build is `PLAIN_TCP` (gateway `-dev`, inner ChaCha20-Poly1305 AEAD
   intact, heartbeats sealed). TLS/mTLS remains fully usable for Go-side
   components (covered by the gateway's e2e tests). The implant also has a
   connection supervisor: 3 consecutive send failures trigger a clean
   teardown + reconnect.
2. Single PSK for all agents (no per-agent key derivation or rotation).
   Anti-replay IS wired in: the gateway enforces strictly increasing per-
   session sequence numbers and drops replays (logged).
3. Compiler worker: `-emit-pe` (default) produces a standalone PE64 via a
   hand-rolled COFF→PE linker with kernel32 import thunks, relocations and
   .reloc; XOR constant splitting and label renaming are self-checked, and
   variable-length labels + random NOP insertion give every build a distinct
   hash (verified: obfuscated PE passes the live command battery). Still
   missing from the original spec: template library and containerized nasm.
   Control-flow flattening is gated off (`-flatten`) — its local-label
   dispatchers do not survive multi-function assembly.
4. **Agent command-frame boundary — RESOLVED.** Single commands now relay
   reliably up to the 16 KB frame budget (500–16000 hex-char file_write
   verified with real writes and read-backs; process_list returns ~10 KB
   responses). Five root causes were found and fixed — a volatile-register
   bug in the pipe write loop (the actual "~3KB boundary"), TCP-stream
   poisoning after oversized frames, a Win64 home-slot clobber that silently
   killed `SO_RCVTIMEO` (idle commands used to wait up to 30 s), a sandbox
   short-write on responses larger than the pipe buffer, and a missing pipe
   drain after rejected oversized responses. Full write-up with the debugging
   methodology in [docs/DEBUG_NOTES_3KB_BOUNDARY.md](docs/DEBUG_NOTES_3KB_BOUNDARY.md).
   UploadFile now uses 7000-byte chunks (100 KB upload ≈ 3 s, md5-verified);
   oversize frames are pre-rejected at the control plane with a clear error.
5. Sandbox `execute` terminates children after 30 s and caps captured output
   at 64 KB; the sandbox heap is reclaimed between commands (a bump-allocator
   that never freed exhausted 4 MB after repeated process_list calls);
   `file_append` (0x07) enables chunked writes. Download is still
   single-frame: files larger than ~8 KB return a clean `sbx-resp-too-big`
   error (the agent drains the pipe and stays healthy; chunked download is
   roadmap).
6. **TLS-mode implant is functional via the connection supervisor**: the
   Schannel receive stream-state still degrades after a few frames, but the
   supervisor tears down and reconnects (~9 s cycle), and commands complete
   over TLS (sysinfo/shell verified). PLAIN_TCP + inner AEAD remains the
   default; sustained TLS operation produces periodic re-registrations in
   gateway logs (operationally visible).
7. Console: no topology graph, multi-user collaboration or plugin packaging
   yet; file upload/download UI still unusable (the gRPC paths underneath
   are verified working — see `tools/cmdprobe`).

Verified end-to-end (PLAIN_TCP mode, this repository's test tooling):
crypto interop suite (6/6), sandbox direct suite (7/7), gateway unit/e2e
tests, and the full live command battery — sysinfo / process_list /
dir_list / file_read / file_write / shell (with exec_return task
completion) against a live agent — plus file transfer round-trips
(100 KB chunked upload in ~3 s and small-file download, both md5-verified
via `tools/cmdprobe`) and oversized-frame rejection with full recovery.

## Detection notes for defenders

Fixed magic `FEI\0` at offset 0 of every frame, 36-byte headers with a
big-endian millisecond timestamp at offset 26, heartbeat intervals equal to
the build-time constant, deterministic nonce derivation
(`le32(seq)||agent_id`), and NATS subjects `fei.event.*` / `fei.cmd.*` are
all practical network/audit signatures for lab detection engineering.

## License

BSD 3-Clause. See `LICENSE`. Usage subject to `DISCLAIMER.md`.
