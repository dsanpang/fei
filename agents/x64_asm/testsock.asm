; testsock: standalone SO_RCVTIMEO investigation against ws2_32.
; Modes (via -D):
;   (none)      full flow: connect, setsockopt(1000ms), recv(1) -> exit code
;               = park_ms(capped 250) | 0x100 recv-got-data | 0x200 sso-fail
;   -DGSO       after setsockopt, getsockopt the value back:
;               exit = readback_ms | (gso_fail ? 0x10000 : 0)
;   -DSSO_ONLY  exit right after setsockopt: 0x400 | ret
;   -DNO_CONNECT skip connect (recv should return WSAENOTCONN at once)
bits 64
default rel

extern LoadLibraryA
extern GetProcAddress
extern GetSystemTimeAsFileTime
extern ExitProcess

section .text
global _start

%macro RESOLVE 2
    mov rcx, r15
    lea rdx, [%1]
    call GetProcAddress
    mov [%2], rax
%endmacro

_start:
    sub rsp, 56

    lea rcx, [str_ws2]
    call LoadLibraryA
    test rax, rax
    jz .fail
    mov r15, rax                    ; ws2_32 base

    RESOLVE s_WSAStartup, ptr_WSAStartup
    RESOLVE s_socket, ptr_socket
    RESOLVE s_connect, ptr_connect
    RESOLVE s_setsockopt, ptr_setsockopt
    RESOLVE s_getsockopt, ptr_getsockopt
    RESOLVE s_recv, ptr_recv

    ; WSAStartup(0x0202, &wsadata)
    mov ecx, 0x0202
    lea rdx, [wsadata]
    call [ptr_WSAStartup]
    test eax, eax
    jnz .fail1

    ; socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)
    mov ecx, 2
    mov edx, 1
    mov r8d, 6
    call [ptr_socket]
    cmp rax, -1
    je .fail2
    mov [sockh], rax

%ifndef NO_CONNECT
    mov word [saddr], 2
    mov ax, 4433
    xchg al, ah
    mov [saddr+2], ax
    mov dword [saddr+4], 0x0100007F
    mov rcx, [sockh]
    lea rdx, [saddr]
    mov r8d, 16
    call [ptr_connect]
    test eax, eax
    jnz .fail3
%endif

    ; setsockopt(s, SOL_SOCKET=0xFFFF, SO_RCVTIMEO=0x1006, &1000, 4)
    mov dword [sso_ms], 1000
    mov rcx, [sockh]
    mov edx, 0xFFFF
    mov r8d, 0x1006
    lea r9, [sso_ms]
    mov dword [rsp+32], 4
    call [ptr_setsockopt]
    mov [sso_ret], eax

%ifdef SSO_ONLY
    mov ecx, eax
    or ecx, 0x400
    call ExitProcess
%endif

%ifdef GSO
    ; getsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &val, &len=4)
    mov dword [gso_val], 0xAAAAAAAA
    mov dword [gso_len], 4
    mov rcx, [sockh]
    mov edx, 0xFFFF
    mov r8d, 0x1006
    lea r9, [gso_val]
    lea rax, [gso_len]
    mov [rsp+32], rax
    call [ptr_getsockopt]
    ; exit code = val | (gso fail ? 0x10000 : 0) | (sso fail ? 0x20000 : 0)
    mov edx, [gso_val]
    test eax, eax
    jz .g1
    or edx, 0x10000
.g1:
    cmp dword [sso_ret], 0
    je .g2
    or edx, 0x20000
.g2:
    mov ecx, edx
    call ExitProcess
%endif

    ; t0
    lea rcx, [ftbuf]
    call GetSystemTimeAsFileTime
    mov rax, [ftbuf]
    mov [t0], rax

    ; recv(s, buf, 1, 0)
    mov rcx, [sockh]
    lea rdx, [rbuf]
    mov r8d, 1
    xor r9d, r9d
    call [ptr_recv]
    mov [recv_ret], eax

    ; t1
    lea rcx, [ftbuf]
    call GetSystemTimeAsFileTime
    mov rax, [ftbuf]
    sub rax, [t0]
    shr rax, 13                 ; 100ns -> ~ms
    cmp eax, 250
    jbe .dt_ok
    mov eax, 250
.dt_ok:
    mov [delta], eax

    mov eax, [delta]
    cmp dword [recv_ret], 0
    jle .nr
    or eax, 0x100
.nr:
    cmp dword [sso_ret], 0
    je .ns
    or eax, 0x200
.ns:
    mov ecx, eax
    call ExitProcess

.fail3:
    mov ecx, 3
    call ExitProcess
.fail2:
    mov ecx, 2
    call ExitProcess
.fail1:
    mov ecx, 1
    call ExitProcess
.fail:
    mov ecx, 0xFF
    call ExitProcess

section .data
str_ws2:       db "ws2_32.dll", 0
s_WSAStartup:  db "WSAStartup", 0
s_socket:      db "socket", 0
s_connect:     db "connect", 0
s_setsockopt:  db "setsockopt", 0
s_getsockopt:  db "getsockopt", 0
s_recv:        db "recv", 0

section .bss
ptr_WSAStartup: resq 1
ptr_socket:    resq 1
ptr_connect:   resq 1
ptr_setsockopt: resq 1
ptr_getsockopt: resq 1
ptr_recv:      resq 1
sockh:         resq 1
sso_ret:       resd 1
recv_ret:      resd 1
delta:         resd 1
sso_ms:        resd 1
gso_val:       resd 1
gso_len:       resd 1
t0:            resq 1
ftbuf:         resb 8
rbuf:          resb 16
wsadata:       resb 512
saddr:         resb 16
