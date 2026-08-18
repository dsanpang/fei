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
pub const CMD_FILE_APPEND: u8 = 0x07;
pub const CMD_DBG_QUERY: u8 = 0x09;
pub const CMD_PROTECT: u8 = 0x08;

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
const FILE_APPEND_DATA: u32 = 0x0004;
const OBJ_CASE_INSENSITIVE: u32 = 0x40;
const SYNCHRONIZE: u32 = 0x0010_0000;

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

// ---------------------------------------------------------------------------
// NT syscall layer: resolve ntdll exports via the PEB walk and call them
// directly. This replaces the previous hand-rolled `syscall` wrappers whose
// inline-asm stack-argument writes ([rsp+0x28]) were unsound under the Rust
// prologue (arguments could be spilled elsewhere / locals corrupted), and it
// also removes the hardcoded per-Windows-version syscall numbers.
// ---------------------------------------------------------------------------

use core::sync::atomic::{AtomicUsize, Ordering};

static NT_BASE: AtomicUsize = AtomicUsize::new(0);

unsafe fn nt_base() -> usize {
    let mut b = NT_BASE.load(Ordering::Relaxed);
    if b == 0 {
        b = find_module_base(&[
            b'n' as u16, b't' as u16, b'd' as u16, b'l' as u16, b'l' as u16,
            b'.' as u16, b'd' as u16, b'l' as u16, b'l' as u16,
        ]);
        NT_BASE.store(b, Ordering::Relaxed);
    }
    b
}

unsafe fn nt_fn(name: &[u8]) -> usize {
    find_export(nt_base(), name)
}

macro_rules! nt_call {
    ($name:literal, $sig:ty, $($arg:expr),* $(,)?) => {{
        static CACHE: AtomicUsize = AtomicUsize::new(0);
        let mut f = CACHE.load(Ordering::Relaxed);
        if f == 0 {
            f = nt_fn($name);
            CACHE.store(f, Ordering::Relaxed);
        }
        if f == 0 { -1 } else {
            let typed: $sig = core::mem::transmute(f);
            typed($($arg),*)
        }
    }};
}

// NtReadFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock*,
//            Buffer*, Length, ByteOffset*, Key*)
type SigNtReadFile = unsafe extern "system" fn(
    usize, usize, usize, usize, *mut IoStatusBlock, *mut u8, u32, usize, usize) -> i32;
// NtWriteFile shares the shape
type SigNtWriteFile = SigNtReadFile;
type SigNtClose = unsafe extern "system" fn(usize) -> i32;
// NtQuerySystemInformation(Class, Info*, Length, ReturnLength*)
type SigNtQuerySystemInformation = unsafe extern "system" fn(
    u32, *mut u8, u32, *mut u32) -> i32;
// NtOpenFile(FileHandle*, DesiredAccess, ObjectAttributes*, IoStatusBlock*,
//            ShareAccess, OpenOptions)
type SigNtOpenFile = unsafe extern "system" fn(
    *mut usize, u32, *const ObjectAttributes, *mut IoStatusBlock, u32, u32) -> i32;
// NtCreateFile(FileHandle*, DesiredAccess, ObjectAttributes*, IoStatusBlock*,
//              AllocationSize*, FileAttributes, ShareAccess, Disposition,
//              CreateOptions, EaBuffer*, EaLength)
type SigNtCreateFile = unsafe extern "system" fn(
    *mut usize, u32, *const ObjectAttributes, *mut IoStatusBlock, usize, u32,
    u32, u32, u32, usize, u32) -> i32;
// NtQueryDirectoryFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock*,
//                      FileInfo*, Length, Class, ReturnSingleEntry, FileName*, RestartScan)
type SigNtQueryDirectoryFile = unsafe extern "system" fn(
    usize, usize, usize, usize, *mut IoStatusBlock, *mut u8, usize, usize,
    usize, usize, usize) -> i32;

unsafe fn nt_read_file(handle: usize, buf: *mut u8, len: u32, iosb: *mut IoStatusBlock) -> i32 {
    nt_call!(b"NtReadFile", SigNtReadFile, handle, 0, 0, 0, iosb, buf, len, 0, 0)
}

unsafe fn nt_write_file(handle: usize, buf: *const u8, len: u32, iosb: *mut IoStatusBlock) -> i32 {
    nt_call!(b"NtWriteFile", SigNtWriteFile, handle, 0, 0, 0,
             iosb, buf as *mut u8, len, 0, 0)
}

unsafe fn nt_query_dir_file(
    handle: usize, iosb: *mut IoStatusBlock, file_info: *mut u8, len: usize,
    restart: u8,
) -> i32 {
    nt_call!(b"NtQueryDirectoryFile", SigNtQueryDirectoryFile,
             handle, 0, 0, 0, iosb, file_info, len,
             FILE_DIRECTORY_INFORMATION as usize, 1usize, 0usize, restart as usize)
}

// NtQueryDirectoryFile terminates enumeration with this warning:
const STATUS_NO_MORE_FILES: i32 = 0x80000006u32 as i32;
const STATUS_NO_MORE_ENTRIES: i32 = 0x8000001Au32 as i32;
const STATUS_MORE_ENTRIES: i32 = 0x00000105;

unsafe fn nt_close(handle: usize) -> i32 {
    nt_call!(b"NtClose", SigNtClose, handle)
}

unsafe fn nt_query_system_information(info_class: u32, buf: *mut u8, buf_len: u32) -> i32 {
    let mut ret_len: u32 = 0;
    let r = nt_call!(b"NtQuerySystemInformation", SigNtQuerySystemInformation,
                     info_class, buf, buf_len, &mut ret_len as *mut _);
    LAST_NT_STATUS.store(r, core::sync::atomic::Ordering::Relaxed);
    r
}

// ---- registry helpers for the protect command (0x08) -------------------
type SigNtOpenKey = unsafe extern "system" fn(*mut usize, u32, *const ObjectAttributes) -> i32;
type SigNtCreateKey = unsafe extern "system" fn(
    *mut usize, u32, *const ObjectAttributes, u32, *const UnicodeString,
    u32, *mut u32) -> i32;
type SigNtQueryValueKey = unsafe extern "system" fn(
    usize, *const UnicodeString, u32, *mut u8, u32, *mut u32) -> i32;
type SigNtSetValueKey = unsafe extern "system" fn(
    usize, *const UnicodeString, u32, u32, *const u8, u32) -> i32;
type SigNtCloseK = unsafe extern "system" fn(usize) -> i32;

const KVPI_CLASS: u32 = 2;          // KeyValuePartialInformation
const REG_SZ_TYPE: u32 = 1;
const REG_OPTION_NON_VOLATILE: u32 = 0;
const KEY_QUERY_VALUE: u32 = 0x0001;
const KEY_SET_VALUE: u32 = 0x0002;

unsafe fn nt_open_key(h: *mut usize, access: u32, attrs: *const ObjectAttributes) -> i32 {
    nt_call!(b"NtOpenKey", SigNtOpenKey, h, access, attrs)
}
unsafe fn nt_create_key(h: *mut usize, access: u32, attrs: *const ObjectAttributes) -> i32 {
    nt_call!(b"NtCreateKey", SigNtCreateKey, h, access, attrs, 0,
             core::ptr::null(), REG_OPTION_NON_VOLATILE, core::ptr::null_mut())
}
unsafe fn nt_query_value(key: usize, name: *const UnicodeString,
                         buf: *mut u8, len: u32, out_len: *mut u32) -> i32 {
    nt_call!(b"NtQueryValueKey", SigNtQueryValueKey,
             key, name, KVPI_CLASS, buf, len, out_len)
}
unsafe fn nt_set_value(key: usize, name: *const UnicodeString,
                       data: *const u8, size: u32) -> i32 {
    nt_call!(b"NtSetValueKey", SigNtSetValueKey, key, name, 0,
             REG_SZ_TYPE, data, size)
}
unsafe fn nt_closek(h: usize) {
    let _ = nt_call!(b"NtClose", SigNtCloseK, h);
}

unsafe fn key_attrs(name: *const UnicodeString, root: usize) -> ObjectAttributes {
    ObjectAttributes {
        length: 48,
        root_directory: root,
        object_name: name,
        attributes: OBJ_CASE_INSENSITIVE,
        security_descriptor: 0,
        security_quality_of_service: 0,
    }
}

fn wide_bytes(s: &[u8]) -> Vec<u16> {
    let mut v: Vec<u16> = Vec::new();
    for &b in s {
        v.push(b as u16);
    }
    v
}

fn us_from(w: &[u16]) -> UnicodeString {
    UnicodeString {
        length: (w.len() * 2) as u16,
        maximum_length: (w.len() * 2 + 2) as u16,
        buffer: w.as_ptr() as *mut u16,
    }
}

fn wide_list_contains(existing: &[u16], item: &[u16]) -> bool {
    let mut start = 0usize;
    for i in 0..=existing.len() {
        if i == existing.len() || existing[i] == b';' as u16 {
            let mut eq = (i - start) == item.len();
            if eq {
                for k in 0..item.len() {
                    let mut a = existing[start + k];
                    let mut b = item[k];
                    if a >= b'A' as u16 && a <= b'Z' as u16 { a += 32; }
                    if b >= b'A' as u16 && b <= b'Z' as u16 { b += 32; }
                    if a != b {
                        eq = false;
                        break;
                    }
                }
            }
            if eq {
                return true;
            }
            start = i + 1;
        }
    }
    false
}

fn wide_list_append(existing: &[u16], item: &[u16]) -> Vec<u16> {
    let mut m: Vec<u16> = Vec::new();
    m.extend_from_slice(existing);
    if !m.is_empty() {
        m.push(b';' as u16);
    }
    m.extend_from_slice(item);
    m
}

// open-or-create: absolute-open first; on miss descend from the
// \Registry\Machine base with RootDirectory-relative names
// (the registry ROOT itself refuses NtCreateKey, so a deep absolute
// NtCreateKey cannot work; descent only runs for custom test paths).
unsafe fn open_or_create_key(path_w: &[u16], access: u32) -> (i32, usize) {
    let abs = us_from(path_w);
    let attrs = key_attrs(&abs, 0);
    let mut h: usize = 0;
    let mut st = nt_open_key(&mut h, access, &attrs);
    if st >= 0 {
        return (st, h);
    }

    let base: [u16; 17] = [0x5C, 0x52, 0x65, 0x67, 0x69, 0x73, 0x74, 0x72, 0x79,
                           0x5C, 0x4D, 0x61, 0x63, 0x68, 0x69, 0x6E, 0x65];
    if path_w.len() <= base.len() {
        return (st, 0);
    }
    for i in 0..base.len() {
        if path_w[i] != base[i] {
            return (st, 0);
        }
    }
    let base_us = us_from(&base);
    let base_attrs = key_attrs(&base_us, 0);
    let mut cur: usize = 0;
    st = nt_open_key(&mut cur, access, &base_attrs);
    if st < 0 {
        return (st, 0);
    }

    let mut comp: Vec<u16> = Vec::new();
    let mut i = base.len();
    while i <= path_w.len() {
        let at_end = i == path_w.len();
        let ch: u16 = if at_end { 0 } else { path_w[i] };
        if at_end || ch == b'\\' as u16 {
            if !comp.is_empty() {
                let rel = us_from(&comp);
                let attrs = key_attrs(&rel, cur);
                let mut next: usize = 0;
                st = nt_open_key(&mut next, access, &attrs);
                if st < 0 {
                    st = nt_create_key(&mut next, access, &attrs);
                }
                nt_closek(cur);
                if st < 0 {
                    return (st, 0);
                }
                cur = next;
                comp.clear();
            }
            if at_end {
                break;
            }
        } else {
            comp.push(ch);
        }
        i += 1;
    }
    (0, cur)
}

// handle_protect: merge the agent's own identity into the kernel
// driver's Config rules. Payload (NUL-separated ASCII): [0] image name,
// [1] agent dir, [2] gateway IP, [3] sandbox image name, [4] OPTIONAL
// custom registry kernel-path (test mode: creation allowed; the
// production path is open-only so a driver-less host never grows a
// stray service key).
unsafe fn handle_protect(out: &mut Vec<u8>, payload: &[u8]) {
    let mut parts: Vec<&[u8]> = Vec::new();
    let mut start = 0usize;
    for i in 0..=payload.len() {
        if i == payload.len() || payload[i] == 0 {
            if i > start {
                parts.push(&payload[start..i]);
            }
            start = i + 1;
        }
    }
    if parts.len() < 4 {
        out.extend_from_slice(b"{\"protect\":\"bad-payload\"}");
        return;
    }

    let default_path: &[u8] = b"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\LayeredGuard\\Config";
    let custom = parts.len() >= 5;
    let reg_path_bytes: &[u8] = if custom { parts[4] } else { default_path };
    let reg_path = wide_bytes(reg_path_bytes);

    let (st, hkey) = open_or_create_key(&reg_path, KEY_QUERY_VALUE | KEY_SET_VALUE);
    if st < 0 || hkey == 0 {
        out.extend_from_slice(b"{\"protect\":\"driver-absent\",\"st\":");
        push_dec(out, st as u32 as u64);
        out.push(b'}');
        return;
    }

    // (value name, first payload index, second payload index)
    let groups: [(&[u8], usize, usize); 3] = [
        (b"Process", 0, 3),
        (b"Path", 1, 1),
        (b"IP", 2, 2),
    ];

    let mut applied: usize = 0;
    for &(vname, ia, ib) in groups.iter() {
        let name_w = wide_bytes(vname);
        let vus = us_from(&name_w);

        let mut info: [u8; 512] = [0; 512];
        let mut rlen: u32 = 0;
        let mut existing: Vec<u16> = Vec::new();
        let q = nt_query_value(hkey, &vus, info.as_mut_ptr(),
                               info.len() as u32, &mut rlen);
        // KEY_VALUE_PARTIAL_INFORMATION layout: TitleIndex, Type,
        // DataLength, Data[1] - a 12-byte header, NOT 8.
        if q == 0 && rlen >= 16 {
            let vtype = u32::from_le_bytes(
                [info[4], info[5], info[6], info[7]]);
            let dlen = u32::from_le_bytes(
                [info[8], info[9], info[10], info[11]]) as usize;
            if vtype == REG_SZ_TYPE && 12 + dlen <= info.len() {
                let n = dlen / 2;
                let mut i = 0usize;
                while i < n {
                    let lo = info[12 + i * 2] as u16;
                    let hi = info[12 + i * 2 + 1] as u16;
                    existing.push(lo | (hi << 8));
                    i += 1;
                }
                // REG_SZ data carries the NUL terminator: leaving it in
                // would embed a NUL mid-value and truncate every viewer.
                while existing.last() == Some(&0) {
                    existing.pop();
                }
            }
        }

        let mut merged: Vec<u16> = existing.clone();
        for &idx in [ia, ib].iter() {
            let item = wide_bytes(parts[idx]);
            if !wide_list_contains(&merged, &item) {
                merged = wide_list_append(&merged, &item);
                applied += 1;
            }
        }

        if merged != existing {
            merged.push(0);            // REG_SZ NUL terminator
            let s = nt_set_value(hkey, &vus,
                                 merged.as_ptr() as *const u8,
                                 (merged.len() * 2) as u32);
            if s < 0 {
                out.extend_from_slice(b"{\"protect\":\"write-failed\",\"st\":");
                push_dec(out, s as u32 as u64);
                out.push(b'}');
                nt_closek(hkey);
                return;
            }
        }
    }

    nt_closek(hkey);
    out.extend_from_slice(b"{\"protect\":\"ok\",\"added\":");
    push_dec(out, applied as u64);
    out.push(b'}');
}

unsafe fn nt_open_file(
    handle: *mut usize, access: u32, attrs: *const ObjectAttributes,
    iosb: *mut IoStatusBlock, share: u32, options: u32,
) -> i32 {
    let r = nt_call!(b"NtOpenFile", SigNtOpenFile, handle, access, attrs, iosb, share, options);
    LAST_NT_STATUS.store(r, core::sync::atomic::Ordering::Relaxed);
    r
}

unsafe fn nt_create_file(
    handle: *mut usize, access: u32, attrs: *const ObjectAttributes,
    iosb: *mut IoStatusBlock, alloc: usize, file_attrs: u32, share: u32,
    disposition: u32, options: u32,
) -> i32 {
    let r = nt_call!(b"NtCreateFile", SigNtCreateFile,
             handle, access, attrs, iosb, alloc, file_attrs, share,
             disposition, options, 0, 0);
    LAST_NT_STATUS.store(r, core::sync::atomic::Ordering::Relaxed);
    r
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
    let params = *(peb as *const usize).add(4);              // PEB+0x20 -> ProcessParameters (x64; +0x18 is Ldr)
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
    // A pipe NtWriteFile is a SHORT write whenever the request exceeds the
    // pipe buffer: it returns success with iosb.information = bytes actually
    // written. Loop until the whole response is in the pipe; the old
    // single-call version silently truncated every large response and left
    // the desynced bytes to poison all later commands.
    let mut off = 0usize;
    while off < data.len() {
        let mut iosb = IoStatusBlock { status: 0, information: 0 };
        let status = nt_write_file(handle, data.as_ptr().add(off),
                                   (data.len() - off) as u32, &mut iosb);
        if status < 0 {
            return false;
        }
        if iosb.information == 0 {
            return false;
        }
        off += iosb.information;
    }
    true
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

type SigNtTerminateProcess = unsafe extern "system" fn(usize, i32) -> i32;

/// Terminate the sandbox process. Chains three independent exits so a
/// resolution failure can never leave a spinning core (the old `loop {}`
/// fallback pegged CPU at 100% whenever anything panicked).
pub fn exit_process(code: i32) -> ! {
    unsafe {
        // 1) NtTerminateProcess(NULL) from ntdll
        let f = nt_fn(b"NtTerminateProcess");
        if f != 0 {
            let typed: SigNtTerminateProcess = core::mem::transmute(f);
            typed(0, code); // NULL handle = current process
        }
        // 2) kernel32!ExitProcess via the PEB walk
        let k32 = find_module_base(&[
            b'k' as u16, b'e' as u16, b'r' as u16, b'n' as u16, b'e' as u16,
            b'l' as u16, b'3' as u16, b'2' as u16, b'.' as u16, b'd' as u16,
            b'l' as u16, b'l' as u16,
        ]);
        let ep = find_export(k32, b"ExitProcess");
        if ep != 0 {
            let typed: unsafe extern "system" fn(u32) -> ! = core::mem::transmute(ep);
            typed(code as u32);
        }
        // 3) last resort: crash (fast-fail) rather than spin
        core::arch::asm!("ud2", options(noreturn, nomem, nostack));
    }
}

pub unsafe fn debug_std_handles() -> (usize, usize) {
    get_std_handles()
}

pub unsafe fn debug_write(handle: usize, data: &[u8]) {
    let _ = write_all(handle, data);
}

static mut RESET_HOOK: Option<fn()> = None;

pub fn run_with_reset(reset: fn()) {
    unsafe { RESET_HOOK = Some(reset) }
    run()
}

pub fn run() {
    unsafe {
        let (stdin, stdout) = get_std_handles();
        let mut cmd_buf = [0u8; CMD_BUF_SIZE];

        loop {
            // reclaim the bump heap between commands: every allocation from
            // the previous iteration (response Vecs, staging) was already
            // written to the pipe, so resetting the pointer is safe and
            // prevents long-session exhaustion (process_list alone reserves
            // up to 1 MB per call against the 4 MB heap)
            unsafe {
                if let Some(h) = RESET_HOOK { h() }
            }

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
                CMD_FILE_APPEND => handle_file_append(&mut resp, payload),
                CMD_DBG_QUERY => handle_dbg_query(&mut resp, payload),
                CMD_PROTECT => handle_protect(&mut resp, payload),
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
        } else if b == 0x0A {
            out.extend_from_slice(b"\n");
        } else {
            out.push(b' ');
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
    // SystemProcessInformation sizing varies with process count: start at
    // 64 KB and double on STATUS_INFO_LENGTH_MISMATCH (classic pattern)
    const STATUS_INFO_LENGTH_MISMATCH: i32 = 0xC0000004u32 as i32;
    let mut heap_buf: Vec<u8> = Vec::new();
    let mut buf_ptr: *mut u8 = core::ptr::null_mut();
    let mut buf_len: u32 = 65536;
    let mut status: i32 = 0;
    loop {
        heap_buf = Vec::new();
        heap_buf.resize(buf_len as usize, 0);
        buf_ptr = heap_buf.as_mut_ptr();
        status = nt_query_system_information(SYSTEM_PROCESS_INFORMATION, buf_ptr, buf_len);
        if status != STATUS_INFO_LENGTH_MISMATCH || buf_len >= 1048576 {
            break;
        }
        buf_len *= 2;
    }
    if status < 0 {
        out.push(b'{');
        push_nt_error(out, b"NtQuerySystemInformation failed");
        out.extend_from_slice(b",\"processes\":[]}");
        return;
    }

    out.extend_from_slice(b"{\"processes\":[");
    let mut offset = 0usize;
    let mut first = true;

    loop {
        let entry = buf_ptr.add(offset);
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
    let status = nt_open_file(
        &mut handle,
        FILE_LIST_DIRECTORY | SYNCHRONIZE,
        &obj_attrs,
        &mut iosb,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
    );
    if status < 0 {
        out.push(b'{');
        push_nt_error(out, b"failed to open directory");
        out.extend_from_slice(b",\"files\":[]}");
        return;
    }

    out.extend_from_slice(b"{\"files\":[");
    let mut first = true;
    let mut restart: u8 = 1;
    let mut ok = false;

    'batches: loop {
        let mut dir_buf = [0u8; 16384];
        let mut qiosb = IoStatusBlock { status: 0, information: 0 };
        let status = nt_query_dir_file(
            handle, &mut qiosb, dir_buf.as_mut_ptr(), dir_buf.len(), restart,
        );
        restart = 0;
        if status == STATUS_NO_MORE_FILES || status == STATUS_NO_MORE_ENTRIES {
            ok = true; // enumeration complete (normal termination warning)
            break 'batches;
        }
        if qiosb.information > 0 {
            // got an entry: parse below and fetch the next one after
        } else if status < 0 {
            LAST_NT_STATUS.store(status, core::sync::atomic::Ordering::Relaxed);
            LAST_QIOSB_INFO.store(qiosb.information as u64, core::sync::atomic::Ordering::Relaxed);
            break 'batches;
        } else {
            ok = true; // no data, no error: listing complete
            break 'batches;
        }
        let _ = STATUS_MORE_ENTRIES;

        let mut entry_offset = 0usize;
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
        if first {
            // batch returned data we fully skipped (. / ..): keep fetching
            // until a real entry or NO_MORE_ENTRIES so we never spin
            continue;
        }
    }
    nt_close(handle);

    if !ok {
        out.clear();
        out.push(b'{');
        push_nt_error(out, b"NtQueryDirectoryFile failed");
        out.extend_from_slice(b",\"files\":[]}");
        return;
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
    let status = nt_open_file(
        &mut handle,
        GENERIC_READ | SYNCHRONIZE,
        &obj_attrs,
        &mut iosb,
        FILE_SHARE_READ,
        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
    );
    if status < 0 {
        out.push(b'{');
        push_nt_error(out, b"failed to open file");
        out.push(b'}');
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
    let status = nt_create_file(
        &mut handle,
        GENERIC_WRITE | SYNCHRONIZE,
        &obj_attrs,
        &mut iosb,
        0,                                // AllocationSize
        0x80,                             // FILE_ATTRIBUTE_NORMAL
        FILE_SHARE_READ,
        FILE_OVERWRITE_IF,
        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
    );
    if status < 0 {
        out.push(b'{');
        push_nt_error(out, b"failed to open file for writing");
        out.push(b'}');
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

unsafe fn terminate(handle: usize, code: u32) {
    static CACHE: AtomicUsize = AtomicUsize::new(0);
    let mut f = CACHE.load(Ordering::Relaxed);
    if f == 0 {
        let k32 = find_module_base(&[
            b'k' as u16, b'e' as u16, b'r' as u16, b'n' as u16, b'e' as u16,
            b'l' as u16, b'3' as u16, b'2' as u16, b'.' as u16, b'd' as u16,
            b'l' as u16, b'l' as u16,
        ]);
        f = find_export(k32, b"TerminateProcess");
        CACHE.store(f, Ordering::Relaxed);
    }
    if f != 0 {
        let typed: unsafe extern "system" fn(usize, u32) -> i32 = core::mem::transmute(f);
        typed(handle, code);
    }
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

    // bounded wait: 30 s, then terminate the child (no runaway processes)
    let mut timed_out = false;
    if wait_for(pi.h_process, 30_000) != WAIT_OBJECT_0 {
        terminate(pi.h_process, 1);
        timed_out = true;
    }
    let mut exit_code: u32 = 0;
    get_exit(pi.h_process, &mut exit_code);
    close_handle(pi.h_process);
    close_handle(pi.h_thread);
    let _ = si.cb;

    out.extend_from_slice(b"{\"pid\":");
    push_dec(out, pi.pid as u64);
    out.extend_from_slice(b",\"stdout\":\"");
    push_json_escaped(out, &output);
    if timed_out {
        out.extend_from_slice(b",\"timed_out\":true");
    }
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

unsafe fn handle_dbg_query(out: &mut Vec<u8>, payload: &[u8]) {
    // minimal NtOpenFile + NtQueryDirectoryFile with everything inline
    let wide = wide_nt_path(payload);
    let us = UnicodeString {
        length: (wide.len() * 2) as u16,
        maximum_length: (wide.len() * 2 + 2) as u16,
        buffer: wide.as_ptr() as *mut u16,
    };
    let oa = ObjectAttributes {
        length: 48, root_directory: 0, object_name: &us,
        attributes: OBJ_CASE_INSENSITIVE, security_descriptor: 0,
        security_quality_of_service: 0,
    };
    let mut h: usize = 0;
    let mut o_iosb = IoStatusBlock { status: 0, information: 0 };
    let st_open = nt_open_file(&mut h, FILE_LIST_DIRECTORY | SYNCHRONIZE, &oa,
        &mut o_iosb, FILE_SHARE_READ | FILE_SHARE_WRITE,
        FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT);

    out.extend_from_slice(b"{\"open\":\"0x");
    push_hex_i32(out, st_open);
    out.extend_from_slice(b"\",\"h\":");
    push_dec(out, h as u64);
    if st_open < 0 {
        out.extend_from_slice(b"}");
        return;
    }

    let mut buf = [0u8; 16384];
    let mut q_iosb = IoStatusBlock { status: 0, information: 0 };
    let st_q = nt_call!(b"NtQueryDirectoryFile", SigNtQueryDirectoryFile,
        h, 0, 0, 0, &mut q_iosb as *mut _, buf.as_mut_ptr(), buf.len() as usize,
        1usize, 1usize, 0usize, 1usize);
    out.extend_from_slice(b",\"q\":\"0x");
    push_hex_i32(out, st_q);
    out.extend_from_slice(b"\",\"info\":");
    push_dec(out, q_iosb.information as u64);
    out.extend_from_slice(b",\"buf0\":\"0x");
    let b0 = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
    push_hex_i32(out, b0 as i32);
    out.extend_from_slice(b"\"");
    nt_close(h);
    out.extend_from_slice(b"}");
}

fn push_hex_i32(out: &mut Vec<u8>, v: i32) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let x = v as u32;
    for shift in (0..=28).rev().step_by(4) {
        out.push(HEX[((x >> shift) & 0xF) as usize]);
    }
}

fn push_nt_error(out: &mut Vec<u8>, msg: &[u8]) {
    // emits `"error":"<msg>","status":"0x..."` — callers own the braces
    out.extend_from_slice(b"\"error\":\"");
    out.extend_from_slice(msg);
    out.extend_from_slice(b"\",\"status\":\"0x");
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let v = LAST_NT_STATUS.load(core::sync::atomic::Ordering::Relaxed) as u32;
    let mut started = false;
    for shift in (0..=28).rev().step_by(4) {
        let nib = ((v >> shift) & 0xF) as usize;
        if nib != 0 || started || shift == 0 {
            out.push(HEX[nib]);
            started = true;
        }
    }
    out.extend_from_slice(b"\"");
}

pub static LAST_NT_STATUS: core::sync::atomic::AtomicI32 = core::sync::atomic::AtomicI32::new(0);
pub static LAST_QIOSB_INFO: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

unsafe fn handle_file_append(out: &mut Vec<u8>, payload: &[u8]) {
    // payload: <path>   <hex content> — opens existing file and appends
    let split = match payload.iter().position(|&b| b == 0) {
        Some(i) => i,
        None => {
            out.extend_from_slice(b"{\"error\":\"payload must be path<NUL>hex\"}");
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
        match (hex_val(hex_part[i]), hex_val(hex_part[i + 1])) {
            (Some(h), Some(l)) => content.push((h << 4) | l),
            _ => {
                out.extend_from_slice(b"{\"error\":\"invalid hex\"}");
                return;
            }
        }
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
    let status = nt_open_file(
        &mut handle,
        (FILE_APPEND_DATA | SYNCHRONIZE) as u32,
        &obj_attrs,
        &mut iosb,
        FILE_SHARE_READ,
        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
    );
    if status < 0 {
        out.push(b'{');
        push_nt_error(out, b"failed to open file for append");
        out.push(b'}');
        return;
    }
    let _ = write_all(handle, &content);
    nt_close(handle);
    out.extend_from_slice(b"{\"appended\":");
    push_dec(out, content.len() as u64);
    out.extend_from_slice(b"}");
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
