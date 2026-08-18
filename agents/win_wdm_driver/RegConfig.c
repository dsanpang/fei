/* SPDX-License-Identifier: GPL-2.0 */
/*
 * RegConfig.c - background registry polling and rule dispatch.
 *
 * A system thread polls <service>\Config every 5 s. Any value change
 * rebuilds the Net rules and replays all five keys; only a Process-string
 * change (or the first run) additionally restores all spoofed PIDs before
 * re-spoofing - IP/Port/Path/RegPath changes never touch spoofed PIDs.
 */
#include <ntstrsafe.h>
#include "RegConfig.h"
#include "PidSpoof.h"
#include "NetHide.h"
#include "PathHide.h"
#include "RegHide.h"

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, RegConfig_StartPolling)
#pragma alloc_text(PAGE, RegConfig_StopPolling)
#pragma alloc_text(PAGE, RegConfig_PollThread)
#pragma alloc_text(PAGE, RegConfig_PollOnce)
#pragma alloc_text(PAGE, RegConfig_ParseAndValidateValue)
#endif

/* ZwQuerySystemInformation is not declared by ntddk headers: declare it
 * locally (spec §5.1); ntoskrnl exports the Zw flavor drivers may call. */
NTSYSAPI
NTSTATUS
NTAPI
ZwQuerySystemInformation (
    __in ULONG SystemInformationClass,
    __out PVOID SystemInformation,
    __in ULONG SystemInformationLength,
    __out_opt PULONG ReturnLength
    );

#define SystemProcessInformationClass 5

/* Process-snapshot entry: only ImageName / UniqueProcessId /
 * NextEntryOffset are consumed. */
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

/* ------------------------------------------------------------------ */
/* Globals (single polling thread: no extra lock required)             */
/* ------------------------------------------------------------------ */
static KEVENT   g_StopEvent;
static PETHREAD g_PollThread;
static UNICODE_STRING g_ConfigKeyPath;      /* <service>\Config */
static WCHAR    g_ConfigKeyBuffer[512];

static PWCHAR   g_PrevValues[VALUE_COUNT];  /* MAX_VALUE_BYTES each */
static BOOLEAN  g_FirstRun = TRUE;

static const PCWSTR g_ValueNames[VALUE_COUNT] = {
    VAL_PROCESS, VAL_IP, VAL_PORT, VAL_PATH, VAL_REGPATH
};

/* ------------------------------------------------------------------ */
/* Thread plumbing                                                     */
/* ------------------------------------------------------------------ */
static VOID RegConfig_PollOnce (VOID);
static NTSTATUS RegConfig_ParseAndValidateValue (
    __in VALUE_TYPE ValType,
    __in PCWSTR RawValue);

static VOID RegConfig_PollThread (__in PVOID Context)
{
    LARGE_INTEGER timeout;
    NTSTATUS status;

    PAGED_CODE();
    UNREFERENCED_PARAMETER(Context);

    /* First round runs immediately, then one round every POLL_INTERVAL. */
    for (;;) {
        RegConfig_PollOnce();

        timeout.QuadPart = -(LONGLONG)POLL_INTERVAL_SEC * 10000000LL;
        status = KeWaitForSingleObject(&g_StopEvent, Executive, KernelMode,
                                       FALSE, &timeout);
        if (status == STATUS_SUCCESS)
            break;                      /* stop signaled */
    }

    PsTerminateSystemThread(STATUS_SUCCESS);
}

NTSTATUS
RegConfig_StartPolling (__in PUNICODE_STRING RegistryPath)
{
    NTSTATUS status;
    HANDLE threadHandle = NULL;
    ULONG i;

    PAGED_CODE();

    /* Deep-copy the config path: RegistryPath is only valid inside
     * DriverEntry. NEVER hard-code the service name a second time. */
    g_ConfigKeyBuffer[0] = L'\0';
    status = RtlStringCchCopyW(g_ConfigKeyBuffer,
                               RTL_NUMBER_OF(g_ConfigKeyBuffer),
                               RegistryPath->Buffer);
    if (!NT_SUCCESS(status)) {
        KdPrint(("LayeredGuard: config path too long\n"));
        return status;
    }
    status = RtlStringCchCatW(g_ConfigKeyBuffer,
                              RTL_NUMBER_OF(g_ConfigKeyBuffer),
                              CONFIG_REG_PATH_SUFFIX);
    if (!NT_SUCCESS(status)) {
        KdPrint(("LayeredGuard: config path overflow\n"));
        return status;
    }
    RtlInitUnicodeString(&g_ConfigKeyPath, g_ConfigKeyBuffer);

    for (i = 0; i < VALUE_COUNT; i++) {
        g_PrevValues[i] = ExAllocatePoolWithTag(NonPagedPool,
                                                MAX_VALUE_BYTES, POOL_TAG);
        if (!g_PrevValues[i]) {
            KdPrint(("LayeredGuard: prev value alloc failed\n"));
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        RtlZeroMemory(g_PrevValues[i], MAX_VALUE_BYTES);
    }

    KeInitializeEvent(&g_StopEvent, NotificationEvent, FALSE);

    status = PsCreateSystemThread(&threadHandle, THREAD_ALL_ACCESS, NULL,
                                  NULL, NULL, RegConfig_PollThread, NULL);
    if (!NT_SUCCESS(status)) {
        KdPrint(("LayeredGuard: PsCreateSystemThread failed 0x%08X\n", status));
        return status;
    }

    status = ObReferenceObjectByHandle(threadHandle, THREAD_ALL_ACCESS,
                                       *PsThreadType, KernelMode,
                                       (PVOID *)&g_PollThread, NULL);
    ZwClose(threadHandle);
    if (!NT_SUCCESS(status)) {
        KdPrint(("LayeredGuard: thread reference failed 0x%08X\n", status));
        g_PollThread = NULL;
        return status;
    }
    return STATUS_SUCCESS;
}

VOID
RegConfig_StopPolling (VOID)
{
    PAGED_CODE();

    ULONG i;

    if (!g_PollThread)
        return;

    KeSetEvent(&g_StopEvent, IO_NO_INCREMENT, FALSE);
    KeWaitForSingleObject(g_PollThread, Executive, KernelMode, FALSE, NULL);

    ObDereferenceObject(g_PollThread);
    g_PollThread = NULL;

    for (i = 0; i < VALUE_COUNT; i++) {
        if (g_PrevValues[i]) {
            ExFreePoolWithTag(g_PrevValues[i], POOL_TAG);
            g_PrevValues[i] = NULL;
        }
    }
}

/* ------------------------------------------------------------------ */
/* Value reading                                                       */
/* ------------------------------------------------------------------ */
static NTSTATUS
RegConfig_ReadRegSzValue (
    __in HANDLE hConfigKey,
    __in PCWSTR ValueName,
    __out PWCHAR ValueBuf                 /* MAX_VALUE_BYTES, zeroed on fail */
    )
{
    UCHAR infoBuf[sizeof(KEY_VALUE_PARTIAL_INFORMATION) + MAX_VALUE_BYTES];
    PKEY_VALUE_PARTIAL_INFORMATION info = (PKEY_VALUE_PARTIAL_INFORMATION)infoBuf;
    UNICODE_STRING name;
    ULONG length = 0;
    NTSTATUS status;

    RtlZeroMemory(ValueBuf, MAX_VALUE_BYTES);

    RtlInitUnicodeString(&name, ValueName);
    status = ZwQueryValueKey(hConfigKey, &name, KeyValuePartialInformation,
                             info, sizeof(infoBuf), &length);
    if (!NT_SUCCESS(status))
        return status;                    /* missing -> caller treats as empty */

    if (info->Type != REG_SZ || info->DataLength == 0)
        return STATUS_INVALID_PARAMETER;  /* non-REG_SZ -> treated as empty */

    RtlCopyMemory(ValueBuf, info->Data,
                  min(info->DataLength, MAX_VALUE_BYTES - sizeof(WCHAR)));
    ValueBuf[MAX_VALUE_BYTES / sizeof(WCHAR) - 1] = L'\0';
    return STATUS_SUCCESS;
}

/* ------------------------------------------------------------------ */
/* One polling round                                                   */
/* ------------------------------------------------------------------ */
static VOID RegConfig_PollOnce (VOID)
{
    WCHAR current[VALUE_COUNT][MAX_VALUE_BYTES / sizeof(WCHAR)];
    OBJECT_ATTRIBUTES oa;
    HANDLE hConfigKey = NULL;
    NTSTATUS status;
    BOOLEAN anyChange = FALSE;
    BOOLEAN processChanged = FALSE;
    ULONG i;

    PAGED_CODE();

    InitializeObjectAttributes(&oa, &g_ConfigKeyPath,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                               NULL, NULL);
    status = ZwOpenKey(&hConfigKey, KEY_READ, &oa);
    if (!NT_SUCCESS(status)) {
        /* Config unreadable: this round must not change any rule. */
        KdPrint(("LayeredGuard: ZwOpenKey(Config) failed 0x%08X\n", status));
        return;
    }

    for (i = 0; i < VALUE_COUNT; i++) {
        status = RegConfig_ReadRegSzValue(hConfigKey, g_ValueNames[i],
                                          current[i]);
        if (!NT_SUCCESS(status))
            current[i][0] = L'\0';        /* missing / non-REG_SZ = empty */

        if (g_FirstRun || wcscmp(current[i], g_PrevValues[i]) != 0) {
            anyChange = TRUE;
            if (i == ValProcess)
                processChanged = TRUE;
        }
    }
    ZwClose(hConfigKey);

    if (!anyChange)
        return;

    /* Only a Process-string change restores previously spoofed PIDs;
     * replaying an unchanged Process list never calls RestoreAll. */
    if (processChanged)
        PidSpoofRestoreAll();

    /* Every change rebuilds the network rule set (below replays IP/Port). */
    NetHide_ResetRules();

    for (i = 0; i < VALUE_COUNT; i++)
        RegConfig_ParseAndValidateValue((VALUE_TYPE)i, current[i]);

    for (i = 0; i < VALUE_COUNT; i++)
        RtlCopyMemory(g_PrevValues[i], current[i], MAX_VALUE_BYTES);

    g_FirstRun = FALSE;
}

/* ------------------------------------------------------------------ */
/* Item validation                                                     */
/* ------------------------------------------------------------------ */
static VOID
RegConfig_TrimWhitespace (__inout PWCHAR Item, __inout PULONG Length)
{
    ULONG start = 0;
    ULONG len = *Length;

    while (start < len && (Item[start] == L' ' || Item[start] == L'\t'))
        start++;
    while (len > start && (Item[len - 1] == L' ' || Item[len - 1] == L'\t' ||
                           Item[len - 1] == L'\r' || Item[len - 1] == L'\n'))
        len--;

    if (start > 0)
        RtlMoveMemory(Item, Item + start, (len - start) * sizeof(WCHAR));
    Item[len - start] = L'\0';
    *Length = len - start;
}

static VOID
RegConfig_TrimTrailingBackslash (__inout PWCHAR Item, __inout PULONG Length)
{
    while (*Length > 0 && Item[*Length - 1] == L'\\') {
        Item[*Length - 1] = L'\0';
        (*Length)--;
    }
}

/* One-shot snapshot; retry-grows the buffer; caps retries at 8 (on
 * exhaustion returns NULL and this round skips process spoofing). */
static PVOID
RegConfig_SnapshotProcesses (__out PULONG BufferSize)
{
    NTSTATUS status;
    PVOID buffer = NULL;
    ULONG size = 64 * 1024;
    ULONG returnLength = 0;
    ULONG retries = 0;

    while (retries < 8) {
        buffer = ExAllocatePoolWithTag(NonPagedPool, size, POOL_TAG);
        if (!buffer)
            return NULL;

        status = ZwQuerySystemInformation(SystemProcessInformationClass,
                                          buffer, size, &returnLength);
        if (NT_SUCCESS(status)) {
            *BufferSize = size;
            return buffer;
        }

        ExFreePoolWithTag(buffer, POOL_TAG);
        if (status != STATUS_INFO_LENGTH_MISMATCH) {
            KdPrint(("LayeredGuard: snapshot failed 0x%08X\n", status));
            return NULL;
        }
        size = returnLength + 0x1000;
        retries++;
    }

    KdPrint(("LayeredGuard: snapshot retries exhausted\n"));
    return NULL;
}

/* Every same-named process with pid != 0/4 is spoofed, not only the first
 * snapshot hit (spec §0.1). */
static VOID
RegConfig_ValidateProcess (__in PCWSTR ImageName, __in PVOID Snapshot)
{
    PSYSTEM_PROCESS_INFORMATION_ENTRY entry = (PSYSTEM_PROCESS_INFORMATION_ENTRY)Snapshot;
    UNICODE_STRING itemName;
    WCHAR nameBuf[64];

    if (!entry || !ImageName[0])
        return;

    RtlStringCchCopyW(nameBuf, RTL_NUMBER_OF(nameBuf), ImageName);
    RtlInitUnicodeString(&itemName, nameBuf);

    while (entry) {
        if (entry->ImageName.Buffer && entry->ImageName.Length > 0) {
            if (RtlEqualUnicodeString(&entry->ImageName, &itemName, TRUE)) {
                ULONG pid = (ULONG)(ULONG_PTR)entry->UniqueProcessId;

                if (pid != 0 && pid != 4)
                    SpoofSinglePid(pid);
            }
        }
        if (entry->NextEntryOffset == 0)
            break;
        entry = (PSYSTEM_PROCESS_INFORMATION_ENTRY)
                    ((PUCHAR)entry + entry->NextEntryOffset);
    }
}

static BOOLEAN
RegConfig_ValidateIPv4 (__in PCWSTR Item, __out ULONG *Octets)
{
    ULONG octet = 0, digitCount = 0, value = 0;
    ULONG index = 0;
    PCWSTR p;
    WCHAR c;

    for (p = Item; ; p++) {
        c = *p;

        if (c >= L'0' && c <= L'9') {
            if (digitCount == 1 && value == 0)
                return FALSE;             /* leading zero forbidden */
            value = value * 10 + (c - L'0');
            digitCount++;
            if (value > 255)
                return FALSE;
        } else if (c == L'.' || c == L'\0') {
            if (digitCount == 0 || octet >= 4)
                return FALSE;
            Octets[octet++] = value;
            value = 0;
            digitCount = 0;
            if (c == L'\0')
                break;
        } else {
            return FALSE;
        }
        index++;
    }

    return (octet == 4);
}

/* little-endian ULONG: oct[0] | oct[1]<<8 | oct[2]<<16 | oct[3]<<24
 * (the NSI table stores IPv4 in network order = same memory layout). */
static ULONG
RegConfig_ParseIPv4WideToUlong (__in const ULONG *Octets)
{
    return Octets[0] | (Octets[1] << 8) | (Octets[2] << 16) | (Octets[3] << 24);
}

static BOOLEAN
RegConfig_ValidatePort (__in PCWSTR Item, __out PUSHORT Port)
{
    ULONG value = 0;
    PCWSTR p;

    if (!Item[0])
        return FALSE;

    for (p = Item; *p; p++) {
        if (*p < L'0' || *p > L'9')
            return FALSE;
        value = value * 10 + (*p - L'0');
        if (value > 65535)
            return FALSE;
    }

    *Port = (USHORT)value;
    return TRUE;
}

/* ZwCreateFile with FILE_DIRECTORY_FILE first, then FILE_NON_DIRECTORY_FILE:
 * if both fail the item is discarded and never added (spec §5.3). */
static NTSTATUS
RegConfig_ValidatePath (__in PCWSTR Win32Path)
{
    WCHAR ntPath[520];
    UNICODE_STRING pathUs;
    OBJECT_ATTRIBUTES oa;
    IO_STATUS_BLOCK iosb;
    HANDLE handle = NULL;
    NTSTATUS status;

    RtlStringCchCopyW(ntPath, RTL_NUMBER_OF(ntPath), L"\\??\\");
    if (FAILED(StringCchCatW(ntPath, RTL_NUMBER_OF(ntPath), Win32Path))) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlInitUnicodeString(&pathUs, ntPath);
    InitializeObjectAttributes(&oa, &pathUs,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                               NULL, NULL);

    status = ZwCreateFile(&handle,
                          FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                          &oa, &iosb, NULL, FILE_ATTRIBUTE_NORMAL,
                          FILE_SHARE_READ, FILE_OPEN,
                          FILE_DIRECTORY_FILE |
                              FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
    if (NT_SUCCESS(status)) {
        ZwClose(handle);
        return status;
    }

    status = ZwCreateFile(&handle,
                          FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                          &oa, &iosb, NULL, FILE_ATTRIBUTE_NORMAL,
                          FILE_SHARE_READ, FILE_OPEN,
                          FILE_NON_DIRECTORY_FILE |
                              FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
    if (NT_SUCCESS(status)) {
        ZwClose(handle);
        return status;
    }

    KdPrint(("LayeredGuard: path item rejected %ws (0x%08X)\n",
             Win32Path, status));
    return status;
}

static NTSTATUS
RegConfig_ValidateRegPath (__in PCWSTR UserPath, __out PWCHAR KernelBuf,
                           __in ULONG KernelBufCch)
{
    OBJECT_ATTRIBUTES oa;
    IO_STATUS_BLOCK iosb;
    UNICODE_STRING pathUs;
    HANDLE hKey = NULL;
    NTSTATUS status;

    status = ConvertToKernelPath(UserPath, KernelBuf, KernelBufCch);
    if (!NT_SUCCESS(status))
        return status;

    RtlInitUnicodeString(&pathUs, KernelBuf);
    InitializeObjectAttributes(&oa, &pathUs,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                               NULL, NULL);

    /* Reentrancy mark: RegHide's own registry traffic must not be hidden. */
    RegHide_MarkReentrant();
    status = ZwOpenKey(&hKey, KEY_READ, &oa);
    RegHide_UnmarkReentrant();

    if (NT_SUCCESS(status))
        ZwClose(hKey);
    else
        KdPrint(("LayeredGuard: regpath item rejected %ws (0x%08X)\n",
                 UserPath, status));
    return status;
}

/* ------------------------------------------------------------------ */
/* Parse + validate one value                                          */
/* ------------------------------------------------------------------ */
static NTSTATUS
RegConfig_ParseAndValidateValue (
    __in VALUE_TYPE ValType,
    __in PCWSTR RawValue)
{
    WCHAR item[520];
    ULONG itemLength;
    PVOID processSnapshot = NULL;
    ULONG snapshotSize = 0;
    PCWSTR cursor;
    PCWSTR sep;
    ULONG copyLen;

    PAGED_CODE();

    if (ValPath)
        PathHide_BeginUpdate();
    if (ValRegPath)
        RegHide_BeginUpdate();
    if (ValProcess)
        processSnapshot = RegConfig_SnapshotProcesses(&snapshotSize);

    cursor = RawValue;
    while (cursor && *cursor) {
        sep = wcschr(cursor, L';');
        copyLen = sep ? (ULONG)(sep - cursor)
                      : (ULONG)wcslen(cursor);

        if (copyLen == 0) {              /* empty segment: skip */
            if (!sep)
                break;
            cursor = sep + 1;
            continue;
        }
        if (copyLen >= RTL_NUMBER_OF(item))
            copyLen = RTL_NUMBER_OF(item) - 1;

        RtlCopyMemory(item, cursor, copyLen * sizeof(WCHAR));
        item[copyLen] = L'\0';
        itemLength = copyLen;

        RegConfig_TrimWhitespace(item, &itemLength);
        if (itemLength > 0) {
            switch (ValType) {
            case ValProcess:
                RegConfig_ValidateProcess(item, processSnapshot);
                break;
            case ValIP: {
                ULONG octets[4];

                if (RegConfig_ValidateIPv4(item, octets))
                    NetHide_AddByRemoteIp(
                        RegConfig_ParseIPv4WideToUlong(octets));
                else
                    KdPrint(("LayeredGuard: bad IP item %ws\n", item));
                break;
            }
            case ValPort: {
                USHORT port;

                if (RegConfig_ValidatePort(item, &port)) {
                    if (port != 0)       /* port=0 adds no rule */
                        NetHide_AddByLocalPort(port);
                } else {
                    KdPrint(("LayeredGuard: bad port item %ws\n", item));
                }
                break;
            }
            case ValPath: {
                RegConfig_TrimTrailingBackslash(item, &itemLength);
                if (itemLength >= 3 && item[1] == L':' &&
                    item[2] == L'\\' &&
                    NT_SUCCESS(RegConfig_ValidatePath(item))) {
                    PathHide_AddPath(item, itemLength);
                } else {
                    KdPrint(("LayeredGuard: bad path item %ws\n", item));
                }
                break;
            }
            case ValRegPath: {
                WCHAR kernelPath[REGHIDE_MAX_PATH];

                RegConfig_TrimTrailingBackslash(item, &itemLength);
                if (NT_SUCCESS(RegConfig_ValidateRegPath(
                        item, kernelPath, RTL_NUMBER_OF(kernelPath)))) {
                    RegHide_AddKey(kernelPath);
                }
                break;
            }
            }
        }

        if (!sep)
            break;
        cursor = sep + 1;
    }

    if (processSnapshot)
        ExFreePoolWithTag(processSnapshot, POOL_TAG);
    if (ValPath)
        PathHide_EndUpdate();
    if (ValRegPath)
        RegHide_EndUpdate();

    return STATUS_SUCCESS;
}
