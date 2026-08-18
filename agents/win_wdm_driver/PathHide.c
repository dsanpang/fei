/* SPDX-License-Identifier: GPL-2.0 */
/*
 * PathHide.c - MiniFilter hiding files and directory trees from CREATE
 * and directory enumeration. Matching is exact OR directory-prefix
 * (hidden path + L'\\'), so children of a hidden directory are
 * intercepted together with the directory itself.
 */
#include <fltKernel.h>
#include <dontuse.h>
#include <suppress.h>
#include <ntstrsafe.h>
#include "PathHide.h"

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, InitPathHide)
#pragma alloc_text(INIT, PathHide_EnsureInstancesKey)
#pragma alloc_text(PAGE, CleanupPathHide)
#endif

/* MiniFilter callbacks must never be paged (spec §8.1/§13). */

#define PHPOOL_TAG 'PtHd'

/* FileNameLength sits at byte offset 60 in every supported class;
 * NextEntryOffset is always at offset 0. */
#define PH_NEXT_OFFSET_OFF   0
#define PH_NAMELEN_OFFSET    60

typedef struct _HIDE_ENTRY {
    LIST_ENTRY Link;
    UNICODE_STRING NtPath;      /* downcased NT path, buffer appended */
} HIDE_ENTRY;

static LIST_ENTRY  g_HideList;         /* active */
static LIST_ENTRY  g_NewHideList;      /* staging */
static ERESOURCE   g_HideLock;
static PFLT_FILTER g_Filter = NULL;

/* ------------------------------------------------------------------ */
/* Registration                                                        */
/* ------------------------------------------------------------------ */
FLT_PREOP_CALLBACK_STATUS PreCreateCallback (
    __inout PFLT_CALLBACK_DATA Data,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __deref_out_opt PVOID *CompletionContext);

FLT_PREOP_CALLBACK_STATUS PreDirCtrlCallback (
    __inout PFLT_CALLBACK_DATA Data,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __deref_out_opt PVOID *CompletionContext);

FLT_POSTOP_CALLBACK_STATUS PostDirCtrlCallback (
    __inout PFLT_CALLBACK_DATA Data,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __in_opt PVOID CompletionContext,
    __in FLT_POST_OPERATION_FLAGS Flags);

static const FLT_OPERATION_REGISTRATION Callbacks[] = {
    { IRP_MJ_CREATE, 0, PreCreateCallback, NULL },
    { IRP_MJ_DIRECTORY_CONTROL, 0, PreDirCtrlCallback, PostDirCtrlCallback },
    { IRP_MJ_OPERATION_END }
};

static const FLT_CONTEXT_REGISTRATION ContextRegistry[] = {
    { FLT_CONTEXT_END }
};

static FLT_UNLOAD_CALLBACK_STATUS FilterUnloadCallback (
    __in FLT_FILTER_UNLOAD_FLAGS Flags);

static const FLT_REGISTRATION FilterRegistration = {
    sizeof(FLT_REGISTRATION),
    FLT_REGISTRATION_VERSION,
    0,                          /* Flags */
    ContextRegistry,            /* Context */
    Callbacks,                  /* OperationRegistration */
    FilterUnloadCallback,       /* FilterUnloadCallback */
    NULL,                       /* InstanceSetupCallback */
    NULL,                       /* InstanceQueryTeardownCallback */
    NULL,                       /* InstanceTeardownStartCallback */
    NULL,                       /* InstanceTeardownCompleteCallback */
    NULL,                       /* GenerateFileNameCallback */
    NULL,                       /* NormalizeNameComponentCallback */
    NULL                        /* NormalizeContextCleanupCallback */
};

/* ------------------------------------------------------------------ */
/* Hide list                                                           */
/* ------------------------------------------------------------------ */
static VOID
PhFreeList (__in PLIST_ENTRY Head)
{
    PLIST_ENTRY link;

    while (!IsListEmpty(Head)) {
        link = RemoveHeadList(Head);
        ExFreePoolWithTag(CONTAINING_RECORD(link, HIDE_ENTRY, Link),
                          PHPOOL_TAG);
    }
}

VOID
PathHide_BeginUpdate (VOID)
{
    /* drop stale staged entries, keep the active list serving readers */
    PhFreeList(&g_NewHideList);
    InitializeListHead(&g_NewHideList);
}

/* \??\X: volume resolution via ZwOpenSymbolicLinkObject, then the path is
 * appended and the whole thing downcased. */
static NTSTATUS
PathHide_Win32ToNtPath (__in PCWSTR Win32Path, __in ULONG Win32Chars,
                        __out PUNICODE_STRING NtPath)
{
    WCHAR drive[8];
    WCHAR target[PATHHIDE_MAX_NT];
    UNICODE_STRING linkName;
    UNICODE_STRING linkTarget;
    OBJECT_ATTRIBUTES oa;
    HANDLE linkHandle = NULL;
    NTSTATUS status;
    ULONG targetLen;

    RtlZeroMemory(NtPath, sizeof(UNICODE_STRING));

    if (Win32Chars < 3 || Win32Path[1] != L':' || Win32Path[2] != L'\\')
        return STATUS_INVALID_PARAMETER;

    RtlStringCchCopyW(drive, RTL_NUMBER_OF(drive), L"\\??\\");
    drive[4] = Win32Path[0];
    drive[5] = L':';
    drive[6] = L'\0';

    RtlInitUnicodeString(&linkName, drive);
    InitializeObjectAttributes(&oa, &linkName,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                               NULL, NULL);
    status = ZwOpenSymbolicLinkObject(&linkHandle, SYMBOLIC_LINK_QUERY, &oa);
    if (!NT_SUCCESS(status))
        return status;

    linkTarget.Buffer = target;
    linkTarget.MaximumLength = sizeof(target);
    linkTarget.Length = 0;
    status = ZwQuerySymbolicLink(linkHandle, &linkTarget, NULL);
    ZwClose(linkHandle);
    if (!NT_SUCCESS(status))
        return status;

    /* target + rest of the user path; NtPath buffer comes preallocated
     * by the caller (PATHHIDE_MAX_NT WCHARs). */
    targetLen = linkTarget.Length / sizeof(WCHAR);
    if (targetLen > 0 && target[targetLen - 1] == L'\\')
        targetLen--;                        /* avoid doubled slash */

    status = RtlStringCchCopyW(NtPath->Buffer, PATHHIDE_MAX_NT, target);
    if (NT_SUCCESS(status))
        status = RtlStringCchCatNW(NtPath->Buffer, PATHHIDE_MAX_NT,
                                   Win32Path + 2, Win32Chars - 2);
    if (!NT_SUCCESS(status))
        return status;

    RtlInitUnicodeString(NtPath, NtPath->Buffer);
    return STATUS_SUCCESS;
}

NTSTATUS
PathHide_AddPath (__in PCWSTR Win32Path, __in ULONG PathLength)
{
    HIDE_ENTRY *entry;
    UNICODE_STRING ntPath;
    WCHAR ntBuf[PATHHIDE_MAX_NT];
    UNICODE_STRING lowered;
    NTSTATUS status;
    ULONG totalChars;
    PLIST_ENTRY link;

    /* Reject rather than truncate over-long paths (never half-hide). */
    if (PathLength + 16 >= PATHHIDE_MAX_NT)
        return STATUS_INVALID_PARAMETER;

    ntPath.Buffer = ntBuf;
    status = PathHide_Win32ToNtPath(Win32Path, PathLength, &ntPath);
    if (!NT_SUCCESS(status)) {
        KdPrint(("LayeredGuard: Win32ToNt failed for %ws\n", Win32Path));
        return status;
    }

    /* Dedup inside the staging list before allocating. */
    lowered.Buffer = ntBuf;
    lowered.MaximumLength = sizeof(ntBuf);
    lowered.Length = ntPath.Length;
    RtlDowncaseUnicodeString(&lowered, &ntPath, FALSE);

    for (link = g_NewHideList.Flink; link != &g_NewHideList;
         link = link->Flink) {
        HIDE_ENTRY *scan = CONTAINING_RECORD(link, HIDE_ENTRY, Link);

        if (RtlEqualUnicodeString(&scan->NtPath, &lowered, FALSE))
            return STATUS_SUCCESS;
    }

    totalChars = lowered.Length / sizeof(WCHAR) + 1;
    entry = (HIDE_ENTRY *)ExAllocatePoolWithTag(
                NonPagedPool, sizeof(HIDE_ENTRY) + totalChars * sizeof(WCHAR),
                PHPOOL_TAG);
    if (!entry)
        return STATUS_INSUFFICIENT_RESOURCES;

    entry->NtPath.Buffer = (PWCHAR)(entry + 1);
    entry->NtPath.MaximumLength = (USHORT)(totalChars * sizeof(WCHAR));
    entry->NtPath.Length = lowered.Length;
    RtlCopyMemory(entry->NtPath.Buffer, lowered.Buffer, lowered.Length);
    entry->NtPath.Buffer[totalChars - 1] = L'\0';

    InsertTailList(&g_NewHideList, &entry->Link);
    return STATUS_SUCCESS;
}

/* Splice list heads under the exclusive lock; never struct-assign a
 * LIST_ENTRY sentinel (corrupts it - spec §8.3). */
VOID
PathHide_EndUpdate (VOID)
{
    LIST_ENTRY oldList;
    PLIST_ENTRY firstNew;
    PLIST_ENTRY link;
    PLIST_ENTRY next;

    InitializeListHead(&oldList);

    ExAcquireResourceExclusiveLite(&g_HideLock, TRUE);

    if (!IsListEmpty(&g_HideList)) {
        oldList.Flink = g_HideList.Flink;
        oldList.Blink = g_HideList.Blink;
        oldList.Flink->Blink = &oldList;
        oldList.Blink->Flink = &oldList;
    }

    if (!IsListEmpty(&g_NewHideList)) {
        firstNew = g_NewHideList.Flink;
        g_HideList.Flink = firstNew;
        g_HideList.Blink = g_NewHideList.Blink;
        firstNew->Blink = &g_HideList;
        g_HideList.Blink->Flink = &g_HideList;
    } else {
        InitializeListHead(&g_HideList);
    }
    InitializeListHead(&g_NewHideList);

    ExReleaseResourceLite(&g_HideLock);

    for (link = oldList.Flink; link != &oldList; link = next) {
        next = link->Flink;
        ExFreePoolWithTag(CONTAINING_RECORD(link, HIDE_ENTRY, Link),
                          PHPOOL_TAG);
    }
}

/* Exact match or directory-tree prefix (hidden + L'\\'). Caller holds a
 * downcased query. */
static BOOLEAN
PhIsHiddenPath (__in PUNICODE_STRING Query, __in BOOLEAN SharedLock)
{
    BOOLEAN hidden = FALSE;
    PLIST_ENTRY link;
    ULONG ruleChars;

    if (SharedLock)
        ExAcquireResourceSharedLite(&g_HideLock, TRUE);

    for (link = g_HideList.Flink; link != &g_HideList; link = link->Flink) {
        HIDE_ENTRY *rule = CONTAINING_RECORD(link, HIDE_ENTRY, Link);

        if (RtlEqualUnicodeString(&rule->NtPath, Query, FALSE)) {
            hidden = TRUE;
            break;
        }
        ruleChars = rule->NtPath.Length / sizeof(WCHAR);
        if (Query->Length >= rule->NtPath.Length &&
            RtlCompareMemory(rule->NtPath.Buffer, Query->Buffer,
                             rule->NtPath.Length) ==
                rule->NtPath.Length &&
            Query->Buffer[ruleChars] == L'\\') {
            hidden = TRUE;
            break;
        }
    }

    if (SharedLock)
        ExReleaseResourceLite(&g_HideLock);
    return hidden;
}

/* ------------------------------------------------------------------ */
/* Instances registry key (§8.2)                                       */
/* ------------------------------------------------------------------ */
static NTSTATUS
PathHide_EnsureInstancesKey (__in PUNICODE_STRING RegistryPath)
{
    WCHAR servicesSuffix[600];
    WCHAR instanceName[280];
    PCWSTR serviceName;
    UNICODE_STRING instancesPath;
    OBJECT_ATTRIBUTES oa;
    HANDLE hInstances = NULL;
    HANDLE hInstance = NULL;
    ULONG disposition;
    UNICODE_STRING valueName;
    ULONG flags;
    NTSTATUS status;

    /* Service name = text after the LAST backslash of RegistryPath (not
     * the whole \Registry\Machine\...\Services\Xxx blob). */
    serviceName = RegistryPath->Buffer + (RegistryPath->Length /
                                          sizeof(WCHAR));
    while (serviceName > RegistryPath->Buffer &&
           *(serviceName - 1) != L'\\')
        serviceName--;

    status = RtlStringCchCopyW(servicesSuffix,
                               RTL_NUMBER_OF(servicesSuffix),
                               RegistryPath->Buffer);
    if (!NT_SUCCESS(status))
        return status;
    status = RtlStringCchCatW(servicesSuffix,
                              RTL_NUMBER_OF(servicesSuffix), L"\\Instances");
    if (!NT_SUCCESS(status))
        return status;

    RtlInitUnicodeString(&instancesPath, servicesSuffix);
    InitializeObjectAttributes(&oa, &instancesPath,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                               NULL, NULL);
    status = ZwCreateKey(&hInstances, KEY_ALL_ACCESS, &oa, 0, NULL,
                         REG_OPTION_NON_VOLATILE, &disposition);
    if (!NT_SUCCESS(status)) {
        KdPrint(("LayeredGuard: ZwCreateKey(Instances) 0x%08X\n", status));
        return status;
    }

    nameChars = (ULONG)wcslen(serviceName);
    RtlStringCchCopyW(instanceName, RTL_NUMBER_OF(instanceName), serviceName);
    RtlStringCchCatW(instanceName, RTL_NUMBER_OF(instanceName), L" Instance");

    RtlInitUnicodeString(&valueName, L"DefaultInstance");
    status = ZwSetValueKey(hInstances, &valueName, 0, REG_SZ, instanceName,
                           ((ULONG)wcslen(instanceName) + 1) * sizeof(WCHAR));
    if (!NT_SUCCESS(status))
        KdPrint(("LayeredGuard: DefaultInstance set 0x%08X\n", status));

    /* Subkey creation is RELATIVE to the open Instances handle: never
     * concatenate an absolute path a second time. */
    RtlInitUnicodeString(&valueName, instanceName);
    InitializeObjectAttributes(&oa, &valueName,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                               hInstances, NULL);
    status = ZwCreateKey(&hInstance, KEY_ALL_ACCESS, &oa, 0, NULL,
                         REG_OPTION_NON_VOLATILE, &disposition);
    if (NT_SUCCESS(status)) {
        /* Rewrite every value even when the key already existed, so the
         * settings always follow the current service name. */
        RtlInitUnicodeString(&valueName, L"Altitude");
        ZwSetValueKey(hInstance, &valueName, 0, REG_SZ, PATHHIDE_ALTITUDE,
                      (ULONG)(sizeof(PATHHIDE_ALTITUDE)));
        RtlInitUnicodeString(&valueName, L"Flags");
        flags = 0;
        ZwSetValueKey(hInstance, &valueName, 0, REG_DWORD, &flags,
                      sizeof(flags));
        ZwClose(hInstance);
    } else {
        KdPrint(("LayeredGuard: instance subkey 0x%08X\n", status));
    }

    ZwClose(hInstances);
    return STATUS_SUCCESS;
}

/* ------------------------------------------------------------------ */
/* IRP_MJ_CREATE pre-callback                                          */
/* ------------------------------------------------------------------ */
FLT_PREOP_CALLBACK_STATUS
PreCreateCallback (__inout PFLT_CALLBACK_DATA Data,
                   __in PCFLT_RELATED_OBJECTS FltObjects,
                   __deref_out_opt PVOID *CompletionContext)
{
    PFLT_FILE_NAME_INFORMATION nameInfo;
    UNICODE_STRING lowered;
    WCHAR query[PATHHIDE_MAX_NT];
    NTSTATUS status;

    UNREFERENCED_PARAMETER(FltObjects);
    *CompletionContext = NULL;

    status = FltGetFileNameInformation(
                 Data,
                 FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
                 &nameInfo);
    if (!NT_SUCCESS(status))
        return FLT_PREOP_SUCCESS_NO_CALLBACK;

    lowered.Buffer = query;
    lowered.MaximumLength = sizeof(query);
    lowered.Length = 0;
    if (NT_SUCCESS(RtlDowncaseUnicodeString(&lowered,
                                            &nameInfo->Name, FALSE))) {
        if (PhIsHiddenPath(&lowered, TRUE)) {
            FltReleaseFileNameInformation(nameInfo);
            Data->IoStatus.Status = STATUS_OBJECT_NAME_NOT_FOUND;
            Data->IoStatus.Information = 0;
            return FLT_PREOP_COMPLETE;
        }
    }
    FltReleaseFileNameInformation(nameInfo);
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

/* ------------------------------------------------------------------ */
/* Directory control                                                   */
/* ------------------------------------------------------------------ */
FLT_PREOP_CALLBACK_STATUS
PreDirCtrlCallback (__inout PFLT_CALLBACK_DATA Data,
                    __in PCFLT_RELATED_OBJECTS FltObjects,
                    __deref_out_opt PVOID *CompletionContext)
{
    UNREFERENCED_PARAMETER(FltObjects);
    *CompletionContext = NULL;

    if (Data->Iopb->MinorFunction == IRP_MN_QUERY_DIRECTORY)
        FltLockUserBuffer(Data);            /* maps the MDL for post-op */

    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

static FLT_POSTOP_CALLBACK_STATUS
PostDirSafeCallback (__inout PFLT_CALLBACK_DATA Data,
                     __in_opt PVOID CompletionContext);

FLT_POSTOP_CALLBACK_STATUS
PostDirCtrlCallback (__inout PFLT_CALLBACK_DATA Data,
                     __in PCFLT_RELATED_OBJECTS FltObjects,
                     __in_opt PVOID CompletionContext,
                     __in FLT_POST_OPERATION_FLAGS Flags)
{
    BOOLEAN postNeeded;

    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    /* DRAINING check at ENTRY, before WhenSafe: the IRP is going away,
     * nothing is safe to touch from here on (spec §0.1). */
    if (FlagOn(Flags, FLTFL_POST_OPERATION_DRAINING))
        return FLT_POSTOP_FINISHED_PROCESSING;

    if (!FltDoCompletionProcessingWhenSafe(Data, NULL, FALSE,
                                           PostDirSafeCallback,
                                           &postNeeded))
        return FLT_POSTOP_FINISHED_PROCESSING;   /* cannot wait: abandon */

    return FLT_POSTOP_FINISHED_PROCESSING;
}

static FLT_POSTOP_CALLBACK_STATUS
PostDirSafeCallback (__inout PFLT_CALLBACK_DATA Data,
                     __in_opt PVOID CompletionContext)
{
    PFLT_IO_PARAMETER_BLOCK iopb = Data->Iopb;
    PVOID buffer;
    ULONG dataSize;
    ULONG curOff = 0;
    PULONG pPrev = NULL;                    /* -> previous entry's NextOff */
    WCHAR dirPath[PATHHIDE_MAX_NT];
    WCHAR full[PATHHIDE_MAX_NT];
    UNICODE_STRING loweredDir;
    PFLT_FILE_NAME_INFORMATION nameInfo;
    FILE_INFORMATION_CLASS infoClass;
    ULONG fileNameOffset;
    NTSTATUS status;

    UNREFERENCED_PARAMETER(CompletionContext);

    if (iopb->MinorFunction != IRP_MN_QUERY_DIRECTORY)
        return FLT_POSTOP_FINISHED_PROCESSING;

    status = Data->IoStatus.Status;
    if (!NT_SUCCESS(status) && status != STATUS_NO_MORE_FILES)
        return FLT_POSTOP_FINISHED_PROCESSING;

    buffer = MmGetSystemAddressForMdlSafe(Data->Iopb->Irp->MdlAddress,
                                          NormalPagePool);
    if (!buffer)
        return FLT_POSTOP_FINISHED_PROCESSING;

    /* Walk bound is IoStatus.Information, NOT QueryDirectory.Length. */
    dataSize = (ULONG)Data->IoStatus.Information;
    if (dataSize == 0)
        return FLT_POSTOP_FINISHED_PROCESSING;

    infoClass = iopb->Parameters.DirectoryControl.QueryDirectory
                    .FileInformationClass;
    switch (infoClass) {
    case FileDirectoryInformation:
        fileNameOffset = FIELD_OFFSET(FILE_DIRECTORY_INFORMATION, FileName);
        break;
    case FileFullDirectoryInformation:
        fileNameOffset = FIELD_OFFSET(FILE_FULL_DIRECTORY_INFORMATION,
                                      FileName);
        break;
    case FileBothDirectoryInformation:
        fileNameOffset = FIELD_OFFSET(FILE_BOTH_DIR_INFORMATION, FileName);
        break;
    case FileIdBothDirectoryInformation:
        fileNameOffset = FIELD_OFFSET(FILE_ID_BOTH_DIR_INFORMATION,
                                      FileName);
        break;
    case FileIdFullDirectoryInformation:
        fileNameOffset = FIELD_OFFSET(FILE_ID_FULL_DIR_INFORMATION,
                                      FileName);
        break;
    default:
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    /* The directory's own path, downcased, trailing slash removed. */
    status = FltGetFileNameInformation(
                 Data,
                 FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
                 &nameInfo);
    if (!NT_SUCCESS(status))
        return FLT_POSTOP_FINISHED_PROCESSING;

    {
        FLT_FILE_NAME_INFORMATION parsed = *nameInfo;

        /* parse a private copy for the dir component only */
        if (!NT_SUCCESS(FltParseFileNameInformation(&parsed))) {
            FltReleaseFileNameInformation(nameInfo);
            return FLT_POSTOP_FINISHED_PROCESSING;
        }

        loweredDir.Buffer = dirPath;
        loweredDir.MaximumLength = sizeof(dirPath);
        loweredDir.Length = 0;
        status = RtlDowncaseUnicodeString(&loweredDir, &parsed.Name, FALSE);
        FltReleaseFileNameInformation(nameInfo);
        if (!NT_SUCCESS(status))
            return FLT_POSTOP_FINISHED_PROCESSING;
    }

    if (loweredDir.Length >= sizeof(WCHAR) &&
        loweredDir.Buffer[loweredDir.Length / sizeof(WCHAR) - 1] == L'\\')
        loweredDir.Length -= sizeof(WCHAR);

    while (curOff + fileNameOffset <= dataSize) {
        PUCHAR entry = (PUCHAR)buffer + curOff;
        ULONG nextOff = *(PULONG)(entry + PH_NEXT_OFFSET_OFF);
        ULONG fileNameLen = *(PULONG)(entry + PH_NAMELEN_OFFSET);
        PWCHAR fileName = (PWCHAR)(entry + fileNameOffset);
        ULONG nameChars;
        UNICODE_STRING query;

        if (curOff + fileNameOffset + fileNameLen > dataSize)
            break;                          /* truncated tail: stop */

        nameChars = fileNameLen / sizeof(WCHAR);

        /* skip "." and ".." by CONTENT together with LENGTH (length-only
         * matching would hide every 1-2 char filename) */
        if (!((nameChars == 1 && fileName[0] == L'.') ||
              (nameChars == 2 && fileName[0] == L'.' &&
               fileName[1] == L'.'))) {

            /* full path = DirPath + '\\' + FileName, all downcased */
            ULONG dirChars = loweredDir.Length / sizeof(WCHAR);
            ULONG k;
            BOOLEAN hide;

            if (dirChars + 1 + nameChars >= PATHHIDE_MAX_NT)
                goto advance;               /* over-long: leave visible */

            RtlCopyMemory(full, loweredDir.Buffer,
                          loweredDir.Length);
            full[dirChars] = L'\\';
            for (k = 0; k < nameChars; k++)
                full[dirChars + 1 + k] =
                    (WCHAR)RtlDowncaseUnicodeChar(fileName[k]);
            query.Buffer = full;
            query.Length = (USHORT)((dirChars + 1 + nameChars) *
                                    sizeof(WCHAR));
            query.MaximumLength = sizeof(full);

            hide = PhIsHiddenPath(&query, TRUE);
            if (hide) {
                if (curOff == 0) {
                    if (nextOff != 0 && nextOff < dataSize) {
                        RtlMoveMemory(entry, entry + nextOff,
                                      dataSize - nextOff);
                        dataSize -= nextOff;
                        /* first-entry compaction: MUST publish the new
                         * remaining byte count (spec §0.1). */
                        Data->IoStatus.Information = dataSize;
                        continue;           /* re-read the shifted entry */
                    }
                    /* first and only entry: report empty */
                    Data->IoStatus.Status = STATUS_NO_MORE_FILES;
                    Data->IoStatus.Information = 0;
                    return FLT_POSTOP_FINISHED_PROCESSING;
                }
                if (nextOff != 0) {
                    if (pPrev)
                        *pPrev += nextOff;
                    curOff += nextOff;
                    continue;
                }
                /* hidden entry is the LAST: terminate at previous */
                if (pPrev)
                    *pPrev = 0;
                break;
            }
        }

advance:
        pPrev = (PULONG)((PUCHAR)buffer + curOff);
        if (nextOff == 0)
            break;
        curOff += nextOff;
    }

    /* every compaction path also refreshes Information; the normal exit
     * keeps the (possibly trimmed) byte count consistent */
    Data->IoStatus.Information = dataSize;
    return FLT_POSTOP_FINISHED_PROCESSING;
}

/* ------------------------------------------------------------------ */
/* Init / cleanup                                                      */
/* ------------------------------------------------------------------ */
static NTSTATUS
FilterUnloadCallback (__in FLT_FILTER_UNLOAD_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(Flags);
    return STATUS_SUCCESS;                  /* allow unload */
}

NTSTATUS
InitPathHide (__in PDRIVER_OBJECT DriverObject,
              __in PUNICODE_STRING RegistryPath)
{
    NTSTATUS status;

    ExInitializeResourceLite(&g_HideLock);
    InitializeListHead(&g_HideList);
    InitializeListHead(&g_NewHideList);

    /* Instances key follows the REAL service name parsed out of
     * RegistryPath (never a hard-coded debug name). */
    status = PathHide_EnsureInstancesKey(RegistryPath);
    if (!NT_SUCCESS(status))
        KdPrint(("LayeredGuard: EnsureInstancesKey 0x%08X\n", status));

    status = FltRegisterFilter(DriverObject, &FilterRegistration, &g_Filter);
    if (!NT_SUCCESS(status)) {
        KdPrint(("LayeredGuard: FltRegisterFilter 0x%08X\n", status));
        g_Filter = NULL;
        return status;
    }

    status = FltStartFiltering(g_Filter);
    if (!NT_SUCCESS(status)) {
        KdPrint(("LayeredGuard: FltStartFiltering 0x%08X\n", status));
        FltUnregisterFilter(g_Filter);
        g_Filter = NULL;
        return status;
    }

    return STATUS_SUCCESS;
}

VOID
CleanupPathHide (VOID)
{
    PAGED_CODE();

    if (g_Filter) {
        FltUnregisterFilter(g_Filter);
        g_Filter = NULL;
    }

    ExAcquireResourceExclusiveLite(&g_HideLock, TRUE);
    PhFreeList(&g_HideList);
    PhFreeList(&g_NewHideList);
    ExReleaseResourceLite(&g_HideLock);
    ExDeleteResourceLite(&g_HideLock);
}
