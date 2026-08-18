/* SPDX-License-Identifier: GPL-2.0 */
/*
 * RegHide.c - registry key hiding via CmRegisterCallbackEx.
 *
 * PreOpen/PreCreate deny the key itself AND its subkey tree (full path
 * equal or prefixed by hidden + L'\\'); PostEnumerateKey replaces an
 * enumerated hidden subkey with the next visible one.
 */
#include <ntstrsafe.h>
#include "RegHide.h"

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, RegHide_Init)
#pragma alloc_text(PAGE, RegHide_Cleanup)
#pragma alloc_text(PAGE, RegHide_AddKey)
#pragma alloc_text(PAGE, ConvertToKernelPath)
#endif

#define RHPOOL_TAG 'RgHd'

static WCHAR g_HideList[REGHIDE_MAX_ENTRIES][REGHIDE_MAX_PATH];   /* active */
static WCHAR g_TempList[REGHIDE_MAX_ENTRIES][REGHIDE_MAX_PATH];   /* temp */
static ULONG g_HideCount;
static FAST_MUTEX g_HideListLock;

static LARGE_INTEGER g_Cookie;
static BOOLEAN g_CallbackRegistered = FALSE;

/* ------------------------------------------------------------------ */
/* Reentrancy protection                                               */
/* ------------------------------------------------------------------ */
static volatile HANDLE g_Reentrant[REGHIDE_MAX_REENTRANT];

VOID
RegHide_MarkReentrant (VOID)
{
    HANDLE tid = PsGetCurrentThreadId();
    ULONG i;

    for (i = 0; i < REGHIDE_MAX_REENTRANT; i++) {
        if (InterlockedCompareExchangePointer(
                (PVOID volatile *)&g_Reentrant[i], (PVOID)tid, NULL) == NULL)
            return;
    }
    /* table exhausted: treat as reentrant (fail closed, never recurse) */
}

VOID
RegHide_UnmarkReentrant (VOID)
{
    HANDLE tid = PsGetCurrentThreadId();
    ULONG i;

    for (i = 0; i < REGHIDE_MAX_REENTRANT; i++) {
        if (InterlockedCompareExchangePointer(
                (PVOID volatile *)&g_Reentrant[i], NULL, (PVOID)tid) ==
                (PVOID)tid)
            return;
    }
}

static BOOLEAN
RhIsReentrant (VOID)
{
    HANDLE tid = PsGetCurrentThreadId();
    ULONG i;

    for (i = 0; i < REGHIDE_MAX_REENTRANT; i++) {
        if (g_Reentrant[i] == tid)
            return TRUE;
    }
    return FALSE;
}

/* ------------------------------------------------------------------ */
/* Prefix conversion (single table shared with ValidateRegPath)        */
/* ------------------------------------------------------------------ */
typedef struct {
    PCWSTR UserPrefix;      /* includes trailing backslash */
    PCWSTR KernelPrefix;   /* includes trailing backslash */
} RH_PREFIX_MAP;

static const RH_PREFIX_MAP g_PrefixMap[] = {
    { L"HKEY_LOCAL_MACHINE\\", L"\\Registry\\Machine\\" },
    { L"HKLM\\",               L"\\Registry\\Machine\\" },
    { L"HKEY_CURRENT_USER\\",  L"\\Registry\\User\\" },
    { L"HKCU\\",               L"\\Registry\\User\\" },
    { L"HKEY_CLASSES_ROOT\\",  L"\\Registry\\Machine\\SOFTWARE\\Classes\\" },
    { L"HKCR\\",               L"\\Registry\\Machine\\SOFTWARE\\Classes\\" },
};

NTSTATUS
ConvertToKernelPath (__in PCWSTR UserPath,
                     __out PWCHAR KernelBuf,
                     __in ULONG KernelBufCch)
{
    NTSTATUS status;
    ULONG i;

    PAGED_CODE();

    KernelBuf[0] = L'\0';

    /* "\..." stays as-is */
    if (UserPath[0] == L'\\')
        return RtlStringCchCopyW(KernelBuf, KernelBufCch, UserPath);

    /* "Registry\..." gets a leading slash */
    if (_wcsnicmp(UserPath, L"Registry\\", 9) == 0) {
        status = RtlStringCchCopyW(KernelBuf, KernelBufCch, L"\\");
        if (NT_SUCCESS(status))
            status = RtlStringCchCatW(KernelBuf, KernelBufCch, UserPath);
        return status;
    }

    for (i = 0; i < RTL_NUMBER_OF(g_PrefixMap); i++) {
        PCWSTR prefix = g_PrefixMap[i].UserPrefix;
        PCWSTR suffix = UserPath + wcslen(prefix);
        PCWSTR k;

        if (_wcsnicmp(UserPath, prefix, wcslen(prefix)) != 0)
            continue;

        /* skip ONE leading '\\' in the suffix after the prefix match
         * (otherwise comparing the 18-char HKLM prefix leaves a stray
         * backslash - spec §0.1) */
        if (*suffix == L'\\')
            suffix++;

        k = g_PrefixMap[i].KernelPrefix;
        status = RtlStringCchCopyW(KernelBuf, KernelBufCch, k);
        if (NT_SUCCESS(status))
            status = RtlStringCchCatW(KernelBuf, KernelBufCch, suffix);
        return status;
    }

    return STATUS_INVALID_PARAMETER;
}

/* ------------------------------------------------------------------ */
/* Hide list                                                           */
/* ------------------------------------------------------------------ */
VOID
RegHide_BeginUpdate (VOID)
{
    /* whole-table staging: EndUpdate replaces the active list */
    RtlZeroMemory(g_TempList, sizeof(g_TempList));
}

static VOID
RhAddTempEntry (__in PCWSTR Path)
{
    ULONG i;

    for (i = 0; i < REGHIDE_MAX_ENTRIES; i++) {
        if (g_TempList[i][0] == L'\0') {
            RtlStringCchCopyW(g_TempList[i], REGHIDE_MAX_PATH, Path);
            return;
        }
    }
    KdPrint(("LayeredGuard: reghide temp list full\n"));
}

/* Canonical-path resolution (§9.4): open the key, query its object name,
 * store BOTH the canonical path and the literal kernel path. */
NTSTATUS
RegHide_AddKey (__in PCWSTR KernelPath)
{
    OBJECT_ATTRIBUTES oa;
    IO_STATUS_BLOCK iosb;
    UNICODE_STRING pathUs;
    HANDLE hKey = NULL;
    NTSTATUS status;

    PAGED_CODE();

    RhAddTempEntry(KernelPath);             /* literal form always stored */

    RtlInitUnicodeString(&pathUs, KernelPath);
    InitializeObjectAttributes(&oa, &pathUs,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                               NULL, NULL);

    /* canonical resolution opens the key too: mark reentrant so our own
     * registry traffic is never filtered */
    RegHide_MarkReentrant();
    status = ZwOpenKey(&hKey, KEY_READ, &oa);
    RegHide_UnmarkReentrant();
    if (!NT_SUCCESS(status))
        return status;

    {
        UCHAR nameInfoBuf[sizeof(OBJECT_NAME_INFORMATION) +
                          REGHIDE_MAX_PATH * sizeof(WCHAR)];
        POBJECT_NAME_INFORMATION nameInfo =
            (POBJECT_NAME_INFORMATION)nameInfoBuf;
        ULONG returnLength = 0;

        status = ObQueryNameString(hKey, nameInfo, sizeof(nameInfoBuf),
                                   &returnLength);
        if (NT_SUCCESS(status) && nameInfo->Name.Buffer &&
            nameInfo->Name.Length > 0) {
            WCHAR canonical[REGHIDE_MAX_PATH];
            ULONG chars = nameInfo->Name.Length / sizeof(WCHAR);

            if (chars < REGHIDE_MAX_PATH) {
                RtlCopyMemory(canonical, nameInfo->Name.Buffer,
                              nameInfo->Name.Length);
                canonical[chars] = L'\0';
                /* store canonical form as well when it differs */
                if (_wcsicmp(canonical, KernelPath) != 0)
                    RhAddTempEntry(canonical);
            }
        }
    }

    ZwClose(hKey);
    return STATUS_SUCCESS;
}

VOID
RegHide_EndUpdate (VOID)
{
    ULONG count = 0;
    ULONG i;

    /* dedup the temp list (case-insensitive), cap at REGHIDE_MAX_ENTRIES */
    for (i = 0; i < REGHIDE_MAX_ENTRIES && count < REGHIDE_MAX_ENTRIES;
         i++) {
        ULONG j;

        if (g_TempList[i][0] == L'\0')
            continue;
        for (j = 0; j < i; j++) {
            if (g_TempList[j][0] != L'\0' &&
                _wcsicmp(g_TempList[j], g_TempList[i]) == 0)
                break;
        }
        if (j == i) {
            /* keep it; compact into the first free slot at 'count' */
            if (count != i) {
                RtlStringCchCopyW(g_TempList[count], REGHIDE_MAX_PATH,
                                  g_TempList[i]);
                g_TempList[i][0] = L'\0';
            }
            count++;
        } else {
            g_TempList[i][0] = L'\0';
        }
    }

    ExAcquireFastMutex(&g_HideListLock);
    RtlCopyMemory(g_HideList, g_TempList, sizeof(g_HideList));
    g_HideCount = count;
    ExReleaseFastMutex(&g_HideListLock);
}

/* equal or prefixed by hidden + '\\' (tree hide) */
static BOOLEAN
RhPathHidden (__in PCWSTR FullPath)
{
    BOOLEAN hidden = FALSE;
    ULONG i;
    ULONG ruleLen;

    ExAcquireFastMutex(&g_HideListLock);
    for (i = 0; i < g_HideCount; i++) {
        if (_wcsicmp(g_HideList[i], FullPath) == 0) {
            hidden = TRUE;
            break;
        }
        ruleLen = (ULONG)wcslen(g_HideList[i]);
        if (_wcsnicmp(g_HideList[i], FullPath, ruleLen) == 0 &&
            FullPath[ruleLen] == L'\\') {
            hidden = TRUE;
            break;
        }
    }
    ExReleaseFastMutex(&g_HideListLock);
    return hidden;
}

/* ------------------------------------------------------------------ */
/* Callback helpers                                                    */
/* ------------------------------------------------------------------ */
static NTSTATUS
RhBuildPreOpenPath (__in PREG_OPEN_KEY_INFORMATION_V1 PreInfo,
                    __out PWCHAR PathBuf,
                    __in ULONG PathCch)
{
    POBJECT_NAME_INFORMATION nameInfo;
    UCHAR nameInfoBuf[sizeof(OBJECT_NAME_INFORMATION) +
                      REGHIDE_MAX_PATH * sizeof(WCHAR)];
    ULONG returnLength = 0;
    NTSTATUS status;

    /* 1: no CompleteName -> nothing to judge */
    if (!PreInfo->CompleteName || !PreInfo->CompleteName->Buffer)
        return STATUS_UNSUCCESSFUL;

    /* 2: absolute path (leading backslash) */
    if (PreInfo->CompleteName->Buffer[0] == L'\\') {
        ULONG chars = PreInfo->CompleteName->Length / sizeof(WCHAR);

        if (chars >= PathCch)
            return STATUS_UNSUCCESSFUL;
        RtlCopyMemory(PathBuf, PreInfo->CompleteName->Buffer,
                      PreInfo->CompleteName->Length);
        PathBuf[chars] = L'\0';
        return STATUS_SUCCESS;
    }

    /* 3: relative to RootObject: ObQueryNameString + '\\' + CompleteName */
    if (PreInfo->RootObject) {
        nameInfo = (POBJECT_NAME_INFORMATION)nameInfoBuf;
        status = ObQueryNameString((PVOID)PreInfo->RootObject, nameInfo,
                                   sizeof(nameInfoBuf), &returnLength);
        if (NT_SUCCESS(status) && nameInfo->Name.Buffer &&
            nameInfo->Name.Length > 0) {
            ULONG rootChars = nameInfo->Name.Length / sizeof(WCHAR);
            ULONG relChars = PreInfo->CompleteName->Length / sizeof(WCHAR);
            ULONG copyFrom = 0;

            if (rootChars + relChars + 2 >= PathCch)
                return STATUS_UNSUCCESSFUL;

            RtlCopyMemory(PathBuf, nameInfo->Name.Buffer,
                          nameInfo->Name.Length);
            /* skip a duplicated slash between the two halves */
            if (rootChars > 0 && PathBuf[rootChars - 1] == L'\\' &&
                PreInfo->CompleteName->Buffer[0] == L'\\')
                copyFrom = 1;
            else if (rootChars > 0 && PathBuf[rootChars - 1] != L'\\')
                PathBuf[rootChars++] = L'\\';

            RtlCopyMemory(PathBuf + rootChars,
                          PreInfo->CompleteName->Buffer + copyFrom,
                          (relChars - copyFrom) * sizeof(WCHAR));
            PathBuf[rootChars + relChars - copyFrom] = L'\0';
            return STATUS_SUCCESS;
        }
    }

    /* 4: fall back to CompleteName as-is */
    {
        ULONG chars = PreInfo->CompleteName->Length / sizeof(WCHAR);

        if (chars >= PathCch)
            return STATUS_UNSUCCESSFUL;
        RtlCopyMemory(PathBuf, PreInfo->CompleteName->Buffer,
                      PreInfo->CompleteName->Length);
        PathBuf[chars] = L'\0';
        return STATUS_SUCCESS;
    }
}

static NTSTATUS
RhHandlePreOpen (__in PVOID Argument2)
{
    PREG_OPEN_KEY_INFORMATION_V1 pre =
        (PREG_OPEN_KEY_INFORMATION_V1)Argument2;
    WCHAR fullPath[REGHIDE_MAX_PATH];
    NTSTATUS status;

    status = RhBuildPreOpenPath(pre, fullPath, RTL_NUMBER_OF(fullPath));
    if (!NT_SUCCESS(status))
        return STATUS_SUCCESS;              /* cannot judge: allow */

    if (RhPathHidden(fullPath))
        return STATUS_OBJECT_NAME_NOT_FOUND;

    return STATUS_SUCCESS;
}

static NTSTATUS
RhHandlePostEnumerateKey (__in PVOID Argument2)
{
    PREG_POST_OPERATION_INFORMATION post =
        (PREG_POST_OPERATION_INFORMATION)Argument2;
    PREG_ENUMERATE_KEY_INFORMATION pre;
    WCHAR subName[256];
    WCHAR fullPath[REGHIDE_MAX_PATH];
    UCHAR nameInfoBuf[sizeof(OBJECT_NAME_INFORMATION) +
                      REGHIDE_MAX_PATH * sizeof(WCHAR)];
    POBJECT_NAME_INFORMATION nameInfo;
    ULONG returnLength = 0;
    KEY_INFORMATION_CLASS kiclass;
    UCHAR infoBuf[512];
    PVOID info = (PVOID)infoBuf;
    ULONG infoLen = 0;
    HANDLE hParent = NULL;
    NTSTATUS status;

    /* 1: failed enumeration passes through untouched */
    if (!NT_SUCCESS(post->Status))
        return STATUS_SUCCESS;

    pre = (PREG_ENUMERATE_KEY_INFORMATION)post->PreInformation;
    if (!pre || !pre->Object || !pre->KeyInformation)
        return STATUS_SUCCESS;

    /* 3: copy the enumerated name into a KERNEL buffer before any
     * comparison - never hold the user pointer outside __try. */
    kiclass = pre->KeyInformationClass;
    __try {
        PUCHAR ki = (PUCHAR)pre->KeyInformation;
        ULONG nameLen = 0;
        PWCHAR namePtr = NULL;

        switch (kiclass) {
        case KeyBasicInformation:
            nameLen = ((PKEY_BASIC_INFORMATION)ki)->NameLength;
            namePtr = ((PKEY_BASIC_INFORMATION)ki)->Name;
            break;
        case KeyNodeInformation:
            nameLen = ((PKEY_NODE_INFORMATION)ki)->NameLength;
            namePtr = ((PKEY_NODE_INFORMATION)ki)->Name;
            break;
        default:
            return STATUS_SUCCESS;          /* unsupported class: allow */
        }

        if (!namePtr || nameLen == 0 || nameLen >= sizeof(subName))
            return STATUS_SUCCESS;

        RtlCopyMemory(subName, namePtr, nameLen);
        subName[nameLen / sizeof(WCHAR)] = L'\0';
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return STATUS_SUCCESS;
    }

    /* 4: parent path + subkey -> full path, judged by the prefix rule */
    nameInfo = (POBJECT_NAME_INFORMATION)nameInfoBuf;
    status = ObQueryNameString((PVOID)pre->Object, nameInfo,
                               sizeof(nameInfoBuf), &returnLength);
    if (!NT_SUCCESS(status) || !nameInfo->Name.Buffer ||
        nameInfo->Name.Length == 0)
        return STATUS_SUCCESS;

    {
        ULONG parentChars = nameInfo->Name.Length / sizeof(WCHAR);
        ULONG subChars = (ULONG)wcslen(subName);

        if (parentChars + subChars + 2 >= RTL_NUMBER_OF(fullPath))
            return STATUS_SUCCESS;

        RtlCopyMemory(fullPath, nameInfo->Name.Buffer,
                      nameInfo->Name.Length);
        if (parentChars == 0 || fullPath[parentChars - 1] != L'\\')
            fullPath[parentChars++] = L'\\';
        RtlCopyMemory(fullPath + parentChars, subName,
                      (subChars + 1) * sizeof(WCHAR));
    }

    /* 5: visible subkey passes through as-is */
    if (!RhPathHidden(fullPath))
        return STATUS_SUCCESS;

    /* 6: find the next VISIBLE subkey starting after the hidden index */
    status = ObOpenObjectByPointer(pre->Object, OBJ_KERNEL_HANDLE, NULL,
                                   KEY_ENUMERATE_SUB_KEYS, NULL, KernelMode,
                                   &hParent);
    if (!NT_SUCCESS(status))
        return STATUS_SUCCESS;

    RegHide_MarkReentrant();
    {
        ULONG index = pre->Index + 1;

        for (;;) {
            RtlZeroMemory(infoBuf, sizeof(infoBuf));
            status = ZwEnumerateKey(hParent, index, kiclass, info,
                                    sizeof(infoBuf), &infoLen);
            if (!NT_SUCCESS(status))
                break;                      /* no more subkeys at all */

            /* extract this candidate's name and re-test */
            {
                PWCHAR candName = NULL;
                ULONG candLen = 0;
                ULONG parentChars2 = nameInfo->Name.Length / sizeof(WCHAR);
                ULONG candChars;

                if (kiclass == KeyBasicInformation) {
                    candLen = ((PKEY_BASIC_INFORMATION)info)->NameLength;
                    candName = ((PKEY_BASIC_INFORMATION)info)->Name;
                } else {
                    candLen = ((PKEY_NODE_INFORMATION)info)->NameLength;
                    candName = ((PKEY_NODE_INFORMATION)info)->Name;
                }
                candChars = candLen / sizeof(WCHAR);

                if (parentChars2 + candChars + 2 <
                        RTL_NUMBER_OF(fullPath)) {
                    RtlCopyMemory(fullPath, nameInfo->Name.Buffer,
                                  nameInfo->Name.Length);
                    if (parentChars2 == 0 ||
                        fullPath[parentChars2 - 1] != L'\\')
                        fullPath[parentChars2++] = L'\\';
                    RtlCopyMemory(fullPath + parentChars2, candName,
                                  candLen);
                    fullPath[parentChars2 + candChars] = L'\0';

                    if (!RhPathHidden(fullPath))
                        break;              /* found a visible one */
                } else {
                    break;
                }
            }
            index++;
        }
    }
    RegHide_UnmarkReentrant();

    /* 7: copy the winner (or the failure) back into the user buffer */
    __try {
        if (!NT_SUCCESS(status)) {
            post->Status = STATUS_NO_MORE_ENTRIES;
        } else if (infoLen > pre->Length) {
            post->Status = STATUS_BUFFER_OVERFLOW;
        } else {
            RtlCopyMemory(pre->KeyInformation, info, infoLen);
            post->Status = STATUS_SUCCESS;
        }
        if (pre->ResultLength)
            *pre->ResultLength = infoLen;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        post->Status = GetExceptionCode();
    }

    ZwClose(hParent);
    return STATUS_SUCCESS;
}

/* ------------------------------------------------------------------ */
/* Callback + init                                                     */
/* ------------------------------------------------------------------ */
static NTSTATUS
RegistryCallback (__in PVOID CallbackContext,
                  __in REG_NOTIFY_CLASS Argument1,
                  __in PVOID Argument2)
{
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(CallbackContext);

    /* top-level SEH: a crash inside must never take the registry with it */
    __try {
        if (RhIsReentrant())
            return STATUS_SUCCESS;

        switch (Argument1) {
        case RegNtPreOpenKeyEx:
        case RegNtPreCreateKeyEx:
            status = RhHandlePreOpen(Argument2);
            break;
        case RegNtPostEnumerateKey:
            status = RhHandlePostEnumerateKey(Argument2);
            break;
        default:
            break;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = STATUS_SUCCESS;
    }

    return status;
}

NTSTATUS
RegHide_Init (__in PDRIVER_OBJECT DriverObject)
{
    UNICODE_STRING altitude;
    NTSTATUS status;

    PAGED_CODE();

    ExInitializeFastMutex(&g_HideListLock);
    RtlZeroMemory(g_HideList, sizeof(g_HideList));
    RtlZeroMemory(g_TempList, sizeof(g_TempList));
    RtlZeroMemory((PVOID)g_Reentrant, sizeof(g_Reentrant));
    g_HideCount = 0;

    /* Altitude differs from the MiniFilter's 370030 */
    RtlInitUnicodeString(&altitude, L"370000");
    status = CmRegisterCallbackEx(RegistryCallback, &altitude, DriverObject,
                                  NULL, &g_Cookie, NULL);
    if (!NT_SUCCESS(status)) {
        KdPrint(("LayeredGuard: CmRegisterCallbackEx 0x%08X\n", status));
        return status;
    }

    g_CallbackRegistered = TRUE;
    return STATUS_SUCCESS;
}

VOID
RegHide_Cleanup (VOID)
{
    PAGED_CODE();

    if (g_CallbackRegistered) {
        CmUnRegisterCallback(g_Cookie);
        g_CallbackRegistered = FALSE;
    }
    RtlZeroMemory(g_HideList, sizeof(g_HideList));
    g_HideCount = 0;
}
