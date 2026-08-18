/* SPDX-License-Identifier: GPL-2.0 */
/*
 * DriverObjectSpoof.c - clone the metadata of a benign target driver
 * (\Driver\Null) onto our own DRIVER_OBJECT and LDR entry so naive
 * tooling that walks driver objects or PsLoadedModuleList reports the
 * wrong image.
 *
 * NEVER modified: MajorFunction[], DeviceObject chain, DriverUnload,
 * DriverExtension, InLoadOrderLinks.
 */
#include <ntstrsafe.h>
#include "DriverObjectSpoof.h"

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, SpoofDriverObject)
#pragma alloc_text(PAGE, RestoreDriverObject)
#endif

#define SPOOFPOOL_TAG 'SpfC'

static SPOOF_CONFIG g_SpoofConfig;
static SPOOF_BACKUP g_SpoofBackup;

/* ------------------------------------------------------------------ */
NTSTATUS
SpoofDriverObject (__in PDRIVER_OBJECT SelfDriverObject)
{
    UNICODE_STRING targetName;
    PDRIVER_OBJECT target = NULL;
    PKLDR_DATA_TABLE_ENTRY selfLdr;
    PKLDR_DATA_TABLE_ENTRY targetLdr;
    NTSTATUS status;

    RtlZeroMemory(&g_SpoofConfig, sizeof(g_SpoofConfig));
    RtlZeroMemory(&g_SpoofBackup, sizeof(g_SpoofBackup));

    RtlInitUnicodeString(&g_SpoofConfig.TargetDriverName,
                         TARGET_SPOOF_DRIVER);
    g_SpoofConfig.SpoofDriverName = TRUE;
    g_SpoofConfig.SpoofDriverStart = TRUE;
    g_SpoofConfig.SpoofDriverSize = TRUE;
    g_SpoofConfig.SpoofDriverSection = TRUE;
    g_SpoofConfig.SpoofDriverInit = TRUE;
    g_SpoofConfig.SpoofLdrEntry = TRUE;

    if (g_SpoofBackup.IsActive)
        return STATUS_ALREADY_REGISTERED;

    RtlInitUnicodeString(&targetName, TARGET_SPOOF_DRIVER);
    status = ObReferenceObjectByName(&targetName, OBJ_CASE_INSENSITIVE,
                                     NULL, 0, *IoDriverObjectType, KernelMode,
                                     NULL, (PVOID *)&target);
    if (!NT_SUCCESS(status)) {
        KdPrint(("LayeredGuard: target driver not found 0x%08X\n", status));
        return status;
    }

    /* ---- backups ------------------------------------------------ */
    g_SpoofBackup.OriginalDriverNameRaw = SelfDriverObject->DriverName;
    RtlStringCchCopyNW(g_SpoofBackup.OriginalNameBuffer,
                       RTL_NUMBER_OF(g_SpoofBackup.OriginalNameBuffer),
                       SelfDriverObject->DriverName.Buffer
                           ? SelfDriverObject->DriverName.Buffer : L"",
                       SelfDriverObject->DriverName.Length /
                           sizeof(WCHAR));
    g_SpoofBackup.OriginalDriverStart = SelfDriverObject->DriverStart;
    g_SpoofBackup.OriginalDriverSize = SelfDriverObject->DriverSize;
    g_SpoofBackup.OriginalDriverSection =
        SelfDriverObject->DriverSection;
    g_SpoofBackup.OriginalDriverInit = SelfDriverObject->DriverInit;

    /* ---- LDR entry first (needs the REAL DriverSection) --------- */
    if (g_SpoofConfig.SpoofLdrEntry) {
        selfLdr = (PKLDR_DATA_TABLE_ENTRY)SelfDriverObject->DriverSection;
        targetLdr = (PKLDR_DATA_TABLE_ENTRY)target->DriverSection;

        if (selfLdr && targetLdr) {
            g_SpoofBackup.OriginalLdrDllBase = selfLdr->DllBase;
            g_SpoofBackup.OriginalLdrSizeOfImage = selfLdr->SizeOfImage;
            g_SpoofBackup.OriginalLdrEntryPoint = selfLdr->EntryPoint;
            g_SpoofBackup.OriginalLdrFullDllName = selfLdr->FullDllName;
            g_SpoofBackup.OriginalLdrBaseDllName = selfLdr->BaseDllName;

            selfLdr->DllBase = targetLdr->DllBase;
            selfLdr->EntryPoint = targetLdr->EntryPoint;
            selfLdr->SizeOfImage = targetLdr->SizeOfImage;
            selfLdr->FullDllName = targetLdr->FullDllName;
            selfLdr->BaseDllName = targetLdr->BaseDllName;
            g_SpoofBackup.LdrSpoofActive = TRUE;
        }
    }

    /* ---- DRIVER_OBJECT fields ------------------------------------ */
    if (g_SpoofConfig.SpoofDriverName)
        SelfDriverObject->DriverName = target->DriverName;
    if (g_SpoofConfig.SpoofDriverStart)
        SelfDriverObject->DriverStart = target->DriverStart;
    if (g_SpoofConfig.SpoofDriverSize)
        SelfDriverObject->DriverSize = target->DriverSize;
    if (g_SpoofConfig.SpoofDriverSection)
        SelfDriverObject->DriverSection = target->DriverSection;
    if (g_SpoofConfig.SpoofDriverInit)
        SelfDriverObject->DriverInit = target->DriverInit;

    g_SpoofBackup.TargetDriverObject = target;  /* reference kept */
    g_SpoofBackup.IsActive = TRUE;
    return STATUS_SUCCESS;
}

/* ------------------------------------------------------------------ */
NTSTATUS
RestoreDriverObject (__in PDRIVER_OBJECT SelfDriverObject)
{
    PKLDR_DATA_TABLE_ENTRY selfLdr;
    PDRIVER_OBJECT target;

    PAGED_CODE();

    if (!g_SpoofBackup.IsActive)
        return STATUS_UNSUCCESSFUL;

    /* 1: LDR first, located through the SAVED section pointer (the live
     * DriverSection currently points at the target's LDR entry). */
    if (g_SpoofBackup.LdrSpoofActive) {
        selfLdr = (PKLDR_DATA_TABLE_ENTRY)
                      g_SpoofBackup.OriginalDriverSection;
        if (selfLdr) {
            selfLdr->DllBase = g_SpoofBackup.OriginalLdrDllBase;
            selfLdr->EntryPoint = g_SpoofBackup.OriginalLdrEntryPoint;
            selfLdr->SizeOfImage = g_SpoofBackup.OriginalLdrSizeOfImage;
            selfLdr->FullDllName = g_SpoofBackup.OriginalLdrFullDllName;
            selfLdr->BaseDllName = g_SpoofBackup.OriginalLdrBaseDllName;
        }
        g_SpoofBackup.LdrSpoofActive = FALSE;
    }

    /* 2: the RAW DriverName keeps the I/O manager's original Buffer
     * pointer - a stack deep-copy would dangle here. */
    SelfDriverObject->DriverName = g_SpoofBackup.OriginalDriverNameRaw;

    /* 3 */
    SelfDriverObject->DriverStart = g_SpoofBackup.OriginalDriverStart;
    SelfDriverObject->DriverSize = g_SpoofBackup.OriginalDriverSize;
    SelfDriverObject->DriverSection = g_SpoofBackup.OriginalDriverSection;
    SelfDriverObject->DriverInit = g_SpoofBackup.OriginalDriverInit;

    /* 4 */
    target = g_SpoofBackup.TargetDriverObject;
    g_SpoofBackup.IsActive = FALSE;
    g_SpoofBackup.TargetDriverObject = NULL;
    if (target)
        ObDereferenceObject(target);

    return STATUS_SUCCESS;
}
