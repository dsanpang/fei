/* SPDX-License-Identifier: GPL-2.0 */
/*
 * DriverObjectSpoof.h - _DRIVER_OBJECT clone spoofing.
 */
#ifndef LAYEREDGUARD_DRIVEROBJECTSPOOF_H
#define LAYEREDGUARD_DRIVEROBJECTSPOOF_H

#include "Driver.h"

/* ------------------------------------------------------------------ */
/* KLDR_DATA_TABLE_ENTRY prefix (§11.3): DriverSection points here.
 * Layout through BaseDllName is stable from Win7 SP1 to Win11 24H2.
 * Every intermediate field is declared - "..." placeholders are
 * forbidden or DllBase would sit right after InLoadOrderLinks and both
 * the write-back path and LDR spoofing would corrupt memory. */
typedef struct _KLDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;    /* MUST NEVER modify the pointers */
    PVOID      ExceptionTable;
    ULONG      ExceptionTableSize;
    PVOID      GpValue;
    PVOID      NonPagedDebugInfo;
    PVOID      DllBase;             /* x64 +0x030 / x86 +0x018 */
    PVOID      EntryPoint;
    ULONG      SizeOfImage;
    UNICODE_STRING FullDllName;     /* x64 +0x048 / x86 +0x024 */
    UNICODE_STRING BaseDllName;     /* x64 +0x058 / x86 +0x02C */
} KLDR_DATA_TABLE_ENTRY, *PKLDR_DATA_TABLE_ENTRY;

typedef struct {
    UNICODE_STRING TargetDriverName;  /* L"\\Driver\\Null" */
    BOOLEAN SpoofDriverName;
    BOOLEAN SpoofDriverStart;
    BOOLEAN SpoofDriverSize;
    BOOLEAN SpoofDriverSection;
    BOOLEAN SpoofDriverInit;
    BOOLEAN SpoofLdrEntry;   /* deceives PsLoadedModuleList walkers */
} SPOOF_CONFIG;

typedef struct {
    BOOLEAN IsActive;
    UNICODE_STRING OriginalDriverNameRaw;  /* original Buffer pointer */
    WCHAR OriginalNameBuffer[256];         /* deep copy, debug only */
    PVOID OriginalDriverStart;
    ULONG OriginalDriverSize;
    PVOID OriginalDriverSection;
    PDRIVER_INITIALIZE OriginalDriverInit;
    BOOLEAN LdrSpoofActive;
    PVOID OriginalLdrDllBase;
    ULONG OriginalLdrSizeOfImage;
    PVOID OriginalLdrEntryPoint;
    UNICODE_STRING OriginalLdrFullDllName;
    UNICODE_STRING OriginalLdrBaseDllName;
    PDRIVER_OBJECT TargetDriverObject;     /* reference held until restore */
} SPOOF_BACKUP;

NTSTATUS SpoofDriverObject (__in PDRIVER_OBJECT SelfDriverObject);
NTSTATUS RestoreDriverObject (__in PDRIVER_OBJECT SelfDriverObject);

#endif /* LAYEREDGUARD_DRIVEROBJECTSPOOF_H */
