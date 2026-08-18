/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Driver.h - shared declarations for the LayeredGuard WDM driver.
 *
 * Unified header policy: every module includes <ntifs.h> ONLY (it is a
 * superset of ntddk.h); pulling ntddk.h in as well collides PEPROCESS
 * typedefs (C2371).
 */
#ifndef LAYEREDGUARD_DRIVER_H
#define LAYEREDGUARD_DRIVER_H

#include <ntifs.h>

/* ------------------------------------------------------------------ */
/* Debug switch                                                        */
/* ------------------------------------------------------------------ */
#ifdef DBG
#define DEBUG_SKIP_SPOOF  1   /* Debug: skip spoofing, convenient for WinDbg */
#else
#define DEBUG_SKIP_SPOOF  0   /* Release: perform spoofing */
#endif

#define TARGET_SPOOF_DRIVER L"\\Driver\\Null"

/* PID spoofing constants */
#define SPOOF_TARGET_PID  4    /* spoof as the System process PID */
#define MAX_SPOOF_PIDS    64   /* spoof table capacity */

/* RegHide constants */
#define REGHIDE_MAX_ENTRIES   64
#define REGHIDE_MAX_PATH      512
#define REGHIDE_MAX_REENTRANT 64

/* ------------------------------------------------------------------ */
/* Undocumented kernel exports (shared by NetHide and DriverObjectSpoof;
 * one declaration only - two copies with drifting parameter types have
 * historically caused silent arg corruption). */
/* ------------------------------------------------------------------ */
extern POBJECT_TYPE *IoDriverObjectType;

NTKERNELAPI
NTSTATUS
ObReferenceObjectByName (
    __in PUNICODE_STRING ObjectName,
    __in ULONG Attributes,
    __in_opt PACCESS_STATE AccessState,
    __in_opt ACCESS_MASK DesiredAccess,
    __in POBJECT_TYPE ObjectType,
    __in KPROCESSOR_MODE AccessMode,
    __inout_opt PVOID ParseContext,
    __out PVOID *Object
    );

/* ------------------------------------------------------------------ */
/* Submodule orchestration (Driver.c)                                  */
/* ------------------------------------------------------------------ */
NTSTATUS
DriverEntry (
    __in struct _DRIVER_OBJECT *DriverObject,
    __in PUNICODE_STRING RegistryPath
    );

VOID
DriverUnload (
    __in struct _DRIVER_OBJECT *DriverObject
    );

/* RegConfig */
NTSTATUS RegConfig_StartPolling (__in PUNICODE_STRING RegistryPath);
VOID     RegConfig_StopPolling (VOID);

/* PidSpoof */
NTSTATUS InitPidSpoof (VOID);
VOID     CleanupPidSpoof (VOID);
NTSTATUS SpoofSinglePid (__in ULONG Pid);
VOID     PidSpoofRestoreAll (VOID);

/* NetHide */
NTSTATUS NetHide_Init (VOID);
VOID     NetHide_Cleanup (VOID);
VOID     NetHide_ResetRules (VOID);
NTSTATUS NetHide_AddByLocalIp (__in ULONG LocalIp);
NTSTATUS NetHide_AddByLocalPort (__in USHORT LocalPort);
NTSTATUS NetHide_AddByRemoteIp (__in ULONG RemoteIp);
NTSTATUS NetHide_AddByPid (__in ULONG Pid);

/* PathHide */
NTSTATUS InitPathHide (__in PDRIVER_OBJECT DriverObject,
                       __in PUNICODE_STRING RegistryPath);
VOID     CleanupPathHide (VOID);
VOID     PathHide_BeginUpdate (VOID);
NTSTATUS PathHide_AddPath (__in PCWSTR Win32Path, __in ULONG PathLength);
VOID     PathHide_EndUpdate (VOID);

/* RegHide */
NTSTATUS RegHide_Init (__in PDRIVER_OBJECT DriverObject);
VOID     RegHide_Cleanup (VOID);
VOID     RegHide_BeginUpdate (VOID);
NTSTATUS RegHide_AddKey (__in PCWSTR KernelPath);
VOID     RegHide_EndUpdate (VOID);
VOID     RegHide_MarkReentrant (VOID);
VOID     RegHide_UnmarkReentrant (VOID);

/* WriteBack */
NTSTATUS Writeback_Init (__in PDRIVER_OBJECT DriverObject);
VOID     Writeback_Cleanup (__in PDRIVER_OBJECT DriverObject);

/* DriverObjectSpoof */
NTSTATUS SpoofDriverObject (__in PDRIVER_OBJECT SelfDriverObject);
NTSTATUS RestoreDriverObject (__in PDRIVER_OBJECT SelfDriverObject);

#endif /* LAYEREDGUARD_DRIVER_H */
