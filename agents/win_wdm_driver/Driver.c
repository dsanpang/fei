/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Driver.c - entry, unload and submodule orchestration for LayeredGuard.
 *
 * Init order (strict, see spec §3): PidSpoof, PathHide, NetHide, RegHide,
 * WriteBack, RegConfig, Spoof. WriteBack MUST run before Spoof because
 * spoofing overwrites DriverSection, after which the real driver path is
 * unreadable; Spoof is therefore the last step.
 */
#include "Driver.h"
#include "RegConfig.h"
#include "PidSpoof.h"
#include "NetHide.h"
#include "PathHide.h"
#include "RegHide.h"
#include "WriteBack.h"
#include "DriverObjectSpoof.h"

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, DriverUnload)
#endif

NTSTATUS
DriverEntry (
    __in struct _DRIVER_OBJECT *DriverObject,
    __in PUNICODE_STRING RegistryPath
    )
{
    NTSTATUS status;
    NTSTATUS finalStatus = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(RegistryPath);

    DriverObject->DriverUnload = DriverUnload;

    /* 1: EPROCESS.UniqueProcessId offset detection */
    status = InitPidSpoof();
    if (!NT_SUCCESS(status)) {
        KdPrint(("LayeredGuard: InitPidSpoof failed 0x%08X\n", status));
    }

    /* 2: MiniFilter Instances key under the REAL service name + register */
    status = InitPathHide(DriverObject, RegistryPath);
    if (!NT_SUCCESS(status)) {
        KdPrint(("LayeredGuard: InitPathHide failed 0x%08X\n", status));
    }

    /* 3: nsiproxy DeviceControl hook */
    status = NetHide_Init();
    if (!NT_SUCCESS(status)) {
        KdPrint(("LayeredGuard: NetHide_Init failed 0x%08X\n", status));
    }

    /* 4: CmRegisterCallbackEx */
    status = RegHide_Init(DriverObject);
    if (!NT_SUCCESS(status)) {
        KdPrint(("LayeredGuard: RegHide_Init failed 0x%08X\n", status));
    }

    /* 5: cache the .sys image + shutdown notification (before Spoof:
     * afterwards DriverSection points somewhere else entirely) */
    status = Writeback_Init(DriverObject);
    if (!NT_SUCCESS(status)) {
        KdPrint(("LayeredGuard: Writeback_Init failed 0x%08X\n", status));
    }

    /* 6: registry polling thread; config path built from RegistryPath */
    status = RegConfig_StartPolling(RegistryPath);
    if (!NT_SUCCESS(status)) {
        KdPrint(("LayeredGuard: RegConfig_StartPolling failed 0x%08X\n", status));
    }

    /* 7: clone-spoof the DriverObject last (release builds only) */
#if !DEBUG_SKIP_SPOOF
    status = SpoofDriverObject(DriverObject);
    if (!NT_SUCCESS(status)) {
        KdPrint(("LayeredGuard: SpoofDriverObject failed 0x%08X\n", status));
    }
#endif

    /* Submodule failures are non-fatal by design: the driver always loads. */
    return finalStatus;
}

VOID
DriverUnload (
    __in struct _DRIVER_OBJECT *DriverObject
    )
{
    PAGED_CODE();

    /* 1: undo the spoof first so later cleanup sees real pointers */
#if !DEBUG_SKIP_SPOOF
    RestoreDriverObject(DriverObject);
#endif

    /* 2: stop the polling thread before tearing anything it feeds */
    RegConfig_StopPolling();

    /* 3..7: reverse dependency order */
    NetHide_Cleanup();
    CleanupPathHide();
    CleanupPidSpoof();
    RegHide_Cleanup();
    Writeback_Cleanup(DriverObject);
}
