/* SPDX-License-Identifier: GPL-2.0 */
/*
 * WriteBack.c - cache the driver .sys image at load and write it back on
 * shutdown / hibernate so the on-disk file survives a "delete then
 * shutdown" attempt.
 */
#include <ntstrsafe.h>
#include "WriteBack.h"
#include "DriverObjectSpoof.h"

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, Writeback_Init)
#pragma alloc_text(PAGE, Writeback_Cleanup)
#pragma alloc_text(PAGE, WritebackDriverFile)
#endif

#define WBPOOL_TAG 'WbKb'

static WCHAR       g_DriverPath[512];
static PVOID       g_CachedImage = NULL;
static ULONG       g_CachedSize = 0;
static volatile LONG g_WritebackInProgress = 0;

static PDRIVER_DISPATCH g_OldShutdown = NULL;
static BOOLEAN          g_ShutdownInstalled = FALSE;
static PDEVICE_OBJECT   g_ShutdownDevice = NULL;
static PCALLBACK_OBJECT g_PowerCallbackObject = NULL;
static PVOID            g_PowerCallbackRegistration = NULL;

/* ------------------------------------------------------------------ */
/* Path + cache                                                        */
/* ------------------------------------------------------------------ */
static NTSTATUS
WbGetDriverFilePath (__in PDRIVER_OBJECT DriverObject)
{
    PKLDR_DATA_TABLE_ENTRY ldr;

    ldr = (PKLDR_DATA_TABLE_ENTRY)DriverObject->DriverSection;
    if (!ldr || !ldr->FullDllName.Buffer)
        return STATUS_INVALID_PARAMETER;

    return RtlStringCchCopyW(g_DriverPath, RTL_NUMBER_OF(g_DriverPath),
                             ldr->FullDllName.Buffer);
}

static NTSTATUS
WbCacheDriverFile (VOID)
{
    OBJECT_ATTRIBUTES oa;
    IO_STATUS_BLOCK iosb;
    UNICODE_STRING path;
    HANDLE file = NULL;
    FILE_STANDARD_INFORMATION stdInfo;
    LARGE_INTEGER fileSize;
    NTSTATUS status;

    RtlInitUnicodeString(&path, g_DriverPath);
    InitializeObjectAttributes(&oa, &path,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                               NULL, NULL);

    status = ZwCreateFile(&file, FILE_READ_DATA | SYNCHRONIZE, &oa, &iosb,
                          NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ,
                          FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
    if (!NT_SUCCESS(status))
        return status;

    status = ZwQueryInformationFile(file, &iosb, &stdInfo,
                                    sizeof(stdInfo),
                                    FileStandardInformation);
    if (!NT_SUCCESS(status)) {
        ZwClose(file);
        return status;
    }

    fileSize = stdInfo.EndOfFile;
    if (fileSize.QuadPart == 0 ||
        fileSize.QuadPart > 0xFFFFFFFFLL ||      /* > 4 GB */
        fileSize.QuadPart > (16 * 1024 * 1024)) { /* > 16 MB */
        ZwClose(file);
        return STATUS_FILE_INVALID;
    }

    g_CachedSize = (ULONG)fileSize.QuadPart;
    g_CachedImage = ExAllocatePoolWithTag(NonPagedPool, g_CachedSize,
                                          WBPOOL_TAG);
    if (!g_CachedImage) {
        g_CachedSize = 0;
        ZwClose(file);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    status = ZwReadFile(file, NULL, NULL, NULL, &iosb, g_CachedImage,
                        g_CachedSize, NULL, NULL);
    ZwClose(file);
    if (!NT_SUCCESS(status) || iosb.Information != g_CachedSize) {
        ExFreePoolWithTag(g_CachedImage, WBPOOL_TAG);
        g_CachedImage = NULL;
        g_CachedSize = 0;
        return STATUS_FILE_INVALID;
    }

    KdPrint(("LayeredGuard: cached %u bytes of the driver image\n",
             g_CachedSize));
    return STATUS_SUCCESS;
}

/* ------------------------------------------------------------------ */
/* Write-back                                                          */
/* ------------------------------------------------------------------ */
VOID
WritebackDriverFile (VOID)
{
    OBJECT_ATTRIBUTES oa;
    IO_STATUS_BLOCK iosb;
    UNICODE_STRING path;
    HANDLE file = NULL;
    NTSTATUS status;

    PAGED_CODE();

    if (KeGetCurrentIrql() != PASSIVE_LEVEL)
        return;

    /* single-flight: skip if a write-back is already running */
    if (InterlockedCompareExchange(&g_WritebackInProgress, 1, 0) != 0)
        return;

    if (g_CachedImage && g_CachedSize > 0 && g_DriverPath[0]) {
        RtlInitUnicodeString(&path, g_DriverPath);
        InitializeObjectAttributes(&oa, &path,
                                   OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                                   NULL, NULL);
        status = ZwCreateFile(&file, GENERIC_WRITE | SYNCHRONIZE, &oa,
                              &iosb, NULL, FILE_ATTRIBUTE_NORMAL, 0,
                              FILE_OVERWRITE_IF,
                              FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
        if (NT_SUCCESS(status)) {
            status = ZwWriteFile(file, NULL, NULL, NULL, &iosb,
                                 g_CachedImage, g_CachedSize, NULL, NULL);
            if (!NT_SUCCESS(status))
                KdPrint(("LayeredGuard: write-back failed 0x%08X\n",
                         status));
            ZwClose(file);
        }
    }

    InterlockedExchange(&g_WritebackInProgress, 0);
}

static NTSTATUS
WbShutdownDispatch (__in PDEVICE_OBJECT DeviceObject, __in PIRP Irp)
{
    /* Deliberately does NOT chain to any previous IRP_MJ_SHUTDOWN handler:
     * the saved pointer exists only so Cleanup can restore it. */
    UNREFERENCED_PARAMETER(DeviceObject);

    WritebackDriverFile();

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

static VOID
WbPowerCallback (__in_opt PCALLBACK_OBJECT CallbackObject,
                 __in_opt PVOID Argument1,
                 __in_opt PVOID Argument2)
{
    UNREFERENCED_PARAMETER(CallbackObject);

    /* PO_CB_SYSTEM_STATE_LOCK (3) + argument 0 = about to sleep/hibernate */
    if ((ULONG_PTR)Argument1 == (ULONG_PTR)3 &&
        (ULONG_PTR)Argument2 == 0) {
        WritebackDriverFile();
    }
}

/* ------------------------------------------------------------------ */
/* Init / cleanup                                                      */
/* ------------------------------------------------------------------ */
NTSTATUS
Writeback_Init (__in PDRIVER_OBJECT DriverObject)
{
    UNICODE_STRING callbackName;
    OBJECT_ATTRIBUTES oa;
    UNICODE_STRING deviceName;
    NTSTATUS status;

    /* MUST run before any DriverObject spoof: afterwards DriverSection
     * points at the target's LDR entry and the real path is gone. */
    status = WbGetDriverFilePath(DriverObject);
    if (!NT_SUCCESS(status)) {
        KdPrint(("LayeredGuard: driver path unreadable 0x%08X\n", status));
        return status;
    }

    status = WbCacheDriverFile();
    if (!NT_SUCCESS(status)) {
        KdPrint(("LayeredGuard: driver cache failed 0x%08X\n", status));
        return status;
    }

    /* power callback (non-fatal on failure) */
    RtlInitUnicodeString(&callbackName, L"\\Callback\\PowerState");
    InitializeObjectAttributes(&oa, &callbackName, 0, NULL, NULL);
    status = ExCreateCallback(&g_PowerCallbackObject, &oa, FALSE, TRUE);
    if (NT_SUCCESS(status)) {
        g_PowerCallbackRegistration = ExRegisterCallback(
            g_PowerCallbackObject, WbPowerCallback, NULL);
    } else {
        KdPrint(("LayeredGuard: power callback unavailable 0x%08X\n",
                 status));
    }

    /* shutdown IRP receiver: device without a symbolic link */
    RtlInitUnicodeString(&deviceName, L"\\Device\\LayeredGuardWriteBack");
    status = IoCreateDevice(DriverObject, 0, &deviceName,
                            FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN,
                            FALSE, &g_ShutdownDevice);
    if (!NT_SUCCESS(status)) {
        KdPrint(("LayeredGuard: IoCreateDevice 0x%08X\n", status));
        g_ShutdownDevice = NULL;
        return status;
    }

    IoRegisterShutdownNotification(g_ShutdownDevice);

    /* save the original pointer BEFORE install; write back on Cleanup
     * (NULL if there was no original - spec §0.1) */
    g_OldShutdown = DriverObject->MajorFunction[IRP_MJ_SHUTDOWN];
    DriverObject->MajorFunction[IRP_MJ_SHUTDOWN] = WbShutdownDispatch;
    g_ShutdownInstalled = TRUE;

    return STATUS_SUCCESS;
}

VOID
Writeback_Cleanup (__in PDRIVER_OBJECT DriverObject)
{
    PAGED_CODE();

    if (g_PowerCallbackRegistration) {
        ExUnregisterCallback(g_PowerCallbackRegistration);
        g_PowerCallbackRegistration = NULL;
    }
    if (g_PowerCallbackObject) {
        ObDereferenceObject(g_PowerCallbackObject);
        g_PowerCallbackObject = NULL;
    }

    if (g_ShutdownDevice) {
        IoUnregisterShutdownNotification(g_ShutdownDevice);
    }

    if (g_ShutdownInstalled) {
        DriverObject->MajorFunction[IRP_MJ_SHUTDOWN] = g_OldShutdown;
        g_OldShutdown = NULL;
        g_ShutdownInstalled = FALSE;
    }

    if (g_ShutdownDevice) {
        IoDeleteDevice(g_ShutdownDevice);
        g_ShutdownDevice = NULL;
    }

    if (g_CachedImage) {
        ExFreePoolWithTag(g_CachedImage, WBPOOL_TAG);
        g_CachedImage = NULL;
        g_CachedSize = 0;
    }
}
