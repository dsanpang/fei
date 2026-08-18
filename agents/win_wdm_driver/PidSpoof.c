/* SPDX-License-Identifier: GPL-2.0 */
/*
 * PidSpoof.c - rewrite EPROCESS.UniqueProcessId of every matched process
 * to SPOOF_TARGET_PID (4, the System process).
 *
 * All EPROCESS field access goes through the pointer-width PULONG_PTR:
 * writing through PULONG alone leaves the high 4 bytes as garbage on x64.
 */
#include "PidSpoof.h"

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, InitPidSpoof)
#pragma alloc_text(PAGE, CleanupPidSpoof)
#pragma alloc_text(PAGE, PidSpoofRestoreAll)
#endif

#define PIDPOOL_TAG 'PidS'

typedef struct {
    PEPROCESS Process;      /* reference held via PsLookupProcessByProcessId */
    ULONG     OriginalPid;
    BOOLEAN   Active;
} SPOOF_ENTRY;

static SPOOF_ENTRY g_SpoofTable[MAX_SPOOF_PIDS];
static FAST_MUTEX  g_SpoofMutex;
static ULONG       g_UniqueProcessIdOffset;

/* ------------------------------------------------------------------ */
/* Offset detection (spec §6.2)                                        */
/* ------------------------------------------------------------------ */
static ULONG
PidSpoof_DetectUniqueProcessIdOffset (VOID)
{
    ULONG major = 0, minor = 0, build = 0;

    PsGetVersion(&major, &minor, &build, NULL);

#ifdef _WIN64
    if (major == 6 && minor == 1)
        return 0x180;                       /* Win7 */
    if (major == 6 && (minor == 2 || minor == 3))
        return 0x2E0;                       /* Win8 / 8.1 */
    if (major == 10) {
        if (build <= 14393)  return 0x2E8;  /* 1507..1607 */
        if (build <= 17763)  return 0x2E0;  /* 1709..1809 */
        if (build <= 18363)  return 0x2E8;  /* 1903..1909 */
        if (build <= 22631)  return 0x440;  /* 2004..23H2 */
        return 0x1D0;                       /* Win11 24H2+ */
    }
    return 0x180;                           /* unrecognized: x64 fallback */
#else
    if (major == 10 && build >= 19041)
        return 0xE4;
    return 0xB4;                            /* x86 fallback incl. old builds */
#endif
}

NTSTATUS
InitPidSpoof (VOID)
{
    ExInitializeFastMutex(&g_SpoofMutex);
    RtlZeroMemory(g_SpoofTable, sizeof(g_SpoofTable));

    g_UniqueProcessIdOffset = PidSpoof_DetectUniqueProcessIdOffset();
    KdPrint(("LayeredGuard: UniqueProcessId offset 0x%X\n",
             g_UniqueProcessIdOffset));
    return STATUS_SUCCESS;
}

/* ------------------------------------------------------------------ */
/* Spoof / restore                                                     */
/* ------------------------------------------------------------------ */
NTSTATUS
SpoofSinglePid (__in ULONG Pid)
{
    NTSTATUS status;
    PEPROCESS process = NULL;
    PULONG_PTR pPid;
    ULONG i;

#if DEBUG_SKIP_SPOOF
    UNREFERENCED_PARAMETER(Pid);
    return STATUS_SUCCESS;
#endif

    if (Pid == 0 || Pid == 4)
        return STATUS_INVALID_PARAMETER;

    ExAcquireFastMutex(&g_SpoofMutex);

    /* Built-in dedup: an already-spoofed original PID is skipped. */
    for (i = 0; i < MAX_SPOOF_PIDS; i++) {
        if (g_SpoofTable[i].Active && g_SpoofTable[i].OriginalPid == Pid) {
            ExReleaseFastMutex(&g_SpoofMutex);
            return STATUS_SUCCESS;
        }
    }

    for (i = 0; i < MAX_SPOOF_PIDS; i++) {
        if (!g_SpoofTable[i].Active)
            break;
    }
    if (i == MAX_SPOOF_PIDS) {
        ExReleaseFastMutex(&g_SpoofMutex);
        KdPrint(("LayeredGuard: spoof table full, pid %u skipped\n", Pid));
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)Pid, &process);
    if (!NT_SUCCESS(status)) {
        ExReleaseFastMutex(&g_SpoofMutex);
        return status;
    }

    pPid = (PULONG_PTR)((PUCHAR)process + g_UniqueProcessIdOffset);
    *pPid = (ULONG_PTR)SPOOF_TARGET_PID;

    g_SpoofTable[i].Process = process;      /* keeps the reference */
    g_SpoofTable[i].OriginalPid = Pid;
    g_SpoofTable[i].Active = TRUE;

    ExReleaseFastMutex(&g_SpoofMutex);
    return STATUS_SUCCESS;
}

VOID
PidSpoofRestoreAll (VOID)
{
    ULONG i;

    PAGED_CODE();

    ExAcquireFastMutex(&g_SpoofMutex);

    for (i = 0; i < MAX_SPOOF_PIDS; i++) {
        PULONG_PTR pPid;

        if (!g_SpoofTable[i].Active)
            continue;

        pPid = (PULONG_PTR)((PUCHAR)g_SpoofTable[i].Process +
                            g_UniqueProcessIdOffset);
        *pPid = (ULONG_PTR)g_SpoofTable[i].OriginalPid;

        ObDereferenceObject(g_SpoofTable[i].Process);
        g_SpoofTable[i].Process = NULL;
        g_SpoofTable[i].OriginalPid = 0;
        g_SpoofTable[i].Active = FALSE;
    }

    ExReleaseFastMutex(&g_SpoofMutex);
}

VOID
CleanupPidSpoof (VOID)
{
    PAGED_CODE();
    PidSpoofRestoreAll();
}
