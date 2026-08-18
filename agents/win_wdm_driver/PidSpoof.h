/* SPDX-License-Identifier: GPL-2.0 */
/*
 * PidSpoof.h - EPROCESS.UniqueProcessId spoofing.
 */
#ifndef LAYEREDGUARD_PIDSPOOF_H
#define LAYEREDGUARD_PIDSPOOF_H

#include "Driver.h"

NTSTATUS InitPidSpoof (VOID);
VOID     CleanupPidSpoof (VOID);
NTSTATUS SpoofSinglePid (__in ULONG Pid);
VOID     PidSpoofRestoreAll (VOID);

#endif /* LAYEREDGUARD_PIDSPOOF_H */
