/* SPDX-License-Identifier: GPL-2.0 */
/*
 * RegHide.h - CmRegisterCallbackEx registry key hiding.
 */
#ifndef LAYEREDGUARD_REGHIDE_H
#define LAYEREDGUARD_REGHIDE_H

#include "Driver.h"

NTSTATUS RegHide_Init (__in PDRIVER_OBJECT DriverObject);
VOID     RegHide_Cleanup (VOID);
VOID     RegHide_BeginUpdate (VOID);
NTSTATUS RegHide_AddKey (__in PCWSTR KernelPath);
VOID     RegHide_EndUpdate (VOID);
VOID     RegHide_MarkReentrant (VOID);
VOID     RegHide_UnmarkReentrant (VOID);

/* Shared user-prefix -> kernel-prefix conversion (also used by RegConfig's
 * ValidateRegPath; single prefix table for both, spec §9.4). */
NTSTATUS ConvertToKernelPath (__in PCWSTR UserPath,
                              __out PWCHAR KernelBuf,
                              __in ULONG KernelBufCch);

#endif /* LAYEREDGUARD_REGHIDE_H */
