/* SPDX-License-Identifier: GPL-2.0 */
/*
 * WriteBack.h - driver-file cache and shutdown write-back.
 */
#ifndef LAYEREDGUARD_WRITEBACK_H
#define LAYEREDGUARD_WRITEBACK_H

#include "Driver.h"

NTSTATUS Writeback_Init (__in PDRIVER_OBJECT DriverObject);
VOID     Writeback_Cleanup (__in PDRIVER_OBJECT DriverObject);

#endif /* LAYEREDGUARD_WRITEBACK_H */
