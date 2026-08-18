/* SPDX-License-Identifier: GPL-2.0 */
/*
 * RegConfig.h - registry polling hub for LayeredGuard.
 */
#ifndef LAYEREDGUARD_REGCONFIG_H
#define LAYEREDGUARD_REGCONFIG_H

#include "Driver.h"

/* Registry config path (kernel format). The full path is concatenated at
 * runtime from RegistryPath + L"\\Config": hard-coding the service name a
 * second time in a header is forbidden (spec §0.1). */
#define CONFIG_REG_PATH_SUFFIX  L"\\Config"

#define POLL_INTERVAL_SEC    5
#define VALUE_COUNT          5
#define MAX_VALUE_BYTES      4096
#define POOL_TAG             'CfgX'

/* Five REG_SZ value names */
#define VAL_PROCESS   L"Process"    /* process image names, ;-separated */
#define VAL_IP        L"IP"         /* remote IPv4, ;-separated */
#define VAL_PORT      L"Port"       /* local ports, ;-separated */
#define VAL_PATH      L"Path"       /* file/directory Win32 paths, ;-separated */
#define VAL_REGPATH   L"RegPath"    /* registry paths, ;-separated */

typedef enum {
    ValProcess = 0, ValIP, ValPort, ValPath, ValRegPath
} VALUE_TYPE;

#endif /* LAYEREDGUARD_REGCONFIG_H */
