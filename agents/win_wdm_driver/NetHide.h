/* SPDX-License-Identifier: GPL-2.0 */
/*
 * NetHide.h - nsiproxy IRP hook and NSI TCP table filtering.
 */
#ifndef LAYEREDGUARD_NETHIDE_H
#define LAYEREDGUARD_NETHIDE_H

#include "Driver.h"

typedef enum {
    NetHideFilterByLocalIp,
    NetHideFilterByLocalPort,
    NetHideFilterByRemoteIp,
    NetHideFilterByPid
} NET_HIDE_FILTER_TYPE;

typedef struct {
    NET_HIDE_FILTER_TYPE Type;
    union {
        ULONG LocalIp;
        USHORT LocalPort;
        ULONG RemoteIp;
        ULONG Pid;
    };
    CHAR ProcessName[16];   /* reserved; unused by RegConfig */
} NET_HIDE_FILTER_RULE;

#endif /* LAYEREDGUARD_NETHIDE_H */
