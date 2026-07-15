/*
 * FUSE BPF program type
 * Copyright (C) 2021 Google LLC
 *
 * This program can be distributed under the terms of the GNU GPL.
 */

#include <linux/bpf.h>
#include <linux/ctype.h>
#include <linux/filter.h>
#include <linux/printk.h>
#include <linux/uaccess.h>
#include <uapi/linux/fuse.h>

#ifdef CONFIG_BPF_EVENTS
/* Use standard bpf_trace_printk from kernel/trace/bpf_trace.c */
extern const struct bpf_func_proto *bpf_get_trace_printk_proto(void);
#else
/* CONFIG_BPF_EVENTS not enabled, provide our own minimal trace_printk */
extern void trace_printk_init_buffers(void);
extern int __trace_printk(unsigned long ip, const char *fmt, ...);
#endif

#define FUSE_IN_ARG_VALUE(i)	offsetof(struct fuse_bpf_args, in_args[i].value)
#define FUSE_OUT_ARG_VALUE(i)	offsetof(struct fuse_bpf_args, out_args[i].value)

#ifndef CONFIG_BPF_EVENTS
/*
 * Minimal bpf_trace_printk — no dependency on CONFIG_BPF_EVENTS.
 * Limited to 3 args; only %d %u %x %ld %lu %lx %lld %llu %llx %p %s.
 */
BPF_CALL_5(fuse_bpf_trace_printk, char *, fmt, u32, fmt_size, u64, arg1,
	   u64, arg2, u64, arg3)
{
	bool str_seen = false;
	int mod[3] = {};
	char buf[64];
	int fmt_cnt = 0;
	u64 unsafe_addr = 0;
	int i;

	if (fmt[--fmt_size] != 0)
		return -EINVAL;

	for (i = 0; i < fmt_size; i++) {
		if ((!isprint(fmt[i]) && !isspace(fmt[i])) || !isascii(fmt[i]))
			return -EINVAL;

		if (fmt[i] != '%')
			continue;

		if (fmt_cnt >= 3)
			return -EINVAL;

		i++;
		if (fmt[i] == 'l') {
			mod[fmt_cnt]++;
			i++;
		} else if (fmt[i] == 'p' || fmt[i] == 's') {
			mod[fmt_cnt]++;
			i++;
			if (!isspace(fmt[i]) && !ispunct(fmt[i]) && fmt[i] != 0)
				return -EINVAL;
			fmt_cnt++;
			if (fmt[i - 1] == 's') {
				if (str_seen)
					return -EINVAL;
				str_seen = true;
				switch (fmt_cnt) {
				case 1:
					unsafe_addr = arg1;
					arg1 = (long)buf;
					break;
				case 2:
					unsafe_addr = arg2;
					arg2 = (long)buf;
					break;
				case 3:
					unsafe_addr = arg3;
					arg3 = (long)buf;
					break;
				}
				buf[0] = 0;
				strncpy_from_unsafe(buf,
						    (void *)(long)unsafe_addr,
						    sizeof(buf));
			}
			continue;
		}

		if (fmt[i] == 'l') {
			mod[fmt_cnt]++;
			i++;
		}

		if (fmt[i] != 'd' && fmt[i] != 'u' && fmt[i] != 'x')
			return -EINVAL;
		fmt_cnt++;
	}

#define __BPF_FUSE_TP(...)						\
	__trace_printk(0, fmt, ##__VA_ARGS__)

#define __BPF_FUSE_ARG1_TP(...)						\
	((mod[0] == 2 || (mod[0] == 1 && __BITS_PER_LONG == 64))	\
	  ? __BPF_FUSE_TP(arg1, ##__VA_ARGS__)				\
	  : ((mod[0] == 1 || (mod[0] == 0 && __BITS_PER_LONG == 32))	\
	      ? __BPF_FUSE_TP((long)arg1, ##__VA_ARGS__)		\
	      : __BPF_FUSE_TP((u32)arg1, ##__VA_ARGS__)))

#define __BPF_FUSE_ARG2_TP(...)						\
	((mod[1] == 2 || (mod[1] == 1 && __BITS_PER_LONG == 64))	\
	  ? __BPF_FUSE_ARG1_TP(arg2, ##__VA_ARGS__)			\
	  : ((mod[1] == 1 || (mod[1] == 0 && __BITS_PER_LONG == 32))	\
	      ? __BPF_FUSE_ARG1_TP((long)arg2, ##__VA_ARGS__)		\
	      : __BPF_FUSE_ARG1_TP((u32)arg2, ##__VA_ARGS__)))

#define __BPF_FUSE_ARG3_TP(...)						\
	((mod[2] == 2 || (mod[2] == 1 && __BITS_PER_LONG == 64))	\
	  ? __BPF_FUSE_ARG2_TP(arg3, ##__VA_ARGS__)			\
	  : ((mod[2] == 1 || (mod[2] == 0 && __BITS_PER_LONG == 32))	\
	      ? __BPF_FUSE_ARG2_TP((long)arg3, ##__VA_ARGS__)		\
	      : __BPF_FUSE_ARG2_TP((u32)arg3, ##__VA_ARGS__)))

	__BPF_FUSE_ARG3_TP();
	return 0;
}

static const struct bpf_func_proto fuse_bpf_trace_printk_proto = {
	.func		= fuse_bpf_trace_printk,
	.gpl_only	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_MEM,
	.arg2_type	= ARG_CONST_SIZE,
};
#endif /* !CONFIG_BPF_EVENTS */

static bool fuse_prog_is_valid_access(int off, int size,
				      enum bpf_access_type type,
				      const struct bpf_prog *prog,
				      struct bpf_insn_access_aux *info)
{
	if (off < 0 || off >= sizeof(struct fuse_bpf_args))
		return false;

	/* Pointers to backing data buffers — BPF may dereference them */
	switch (off) {
	case FUSE_IN_ARG_VALUE(0):
	case FUSE_IN_ARG_VALUE(1):
	case FUSE_IN_ARG_VALUE(2):
	case FUSE_IN_ARG_VALUE(3):
	case FUSE_IN_ARG_VALUE(4):
		if (type == BPF_WRITE)
			return false;
		info->reg_type = PTR_TO_RDONLY_BUF;
		return true;
	case FUSE_OUT_ARG_VALUE(0):
	case FUSE_OUT_ARG_VALUE(1):
	case FUSE_OUT_ARG_VALUE(2):
		info->reg_type = PTR_TO_RDWR_BUF;
		return true;
	}

	if (type == BPF_WRITE) {
		switch (off) {
		case offsetof(struct fuse_bpf_args, error_in):
		case offsetof(struct fuse_bpf_args, flags):
			break;
		default:
			return false;
		}
	}

	info->reg_type = UNKNOWN_VALUE;
	return true;
}

static const struct bpf_func_proto *
fuse_prog_func_proto(enum bpf_func_id func_id, const struct bpf_prog *prog)
{
	switch (func_id) {
	case BPF_FUNC_trace_printk:
#ifdef CONFIG_BPF_EVENTS
		return bpf_get_trace_printk_proto();
#else
		return &fuse_bpf_trace_printk_proto;
#endif

	case BPF_FUNC_get_current_uid_gid:
		return &bpf_get_current_uid_gid_proto;

	case BPF_FUNC_get_current_pid_tgid:
		return &bpf_get_current_pid_tgid_proto;

	case BPF_FUNC_map_lookup_elem:
		return &bpf_map_lookup_elem_proto;

	case BPF_FUNC_map_update_elem:
		return &bpf_map_update_elem_proto;

	default:
		return NULL;
	}
}

static const struct bpf_verifier_ops fuse_verifier_ops = {
	.get_func_proto  = fuse_prog_func_proto,
	.is_valid_access = fuse_prog_is_valid_access,
};

static struct bpf_prog_type_list fuse_prog_type = {
	.ops	= &fuse_verifier_ops,
	.type	= BPF_PROG_TYPE_FUSE,
};

static int __init fuse_bpf_init(void)
{
	bpf_register_prog_type(&fuse_prog_type);
	return 0;
}

late_initcall(fuse_bpf_init);
