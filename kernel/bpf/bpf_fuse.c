/*
 * FUSE BPF program type
 * Copyright (C) 2021 Google LLC
 *
 * This program can be distributed under the terms of the GNU GPL.
 */

#include <linux/bpf.h>
#include <linux/filter.h>
#include <uapi/linux/fuse.h>

#define FUSE_IN_ARG_VALUE(i)	offsetof(struct fuse_bpf_args, in_args[i].value)
#define FUSE_OUT_ARG_VALUE(i)	offsetof(struct fuse_bpf_args, out_args[i].value)

static bool fuse_prog_is_valid_access(int off, int size,
				      enum bpf_access_type type,
				      enum bpf_reg_type *reg_type)
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
		*reg_type = PTR_TO_MEM;
		return true;
	case FUSE_OUT_ARG_VALUE(0):
	case FUSE_OUT_ARG_VALUE(1):
	case FUSE_OUT_ARG_VALUE(2):
		*reg_type = PTR_TO_MEM;
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

	*reg_type = UNKNOWN_VALUE;
	return true;
}

static const struct bpf_func_proto *
fuse_prog_func_proto(enum bpf_func_id func_id)
{
	switch (func_id) {
	case BPF_FUNC_trace_printk:
		return bpf_get_trace_printk_proto();

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
