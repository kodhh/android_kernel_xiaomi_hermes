/*
 * FUSE BPF program type
 * Copyright (C) 2021 Google LLC
 *
 * This program can be distributed under the terms of the GNU GPL.
 */

#include <linux/bpf.h>
#include <linux/filter.h>
#include <uapi/linux/fuse.h>

static bool fuse_prog_is_valid_access(int off, int size,
				      enum bpf_access_type type,
				      enum bpf_reg_type *reg_type)
{
	if (off < 0 || off >= sizeof(struct fuse_bpf_args))
		return false;

	if (type == BPF_WRITE) {
		switch (off) {
		case offsetof(struct fuse_bpf_args, error_in):
		case offsetof(struct fuse_bpf_args, flags):
			break;
		default:
			return false;
		}
	}

	*reg_type = PTR_TO_CTX;
	return true;
}

static const struct bpf_func_proto *
fuse_prog_func_proto(enum bpf_func_id func_id)
{
	return NULL;
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
