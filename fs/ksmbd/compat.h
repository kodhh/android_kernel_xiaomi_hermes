/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef __KSMBD_COMPAT_H
#define __KSMBD_COMPAT_H

#include <linux/version.h>
#include <linux/time64.h>

/*
 * GENL_DONT_VALIDATE_STRICT and GENL_DONT_VALIDATE_DUMP were added
 * in kernel 5.2. On older kernels, leave validate unset (0).
 */
#ifndef GENL_DONT_VALIDATE_STRICT
#define GENL_DONT_VALIDATE_STRICT 0
#endif

#ifndef GENL_DONT_VALIDATE_DUMP
#define GENL_DONT_VALIDATE_DUMP 0
#endif

/*
 * Prior to kernel 4.21, struct genl_family did not have .ops and .n_ops
 * fields. Use genl_register_family_with_ops() instead.
 */
#ifndef HAVE_GENL_FAMILY_OPS
#define genl_register_family(family) \
	genl_register_family_with_ops(family, family->ops, family->n_ops)
#endif

#endif /* __KSMBD_COMPAT_H */
