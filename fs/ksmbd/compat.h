/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef __KSMBD_COMPAT_H
#define __KSMBD_COMPAT_H

#include <linux/version.h>
#include <linux/time64.h>
#include <linux/fs.h>
#include <linux/backing-dev.h>

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
 * get_acl() was not a global helper in 3.10 - call i_op->get_acl directly.
 */
#ifndef get_acl
static inline struct posix_acl *get_acl(struct inode *inode, int type)
{
	if (inode->i_op->get_acl)
		return inode->i_op->get_acl(inode, type);
	return NULL;
}
#endif

/*
 * inode_to_bdi() was added later. In 3.10, use inode->i_sb->s_bdi,
 * with a special case for bdev filesystems.
 */
#ifndef inode_to_bdi
static inline struct backing_dev_info *inode_to_bdi(struct inode *inode)
{
	struct super_block *sb = inode->i_sb;

	if (strcmp(sb->s_type->name, "bdev") == 0)
		return inode->i_mapping->backing_dev_info;
	return sb->s_bdi;
}
#endif

/*
 * __ATTR_RO/WO/RW macros were added in later kernels.
 */
#ifndef __ATTR_WO
#define __ATTR_WO(_name) { \
	.attr	= { .name = __stringify(_name), .mode = 0200 }, \
	.store	= _name##_store,				\
}
#endif

#ifndef __ATTR_RW
#define __ATTR_RW(_name) { \
	.attr	= { .name = __stringify(_name), .mode = 0644 }, \
	.show	= _name##_show,					\
	.store	= _name##_store,				\
}
#endif

/*
 * CLASS_ATTR_RO/WO/RW were added in later kernels.
 */
#ifndef CLASS_ATTR_RO
#define CLASS_ATTR_RO(_name) CLASS_ATTR(_name, S_IRUGO, _name##_show, NULL)
#endif

#ifndef CLASS_ATTR_WO
#define CLASS_ATTR_WO(_name) CLASS_ATTR(_name, S_IWUSR, NULL, _name##_store)
#endif

#ifndef CLASS_ATTR_RW
#define CLASS_ATTR_RW(_name) CLASS_ATTR(_name, S_IRUGO | S_IWUSR, _name##_show, _name##_store)
#endif

/*
 * vfs_fallocate() was not available in 3.10 - call f_op->fallocate directly.
 */
#ifndef vfs_fallocate
static inline long vfs_fallocate(struct file *file, int mode, loff_t offset,
				 loff_t len)
{
	if (!file->f_op->fallocate)
		return -EOPNOTSUPP;
	return file->f_op->fallocate(file, mode, offset, len);
}
#endif

/*
 * MODULE_SOFTDEP was added in 3.12.
 */
#ifndef MODULE_SOFTDEP
#define MODULE_SOFTDEP(_softdep) MODULE_INFO(softdep, _softdep)
#endif

/*
 * d_is_negative / d_is_symlink - 4.6+ dentry helpers.
 * In 3.10, check d_inode directly.
 */
#ifndef d_is_negative
#define d_is_negative(d)		((d)->d_inode == NULL)
#endif

#ifndef d_is_symlink
#define d_is_symlink(d)			((d)->d_inode && S_ISLNK((d)->d_inode->i_mode))
#endif

#endif /* __KSMBD_COMPAT_H */
