/*
 * linux/fs/crypto/hooks.c
 *
 * Copyright (C) 2015, Google, Inc.
 *
 * This contains hooks for encryption operations that can't be inlined.
 */

#include <linux/security.h>
#include <linux/namei.h>
#include "fscrypt_private.h"

/**
 * __fscrypt_prepare_rename - prepare for a rename between possibly-encrypted directories
 * @old_dir: source directory
 * @old_dentry: dentry for source file
 * @new_dir: target directory
 * @new_dentry: dentry for target location (may be negative unless exchanging)
 * @flags: rename flags
 *
 * Return: 0 on success, -ENOKEY if an encryption key is missing, -EPERM if the
 * rename would cause inconsistent encryption policies, or another -errno code
 */
int __fscrypt_prepare_rename(struct inode *old_dir, struct dentry *old_dentry,
			     struct inode *new_dir, struct dentry *new_dentry,
			     unsigned int flags)
{
	int err;

	err = fscrypt_require_key(old_dir);
	if (err)
		return err;

	err = fscrypt_require_key(new_dir);
	if (err)
		return err;

	if (old_dir != new_dir) {
		if (IS_ENCRYPTED(new_dir) &&
		    !fscrypt_has_permitted_context(new_dir,
						   d_inode(old_dentry)))
			return -EPERM;

		if ((flags & RENAME_EXCHANGE) &&
		    IS_ENCRYPTED(old_dir) &&
		    !fscrypt_has_permitted_context(old_dir,
						   d_inode(new_dentry)))
			return -EPERM;
	}
	return 0;
}
EXPORT_SYMBOL_GPL(__fscrypt_prepare_rename);
