/*
 *  linux/fs/ext4/symlink.c
 *
 * Only fast symlinks left here - the rest is done by generic code. AV, 1999
 *
 * Copyright (C) 1992, 1993, 1994, 1995
 * Remy Card (card@masi.ibp.fr)
 * Laboratoire MASI - Institut Blaise Pascal
 * Universite Pierre et Marie Curie (Paris VI)
 *
 *  from
 *
 *  linux/fs/minix/symlink.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 *
 *  ext4 symlink handling code
 */

#include <linux/fs.h>
#include <linux/jbd2.h>
#include <linux/namei.h>
#include "ext4.h"
#include "xattr.h"

#ifdef CONFIG_FS_ENCRYPTION
static void *ext4_follow_link(struct dentry *dentry, struct nameidata *nd)
{
	struct inode *inode = dentry->d_inode;
	int res;

	if (!ext4_encrypted_inode(inode))
		return page_follow_link_light(dentry, nd);

	res = fscrypt_get_encryption_info(inode);
	if (res)
		return ERR_PTR(res);

	if (!fscrypt_has_encryption_key(inode))
		return ERR_PTR(-ENOKEY);

	return page_follow_link_light(dentry, nd);
}

static void ext4_put_link(struct dentry *dentry, struct nameidata *nd,
			  void *cookie)
{
	struct page *page = cookie;
	if (!page) {
		kfree(nd_get_link(nd));
	} else {
		kunmap(page);
		page_cache_release(page);
	}
}
#endif

const struct inode_operations ext4_symlink_inode_operations = {
	.readlink	= generic_readlink,
#ifdef CONFIG_FS_ENCRYPTION
	.follow_link	= ext4_follow_link,
	.put_link	= ext4_put_link,
#else
	.follow_link	= page_follow_link_light,
	.put_link	= page_put_link,
#endif
	.setattr	= ext4_setattr,
	.setxattr	= generic_setxattr,
	.getxattr	= generic_getxattr,
	.listxattr	= ext4_listxattr,
	.removexattr	= generic_removexattr,
};

const struct inode_operations ext4_fast_symlink_inode_operations = {
	.readlink	= generic_readlink,
	.follow_link	= ext4_follow_link,
	.setattr	= ext4_setattr,
	.setxattr	= generic_setxattr,
	.getxattr	= generic_getxattr,
	.listxattr	= ext4_listxattr,
	.removexattr	= generic_removexattr,
};
