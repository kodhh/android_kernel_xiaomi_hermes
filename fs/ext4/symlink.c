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
	struct page *cpage = NULL;
	char *caddr, *paddr = NULL;
	struct fscrypt_str cstr = FSTR_INIT(NULL, 0);
	struct fscrypt_str pstr = FSTR_INIT(NULL, 0);
	struct fscrypt_symlink_data *sd;
	u32 max_size = inode->i_sb->s_blocksize;
	int res;

	if (!ext4_encrypted_inode(inode))
		return page_follow_link_light(dentry, nd);

	res = fscrypt_get_encryption_info(inode);
	if (res)
		return ERR_PTR(res);

	if (!fscrypt_has_encryption_key(inode))
		return ERR_PTR(-ENOKEY);

	if (ext4_inode_is_fast_symlink(inode)) {
		caddr = (char *)EXT4_I(inode)->i_data;
		max_size = sizeof(EXT4_I(inode)->i_data);
	} else {
		cpage = read_mapping_page(inode->i_mapping, 0, NULL);
		if (IS_ERR(cpage))
			return ERR_CAST(cpage);
		caddr = kmap(cpage);
	}

	sd = (struct fscrypt_symlink_data *)caddr;
	cstr.name = sd->encrypted_path;
	cstr.len = le16_to_cpu(sd->len);

	if (unlikely(cstr.len == 0)) {
		res = -ENOENT;
		goto errout;
	}

	if ((cstr.len + sizeof(struct fscrypt_symlink_data) - 1) > max_size) {
		res = -EIO;
		goto errout;
	}

	res = fscrypt_fname_alloc_buffer(inode, cstr.len, &pstr);
	if (res)
		goto errout;

	res = fscrypt_fname_disk_to_usr(inode, 0, 0, &cstr, &pstr);
	if (res)
		goto errout;

	if (unlikely(pstr.name[0] == 0)) {
		res = -ENOENT;
		goto errout;
	}

	paddr = pstr.name;
	paddr[pstr.len] = '\0';
	nd_set_link(nd, paddr);

	if (cpage) {
		kunmap(cpage);
		page_cache_release(cpage);
	}
	return NULL;
errout:
	fscrypt_fname_free_buffer(&pstr);
	if (cpage) {
		kunmap(cpage);
		page_cache_release(cpage);
	}
	return ERR_PTR(res);
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

static void *ext4_follow_fast_link(struct dentry *dentry, struct nameidata *nd)
{
	struct ext4_inode_info *ei = EXT4_I(dentry->d_inode);
	nd_set_link(nd, (char *) ei->i_data);
	return NULL;
}

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
	.follow_link	= ext4_follow_fast_link,
	.setattr	= ext4_setattr,
	.setxattr	= generic_setxattr,
	.getxattr	= generic_getxattr,
	.listxattr	= ext4_listxattr,
	.removexattr	= generic_removexattr,
};
