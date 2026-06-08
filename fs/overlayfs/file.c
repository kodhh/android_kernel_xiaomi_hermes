/*
 *
 * Copyright (C) 2017 Red Hat, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published by
 * the Free Software Foundation.
 */

#include <linux/fs.h>
#include <linux/file.h>
#include <linux/mount.h>
#include <linux/cred.h>
#include <linux/uio.h>
#include <linux/poll.h>
#include <linux/mm.h>
#include "overlayfs.h"

static struct file *ovl_open_realfile(struct file *file,
				      struct path *realpath)
{
	struct inode *inode = file_inode(file);
	struct file *realfile;
	const struct cred *old_cred;

	old_cred = ovl_override_creds(inode->i_sb);
	realfile = dentry_open(realpath, file->f_flags, current_cred());
	ovl_revert_creds(old_cred);

	return realfile;
}

static int ovl_open(struct inode *inode, struct file *file)
{
	struct dentry *dentry = file->f_path.dentry;
	struct path realpath;
	struct file *realfile;
	int err;
	enum ovl_path_type type;

	type = ovl_path_real(dentry, &realpath);

	if (ovl_open_need_copy_up(file->f_flags, type, realpath.dentry)) {
		err = ovl_want_write(dentry);
		if (err)
			return err;

		if (file->f_flags & O_TRUNC)
			err = ovl_copy_up_truncate(dentry);
		else
			err = ovl_copy_up(dentry);
		ovl_drop_write(dentry);
		if (err)
			return err;

		ovl_path_upper(dentry, &realpath);
	}

	file->f_flags &= ~(O_CREAT | O_EXCL | O_NOCTTY | O_TRUNC);

	realfile = ovl_open_realfile(file, &realpath);
	if (IS_ERR(realfile))
		return PTR_ERR(realfile);

	file->private_data = realfile;

	return 0;
}

static int ovl_release(struct inode *inode, struct file *file)
{
	if (file->private_data)
		fput(file->private_data);
	return 0;
}

static loff_t ovl_llseek(struct file *file, loff_t offset, int whence)
{
	struct inode *inode = file_inode(file);
	struct file *realfile = file->private_data;
	const struct cred *old_cred;
	loff_t ret;

	mutex_lock(&inode->i_mutex);
	realfile->f_pos = file->f_pos;

	old_cred = ovl_override_creds(inode->i_sb);
	ret = vfs_llseek(realfile, offset, whence);
	ovl_revert_creds(old_cred);

	file->f_pos = realfile->f_pos;
	mutex_unlock(&inode->i_mutex);

	return ret;
}

static ssize_t ovl_read(struct file *file, char __user *buf, size_t len,
			loff_t *pos)
{
	struct inode *inode = file_inode(file);
	struct file *realfile = file->private_data;
	const struct cred *old_cred;
	ssize_t ret;

	old_cred = ovl_override_creds(inode->i_sb);
	ret = vfs_read(realfile, buf, len, pos);
	ovl_revert_creds(old_cred);

	return ret;
}

static ssize_t ovl_write(struct file *file, const char __user *buf,
			 size_t len, loff_t *pos)
{
	struct inode *inode = file_inode(file);
	struct file *realfile = file->private_data;
	const struct cred *old_cred;
	ssize_t ret;

	old_cred = ovl_override_creds(inode->i_sb);
	ret = vfs_write(realfile, buf, len, pos);
	ovl_revert_creds(old_cred);

	return ret;
}

static unsigned int ovl_poll(struct file *file, struct poll_table_struct *wait)
{
	struct file *realfile = file->private_data;
	struct inode *inode = file_inode(file);
	const struct cred *old_cred;
	unsigned int ret;

	old_cred = ovl_override_creds(inode->i_sb);
	ret = realfile->f_op->poll(realfile, wait);
	ovl_revert_creds(old_cred);

	return ret;
}

static int ovl_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct file *realfile = file->private_data;
	const struct cred *old_cred;
	int ret;

	if (!realfile->f_op->mmap)
		return -ENODEV;

	if (WARN_ON(file != vma->vm_file))
		return -EIO;

	vma->vm_file = get_file(realfile);

	old_cred = ovl_override_creds(file_inode(file)->i_sb);
	ret = realfile->f_op->mmap(realfile, vma);
	ovl_revert_creds(old_cred);

	if (ret)
		fput(realfile);
	else
		fput(file);

	return ret;
}

static int ovl_fsync(struct file *file, loff_t start, loff_t end,
		     int datasync)
{
	struct file *realfile = file->private_data;
	struct inode *inode = file_inode(file);
	const struct cred *old_cred;
	int ret;

	old_cred = ovl_override_creds(inode->i_sb);
	ret = vfs_fsync_range(realfile, start, end, datasync);
	ovl_revert_creds(old_cred);

	return ret;
}

const struct file_operations ovl_file_operations = {
	.open		= ovl_open,
	.release	= ovl_release,
	.llseek		= ovl_llseek,
	.read		= ovl_read,
	.write		= ovl_write,
	.poll		= ovl_poll,
	.mmap		= ovl_mmap,
	.fsync		= ovl_fsync,
};
