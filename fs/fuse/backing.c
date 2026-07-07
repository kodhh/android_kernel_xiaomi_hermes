/*
  FUSE-BPF: Filesystem in Userspace with BPF
  Copyright (C) 2021  Google LLC

  This program can be distributed under the terms of the GNU GPL.
*/

#include "fuse_i.h"
#include <linux/file.h>
#include <linux/namei.h>
#include <linux/slab.h>
#include <linux/xattr.h>
#include <linux/aio.h>

static inline struct fuse_dentry *fuse_get_dentry(struct dentry *dentry)
{
	return (struct fuse_dentry *)dentry->d_fsdata;
}

int fuse_bpf_set_backing_path(struct dentry *entry, int backing_fd)
{
	struct fuse_dentry *fd = fuse_get_dentry(entry);
	struct file *backing_file;

	if (!fd) {
		fd = kzalloc(sizeof(*fd), GFP_KERNEL);
		if (!fd)
			return -ENOMEM;
		entry->d_fsdata = fd;
	}

	backing_file = fget(backing_fd);
	if (!backing_file)
		return -EINVAL;

	fd->backing_path = backing_file->f_path;
	path_get(&fd->backing_path);
	fput(backing_file);

	return 0;
}

int fuse_bpf_lookup(struct inode *dir_ino, struct dentry *entry,
		    struct fuse_entry_bpf_out *febo)
{
	struct fuse_dentry *fd;
	int err = 0;

	if (febo->backing_action == FUSE_ACTION_REPLACE) {
		err = fuse_bpf_set_backing_path(entry, febo->backing_fd);
		if (!err && entry->d_inode) {
			struct fuse_inode *fi = get_fuse_inode(entry->d_inode);
			fd = fuse_get_dentry(entry);
			if (fd && fd->backing_path.dentry &&
			    fd->backing_path.dentry->d_inode)
				fi->backing_inode = igrab(
					fd->backing_path.dentry->d_inode);
		}
	}

	return err;
}

int fuse_bpf_create(struct inode *dir, struct dentry *entry,
		    struct fuse_entry_bpf_out *febo, umode_t mode)
{
	if (febo->backing_action == FUSE_ACTION_REPLACE)
		return fuse_bpf_set_backing_path(entry, febo->backing_fd);
	return 0;
}

int fuse_bpf_open(struct inode *inode, struct file *file)
{
	struct fuse_file *ff = file->private_data;
	struct fuse_dentry *fd = fuse_get_dentry(file->f_path.dentry);
	struct file *backing_file;

	if (!fd || !fd->backing_path.dentry)
		return -ENOENT;

	backing_file = dentry_open(&fd->backing_path, file->f_flags,
				   current_cred());
	if (IS_ERR(backing_file))
		return PTR_ERR(backing_file);

	ff->backing_file = backing_file;
	return 0;
}

int fuse_bpf_release(struct inode *inode, struct file *file)
{
	struct fuse_file *ff = file->private_data;

	if (ff->backing_file) {
		fput(ff->backing_file);
		ff->backing_file = NULL;
	}
	return 0;
}

static void fuse_file_accessed(struct file *dst_file, struct file *src_file)
{
	struct inode *dst_inode;
	struct inode *src_inode;

	if (dst_file->f_flags & O_NOATIME)
		return;

	dst_inode = file_inode(dst_file);
	src_inode = file_inode(src_file);

	if ((!timespec_equal(&dst_inode->i_mtime, &src_inode->i_mtime) ||
	     !timespec_equal(&dst_inode->i_ctime, &src_inode->i_ctime))) {
		dst_inode->i_mtime = src_inode->i_mtime;
		dst_inode->i_ctime = src_inode->i_ctime;
	}

	touch_atime(&dst_file->f_path);
}

ssize_t fuse_bpf_read_iter(struct file *file, struct kiocb *iocb,
			   const struct iovec *iov, unsigned long nr_segs,
			   loff_t *ppos)
{
	struct fuse_file *ff = file->private_data;
	struct file *backing_file = ff->backing_file;
	const struct cred *old_cred;
	struct kiocb kiocb;
	ssize_t ret;

	if (!backing_file)
		return -EINVAL;

	init_sync_kiocb(&kiocb, backing_file);
	kiocb.ki_pos = *ppos;
	kiocb.ki_nbytes = iov_length(iov, nr_segs);

	old_cred = override_creds(backing_file->f_cred);
	ret = call_read_iter(backing_file, &kiocb, iov, nr_segs, *ppos);
	revert_creds(old_cred);

	*ppos = kiocb.ki_pos;

	fuse_file_accessed(file, backing_file);

	return ret;
}

ssize_t fuse_bpf_write_iter(struct file *file, struct kiocb *iocb,
			    const struct iovec *iov, unsigned long nr_segs,
			    loff_t *ppos)
{
	struct fuse_file *ff = file->private_data;
	struct file *backing_file = ff->backing_file;
	struct inode *fuse_inode = file_inode(file);
	const struct cred *old_cred;
	struct kiocb kiocb;
	ssize_t ret;

	if (!backing_file)
		return -EINVAL;

	init_sync_kiocb(&kiocb, backing_file);
	kiocb.ki_pos = *ppos;
	kiocb.ki_nbytes = iov_length(iov, nr_segs);

	mutex_lock(&fuse_inode->i_mutex);

	old_cred = override_creds(backing_file->f_cred);
	file_start_write(backing_file);
	ret = call_write_iter(backing_file, &kiocb, iov, nr_segs, *ppos);
	file_end_write(backing_file);
	revert_creds(old_cred);

	*ppos = kiocb.ki_pos;

	if (ret > 0) {
		struct inode *backing_inode = file_inode(backing_file);
		fuse_inode->i_mtime = backing_inode->i_mtime;
		fuse_inode->i_ctime = backing_inode->i_ctime;
	}

	fuse_file_accessed(file, backing_file);

	mutex_unlock(&fuse_inode->i_mutex);

	return ret;
}

ssize_t fuse_bpf_file_read_iter(struct file *file, struct kiocb *iocb,
				const struct iovec *iov, unsigned long nr_segs,
				loff_t *ppos)
{
	return fuse_bpf_read_iter(file, iocb, iov, nr_segs, ppos);
}

ssize_t fuse_bpf_file_write_iter(struct file *file, struct kiocb *iocb,
				 const struct iovec *iov, unsigned long nr_segs,
				 loff_t *ppos)
{
	return fuse_bpf_write_iter(file, iocb, iov, nr_segs, ppos);
}

int fuse_bpf_getattr(struct vfsmount *mnt, struct dentry *entry,
		     struct kstat *stat)
{
	struct fuse_dentry *fd = fuse_get_dentry(entry);

	if (!fd || !fd->backing_path.dentry)
		return -ENOENT;

	return vfs_getattr(&fd->backing_path, stat);
}

int fuse_bpf_setattr(struct dentry *entry, struct iattr *attr)
{
	struct fuse_dentry *fd = fuse_get_dentry(entry);
	struct inode *backing_inode;
	int err;

	if (!fd || !fd->backing_path.dentry)
		return -ENOENT;

	backing_inode = fd->backing_path.dentry->d_inode;

	mutex_lock(&backing_inode->i_mutex);
	err = inode_change_ok(backing_inode, attr);
	if (!err)
		err = notify_change(fd->backing_path.dentry, attr,
				    NULL);
	mutex_unlock(&backing_inode->i_mutex);

	return err;
}

int fuse_bpf_setxattr(struct dentry *entry, const char *name,
		      const void *value, size_t size, int flags)
{
	struct fuse_dentry *fd = fuse_get_dentry(entry);

	if (!fd || !fd->backing_path.dentry)
		return -ENOENT;

	return vfs_setxattr(fd->backing_path.dentry, name, value, size,
			    flags);
}

ssize_t fuse_bpf_getxattr(struct dentry *entry, const char *name,
			  void *value, size_t size)
{
	struct fuse_dentry *fd = fuse_get_dentry(entry);

	if (!fd || !fd->backing_path.dentry)
		return -ENOENT;

	return vfs_getxattr(fd->backing_path.dentry, name, value, size);
}

int fuse_bpf_removexattr(struct dentry *entry, const char *name)
{
	struct fuse_dentry *fd = fuse_get_dentry(entry);

	if (!fd || !fd->backing_path.dentry)
		return -ENOENT;

	return vfs_removexattr(fd->backing_path.dentry, name);
}

int fuse_bpf_listxattr(struct dentry *entry, char *buf, size_t size)
{
	struct fuse_dentry *fd = fuse_get_dentry(entry);

	if (!fd || !fd->backing_path.dentry)
		return -ENOENT;

	return vfs_listxattr(fd->backing_path.dentry, buf, size);
}

void fuse_dentry_release(struct dentry *dentry)
{
	struct fuse_dentry *fd = dentry->d_fsdata;

	if (fd) {
		path_put(&fd->backing_path);
		kfree(fd);
	}
}
