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
#include <linux/fs_stack.h>

#ifndef FUSE_SUPER_MAGIC
#define FUSE_SUPER_MAGIC 0x65735546
#endif
#include <linux/statfs.h>

static inline struct fuse_dentry *backing_get_dentry(struct dentry *dentry)
{
	return (struct fuse_dentry *)dentry->d_fsdata;
}

int fuse_bpf_set_backing_path(struct dentry *entry, int backing_fd)
{
	struct fuse_dentry *fd = backing_get_dentry(entry);
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
			fd = backing_get_dentry(entry);
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
	struct fuse_dentry *fd = backing_get_dentry(file->f_path.dentry);
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
	struct kiocb kiocb;
	ssize_t ret;

	if (!backing_file)
		return -EINVAL;

	init_sync_kiocb(&kiocb, backing_file);
	kiocb.ki_pos = *ppos;
	kiocb.ki_nbytes = iov_length(iov, nr_segs);

	if (!backing_file->f_op->aio_read)
		return -EINVAL;
	ret = backing_file->f_op->aio_read(&kiocb, iov, nr_segs, *ppos);
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
	struct kiocb kiocb;
	ssize_t ret;

	if (!backing_file)
		return -EINVAL;

	init_sync_kiocb(&kiocb, backing_file);
	kiocb.ki_pos = *ppos;
	kiocb.ki_nbytes = iov_length(iov, nr_segs);

	mutex_lock(&fuse_inode->i_mutex);

	file_start_write(backing_file);
	if (!backing_file->f_op->aio_write) {
		file_end_write(backing_file);
		mutex_unlock(&fuse_inode->i_mutex);
		return -EINVAL;
	}
	ret = backing_file->f_op->aio_write(&kiocb, iov, nr_segs, *ppos);
	file_end_write(backing_file);

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
	struct fuse_dentry *fd = backing_get_dentry(entry);

	if (!fd || !fd->backing_path.dentry)
		return -ENOENT;

	return vfs_getattr(&fd->backing_path, stat);
}

int fuse_bpf_setattr(struct dentry *entry, struct iattr *attr)
{
	struct fuse_dentry *fd = backing_get_dentry(entry);
	struct inode *backing_inode;
	int err;

	if (!fd || !fd->backing_path.dentry)
		return -ENOENT;

	backing_inode = fd->backing_path.dentry->d_inode;

	mutex_lock(&backing_inode->i_mutex);
	err = inode_change_ok(backing_inode, attr);
	if (!err)
		err = notify_change(fd->backing_path.dentry, attr, NULL);
	mutex_unlock(&backing_inode->i_mutex);

	return err;
}

int fuse_bpf_setxattr(struct dentry *entry, const char *name,
		      const void *value, size_t size, int flags)
{
	struct fuse_dentry *fd = backing_get_dentry(entry);

	if (!fd || !fd->backing_path.dentry)
		return -ENOENT;

	return vfs_setxattr(fd->backing_path.dentry, name, value, size,
			    flags);
}

ssize_t fuse_bpf_getxattr(struct dentry *entry, const char *name,
			  void *value, size_t size)
{
	struct fuse_dentry *fd = backing_get_dentry(entry);

	if (!fd || !fd->backing_path.dentry)
		return -ENOENT;

	return vfs_getxattr(fd->backing_path.dentry, name, value, size);
}

int fuse_bpf_removexattr(struct dentry *entry, const char *name)
{
	struct fuse_dentry *fd = backing_get_dentry(entry);

	if (!fd || !fd->backing_path.dentry)
		return -ENOENT;

	return vfs_removexattr(fd->backing_path.dentry, name);
}

int fuse_bpf_listxattr(struct dentry *entry, char *buf, size_t size)
{
	struct fuse_dentry *fd = backing_get_dentry(entry);

	if (!fd || !fd->backing_path.dentry)
		return -ENOENT;

	return vfs_listxattr(fd->backing_path.dentry, buf, size);
}

int fuse_bpf_mkdir(struct inode *dir, struct dentry *entry, umode_t mode)
{
	struct fuse_dentry *fd = backing_get_dentry(entry);
	struct inode *backing_dir;
	int err;

	if (!fd || !fd->backing_path.dentry)
		return -ENOENT;

	backing_dir = fd->backing_path.dentry->d_inode;

	mutex_lock_nested(&backing_dir->i_mutex, I_MUTEX_PARENT);
	err = vfs_mkdir(backing_dir, fd->backing_path.dentry, mode);
	mutex_unlock(&backing_dir->i_mutex);

	return err;
}

int fuse_bpf_rmdir(struct inode *dir, struct dentry *entry)
{
	struct fuse_dentry *fd = backing_get_dentry(entry);
	struct dentry *backing_parent;
	struct inode *backing_dir;
	int err;

	if (!fd || !fd->backing_path.dentry)
		return -ENOENT;

	backing_parent = dget_parent(fd->backing_path.dentry);
	backing_dir = backing_parent->d_inode;

	mutex_lock_nested(&backing_dir->i_mutex, I_MUTEX_PARENT);
	err = vfs_rmdir(backing_dir, fd->backing_path.dentry);
	mutex_unlock(&backing_dir->i_mutex);

	dput(backing_parent);
	if (!err)
		d_drop(entry);
	return err;
}

int fuse_bpf_unlink(struct inode *dir, struct dentry *entry)
{
	struct fuse_dentry *fd = backing_get_dentry(entry);
	struct dentry *backing_parent;
	struct inode *backing_dir;
	int err;

	if (!fd || !fd->backing_path.dentry)
		return -ENOENT;

	backing_parent = dget_parent(fd->backing_path.dentry);
	backing_dir = backing_parent->d_inode;

	mutex_lock_nested(&backing_dir->i_mutex, I_MUTEX_PARENT);
	err = vfs_unlink(backing_dir, fd->backing_path.dentry, NULL);
	mutex_unlock(&backing_dir->i_mutex);

	dput(backing_parent);
	if (!err)
		d_drop(entry);
	return err;
}

int fuse_bpf_rename(struct inode *olddir, struct dentry *oldent,
		    struct inode *newdir, struct dentry *newent)
{
	struct fuse_dentry *old_fd = backing_get_dentry(oldent);
	struct fuse_dentry *new_fd = backing_get_dentry(newent);
	struct dentry *old_backing_parent;
	struct dentry *new_backing_parent;
	struct inode *old_backing_dir;
	struct inode *new_backing_dir;
	struct dentry *trap;
	int err;

	if (!old_fd || !old_fd->backing_path.dentry)
		return -ENOENT;
	if (!new_fd || !new_fd->backing_path.dentry)
		return -EINVAL;

	old_backing_parent = dget_parent(old_fd->backing_path.dentry);
	new_backing_parent = dget_parent(new_fd->backing_path.dentry);
	old_backing_dir = old_backing_parent->d_inode;
	new_backing_dir = new_backing_parent->d_inode;

	trap = lock_rename(old_backing_parent, new_backing_parent);
	if (trap == old_fd->backing_path.dentry ||
	    trap == new_fd->backing_path.dentry) {
		err = -EINVAL;
		goto out;
	}
	err = vfs_rename(old_backing_dir, old_fd->backing_path.dentry,
			 new_backing_dir, new_fd->backing_path.dentry,
			 NULL, 0);
out:
	unlock_rename(old_backing_parent, new_backing_parent);
	dput(new_backing_parent);
	dput(old_backing_parent);
	return err;
}

int fuse_bpf_symlink(struct inode *dir, struct dentry *entry,
		     const char *link, int len)
{
	struct fuse_dentry *fd = backing_get_dentry(entry);
	struct inode *backing_dir;
	int err;

	if (!fd || !fd->backing_path.dentry)
		return -ENOENT;

	backing_dir = fd->backing_path.dentry->d_inode;

	mutex_lock_nested(&backing_dir->i_mutex, I_MUTEX_PARENT);
	err = vfs_symlink(backing_dir, fd->backing_path.dentry, link);
	mutex_unlock(&backing_dir->i_mutex);

	if (!err && entry->d_inode)
		fsstack_copy_attr_all(entry->d_inode,
				      fd->backing_path.dentry->d_inode);
	return err;
}

int fuse_bpf_link(struct dentry *entry, struct inode *dir,
		  struct dentry *newent)
{
	struct fuse_dentry *new_fd = backing_get_dentry(newent);
	struct fuse_dentry *old_fd = backing_get_dentry(entry);
	struct dentry *backing_parent;
	struct inode *backing_dir;
	int err;

	if (!new_fd || !new_fd->backing_path.dentry)
		return -ENOENT;
	if (!old_fd || !old_fd->backing_path.dentry)
		return -ENOENT;

	backing_parent = dget_parent(new_fd->backing_path.dentry);
	backing_dir = backing_parent->d_inode;

	mutex_lock_nested(&backing_dir->i_mutex, I_MUTEX_PARENT);
	err = vfs_link(old_fd->backing_path.dentry, backing_dir,
		       new_fd->backing_path.dentry, NULL);
	mutex_unlock(&backing_dir->i_mutex);

	dput(backing_parent);
	return err;
}

int fuse_bpf_mknod(struct inode *dir, struct dentry *entry,
		   umode_t mode, dev_t rdev)
{
	struct fuse_dentry *fd = backing_get_dentry(entry);
	struct inode *backing_dir;
	int err;

	if (!fd || !fd->backing_path.dentry)
		return -ENOENT;

	backing_dir = fd->backing_path.dentry->d_inode;

	mutex_lock_nested(&backing_dir->i_mutex, I_MUTEX_PARENT);
	err = vfs_mknod(backing_dir, fd->backing_path.dentry, mode, rdev);
	mutex_unlock(&backing_dir->i_mutex);

	return err;
}

struct readdir_cb {
	struct dir_context ctx;
	filldir_t filldir;
	void *buf;
};

static int readdir_filldir(void *buf, const char *name, int namelen,
			   loff_t offset, u64 ino, unsigned d_type)
{
	struct readdir_cb *cb = buf;
	return cb->filldir(cb->buf, name, namelen, offset, ino, d_type);
}

ssize_t fuse_bpf_readdir(struct file *file, struct dir_context *ctx)
{
	struct fuse_file *ff = file->private_data;
	struct file *backing_file = ff->backing_file;

	if (!backing_file)
		return -ENOENT;

	backing_file->f_pos = file->f_pos;
	return vfs_readdir(backing_file, readdir_filldir, ctx);
}

int fuse_bpf_statfs(struct dentry *dentry, struct kstatfs *buf)
{
	struct fuse_dentry *fd = backing_get_dentry(dentry);
	struct path backing_path;
	int err;

	if (!fd || !fd->backing_path.dentry)
		return -ENOENT;

	backing_path = fd->backing_path;
	err = vfs_statfs(&backing_path, buf);
	if (!err)
		buf->f_type = FUSE_SUPER_MAGIC;
	return err;
}

int fuse_bpf_access(struct inode *inode, int mask)
{
	struct fuse_inode *fi = get_fuse_inode(inode);

	if (!fi->backing_inode)
		return -ENOENT;

	return inode_permission(fi->backing_inode, mask);
}

long fuse_bpf_ioctl(struct file *file, unsigned int command,
		    unsigned long arg, int flags)
{
	struct fuse_file *ff = file->private_data;

	if (!ff->backing_file)
		return -ENOENT;

	if (flags & FUSE_IOCTL_COMPAT)
		return -ENOTTY;

	return do_vfs_ioctl(ff->backing_file, 0, command, arg);
}

int fuse_bpf_fallocate(struct file *file, int mode, loff_t offset,
		       loff_t length)
{
	struct fuse_file *ff = file->private_data;

	if (!ff->backing_file)
		return -ENOENT;

	if (!ff->backing_file->f_op->fallocate)
		return -EOPNOTSUPP;

	return ff->backing_file->f_op->fallocate(ff->backing_file, mode,
						 offset, length);
}

int fuse_bpf_flock(struct file *file, int cmd, struct file_lock *fl)
{
	struct fuse_file *ff = file->private_data;
	struct file *backing_file = ff->backing_file;

	if (!backing_file)
		return -ENOENT;

	fl->fl_file = backing_file;
	if (backing_file->f_op->flock)
		return backing_file->f_op->flock(backing_file, cmd, fl);
	return flock_lock_file_wait(backing_file, fl);
}

ssize_t fuse_bpf_mmap(struct file *file, struct vm_area_struct *vma)
{
	int ret;
	struct fuse_file *ff = file->private_data;
	struct inode *fuse_inode = file_inode(file);
	struct file *backing_file = ff->backing_file;
	struct inode *backing_inode;

	if (!backing_file)
		return -ENOENT;

	if (!backing_file->f_op->mmap)
		return -ENODEV;

	if (WARN_ON(file != vma->vm_file))
		return -EIO;

	vma->vm_file = get_file(backing_file);
	ret = backing_file->f_op->mmap(vma->vm_file, vma);
	if (ret)
		fput(backing_file);
	else
		fput(file);

	if (file->f_flags & O_NOATIME)
		return ret;

	backing_inode = file_inode(backing_file);
	if ((!timespec_equal(&fuse_inode->i_mtime,
			     &backing_inode->i_mtime) ||
	     !timespec_equal(&fuse_inode->i_ctime,
			     &backing_inode->i_ctime))) {
		fuse_inode->i_mtime = backing_inode->i_mtime;
		fuse_inode->i_ctime = backing_inode->i_ctime;
	}
	touch_atime(&file->f_path);

	return ret;
}

int fuse_bpf_fsync(struct file *file, loff_t start, loff_t end,
		   int datasync)
{
	struct fuse_file *ff = file->private_data;

	if (!ff->backing_file)
		return -ENOENT;

	return vfs_fsync_range(ff->backing_file, start, end, datasync);
}

void fuse_dentry_release(struct dentry *dentry)
{
	struct fuse_dentry *fd = dentry->d_fsdata;

	if (fd) {
		path_put(&fd->backing_path);
		kfree(fd);
	}
}
