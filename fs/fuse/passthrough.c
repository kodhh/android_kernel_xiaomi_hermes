/*
 * FUSE passthrough support
 * Copyright (C) 2020  Alessio Balsini <alessio.balsini@android.com>
 *
 * This program can be distributed under the terms of the GNU GPL.
 */

#include "fuse_i.h"

#include <linux/file.h>
#include <linux/fuse.h>
#include <linux/slab.h>

static void fuse_file_accessed(struct file *dst_file, struct file *src_file)
{
	struct inode *dst_inode, *src_inode;

	if (dst_file->f_flags & O_NOATIME)
		return;

	dst_inode = file_inode(dst_file);
	src_inode = file_inode(src_file);

	if ((!timespec_equal(&dst_inode->i_mtime, &src_inode->i_mtime) ||
	     !timespec_equal(&dst_inode->i_ctime, &src_inode->i_ctime))) {
		dst_inode->i_mtime = src_inode->i_mtime;
		dst_inode->i_ctime = src_inode->i_ctime;
		mark_inode_dirty_sync(dst_inode);
	}

	if (timespec_compare(&src_inode->i_atime, &dst_inode->i_atime) > 0) {
		dst_inode->i_atime = src_inode->i_atime;
		mark_inode_dirty_sync(dst_inode);
	}
}

ssize_t fuse_passthrough_read_iter(struct file *file, struct kiocb *iocb_fuse,
				   const struct iovec *iov, unsigned long nr_segs,
				   loff_t *ppos)
{
	struct fuse_file *ff = file->private_data;
	struct file *passthrough_filp = ff->passthrough.filp;
	const struct cred *old_cred;

	if (!passthrough_filp)
		return -EINVAL;

	old_cred = override_creds(ff->passthrough.cred);
	call_read_iter(passthrough_filp, iocb_fuse, iov, nr_segs, *ppos);
	revert_creds(old_cred);

	fuse_file_accessed(file, passthrough_filp);

	return 0;
}

ssize_t fuse_passthrough_write_iter(struct file *file, struct kiocb *iocb_fuse,
				    const struct iovec *iov, unsigned long nr_segs,
				    loff_t *ppos)
{
	struct fuse_file *ff = file->private_data;
	struct file *passthrough_filp = ff->passthrough.filp;
	const struct cred *old_cred;

	if (!passthrough_filp)
		return -EINVAL;

	old_cred = override_creds(ff->passthrough.cred);
	call_write_iter(passthrough_filp, iocb_fuse, iov, nr_segs, *ppos);
	revert_creds(old_cred);

	fuse_file_accessed(file, passthrough_filp);

	return 0;
}

ssize_t fuse_passthrough_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct fuse_file *ff = file->private_data;
	struct file *passthrough_filp = ff->passthrough.filp;
	const struct cred *old_cred;
	int ret;

	if (!passthrough_filp->f_op->mmap)
		return -ENODEV;

	if (vma->vm_file)
		fput(vma->vm_file);
	vma->vm_file = get_file(passthrough_filp);

	old_cred = override_creds(ff->passthrough.cred);
	ret = call_mmap(passthrough_filp, vma);
	revert_creds(old_cred);

	fuse_file_accessed(file, passthrough_filp);

	return ret;
}

int fuse_passthrough_open(struct fuse_dev *fud, u32 lower_fd)
{
	struct fuse_conn *fc = fud->fc;
	struct file *passthrough_filp;
	struct inode *passthrough_inode;
	struct super_block *passthrough_sb;
	struct fuse_passthrough *passthrough;
	int res;

	if (!fc->passthrough)
		return -EOPNOTSUPP;

	passthrough_filp = fget(lower_fd);
	if (!passthrough_filp) {
		pr_err("FUSE: invalid file descriptor for passthrough.\n");
		return -EINVAL;
	}

	if (!passthrough_filp->f_op->aio_read ||
	    !passthrough_filp->f_op->aio_write) {
		pr_err("FUSE: passthrough file misses file operations.\n");
		fput(passthrough_filp);
		return -EINVAL;
	}

	passthrough_inode = file_inode(passthrough_filp);
	passthrough_sb = passthrough_inode->i_sb;
	if (passthrough_sb->s_stack_depth >= FILESYSTEM_MAX_STACK_DEPTH) {
		pr_err("FUSE: fs stacking depth exceeded for passthrough\n");
		fput(passthrough_filp);
		return -EINVAL;
	}

	passthrough = kmalloc(sizeof(struct fuse_passthrough), GFP_KERNEL);
	if (!passthrough) {
		fput(passthrough_filp);
		return -ENOMEM;
	}

	passthrough->filp = passthrough_filp;
	passthrough->cred = prepare_creds();
	if (!passthrough->cred) {
		fput(passthrough_filp);
		kfree(passthrough);
		return -ENOMEM;
	}

	spin_lock(&fc->passthrough_req_lock);
	res = idr_alloc(&fc->passthrough_req, passthrough, 1, 0, GFP_ATOMIC);
	spin_unlock(&fc->passthrough_req_lock);
	if (res < 0) {
		fuse_passthrough_release(passthrough);
		kfree(passthrough);
		fput(passthrough_filp);
		return res;
	}

	return res;
}

int fuse_passthrough_setup(struct fuse_conn *fc, struct fuse_file *ff,
			   struct fuse_open_out *openarg)
{
	struct fuse_passthrough *passthrough;
	int passthrough_fh = openarg->passthrough_fh;

	if (!fc->passthrough)
		return 0;

	if (passthrough_fh <= 0)
		return 0;

	spin_lock(&fc->passthrough_req_lock);
	passthrough = idr_find(&fc->passthrough_req, passthrough_fh);
	idr_remove(&fc->passthrough_req, passthrough_fh);
	spin_unlock(&fc->passthrough_req_lock);

	if (!passthrough)
		return -EINVAL;

	ff->passthrough = *passthrough;
	kfree(passthrough);

	return 0;
}

void fuse_passthrough_release(struct fuse_passthrough *passthrough)
{
	if (passthrough->filp) {
		fput(passthrough->filp);
		passthrough->filp = NULL;
	}
	if (passthrough->cred) {
		put_cred(passthrough->cred);
		passthrough->cred = NULL;
	}
}
