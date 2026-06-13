/*
 * FUSE passthrough support
 * Copyright (C) 2020  Alessio Balsini <alessio.balsini@android.com>
 *
 * This program can be distributed under the terms of the GNU GPL.
 */

#include "fuse_i.h"

#include <linux/file.h>
#include <linux/fuse.h>
#include <linux/idr.h>
#include <linux/slab.h>
#include <linux/uio.h>
#include <linux/aio.h>

static void fuse_copyattr(struct file *dst_file, struct file *src_file)
{
	struct inode *dst = file_inode(dst_file);
	struct inode *src = file_inode(src_file);

	dst->i_atime = src->i_atime;
	dst->i_mtime = src->i_mtime;
	dst->i_ctime = src->i_ctime;
	i_size_write(dst, i_size_read(src));
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

ssize_t fuse_passthrough_read_iter(struct file *file, struct kiocb *iocb_fuse,
				   const struct iovec *iov, unsigned long nr_segs,
				   loff_t *ppos)
{
	ssize_t ret;
	struct fuse_file *ff = file->private_data;
	struct file *passthrough_filp = ff->passthrough.filp;
	const struct cred *old_cred;
	struct kiocb iocb;

	if (!passthrough_filp)
		return -EINVAL;

	init_sync_kiocb(&iocb, passthrough_filp);
	iocb.ki_pos = *ppos;
	iocb.ki_nbytes = iov_length(iov, nr_segs);

	old_cred = override_creds(ff->passthrough.cred);
	ret = call_read_iter(passthrough_filp, &iocb, iov, nr_segs, *ppos);
	revert_creds(old_cred);

	*ppos = iocb.ki_pos;

	fuse_file_accessed(file, passthrough_filp);

	return ret;
}

ssize_t fuse_passthrough_write_iter(struct file *file, struct kiocb *iocb_fuse,
				    const struct iovec *iov, unsigned long nr_segs,
				    loff_t *ppos)
{
	ssize_t ret;
	struct fuse_file *ff = file->private_data;
	struct file *passthrough_filp = ff->passthrough.filp;
	struct inode *fuse_inode = file_inode(file);
	const struct cred *old_cred;
	struct kiocb iocb;

	if (!passthrough_filp)
		return -EINVAL;

	init_sync_kiocb(&iocb, passthrough_filp);
	iocb.ki_pos = *ppos;
	iocb.ki_nbytes = iov_length(iov, nr_segs);

	mutex_lock(&fuse_inode->i_mutex);

	fuse_copyattr(file, passthrough_filp);

	old_cred = override_creds(ff->passthrough.cred);
	file_start_write(passthrough_filp);
	ret = call_write_iter(passthrough_filp, &iocb, iov, nr_segs, *ppos);
	file_end_write(passthrough_filp);
	revert_creds(old_cred);

	*ppos = iocb.ki_pos;

	if (ret > 0)
		fuse_copyattr(file, passthrough_filp);

	fuse_file_accessed(file, passthrough_filp);

	mutex_unlock(&fuse_inode->i_mutex);

	return ret;
}

ssize_t fuse_passthrough_mmap(struct file *file, struct vm_area_struct *vma)
{
	int ret;
	struct fuse_file *ff = file->private_data;
	struct file *passthrough_filp = ff->passthrough.filp;
	const struct cred *old_cred;

	if (!passthrough_filp->f_op->mmap)
		return -ENODEV;

	if (WARN_ON(file != vma->vm_file))
		return -EIO;

	vma->vm_file = get_file(passthrough_filp);

	old_cred = override_creds(ff->passthrough.cred);
	ret = call_mmap(vma->vm_file, vma);
	revert_creds(old_cred);

	if (ret)
		fput(passthrough_filp);
	else
		fput(file);

	fuse_file_accessed(file, passthrough_filp);

	return ret;
}

int fuse_passthrough_open(struct fuse_conn *fc, u32 lower_fd)
{
	int res;
	struct file *passthrough_filp;
	struct inode *passthrough_inode;
	struct super_block *passthrough_sb;
	struct fuse_passthrough *passthrough;

	if (!fc->passthrough)
		return -EPERM;

	passthrough_filp = fget(lower_fd);
	if (!passthrough_filp) {
		pr_err("FUSE: invalid file descriptor for passthrough.\n");
		return -EBADF;
	}

	if (!passthrough_filp->f_op->aio_read ||
	    !passthrough_filp->f_op->aio_write) {
		pr_err("FUSE: passthrough file misses file operations.\n");
		res = -EBADF;
		goto err_free_file;
	}

	passthrough_inode = file_inode(passthrough_filp);
	passthrough_sb = passthrough_inode->i_sb;
	if (passthrough_sb->s_stack_depth >= FILESYSTEM_MAX_STACK_DEPTH) {
		pr_err("FUSE: fs stacking depth exceeded for passthrough\n");
		res = -EINVAL;
		goto err_free_file;
	}

	passthrough = kmalloc(sizeof(struct fuse_passthrough), GFP_KERNEL);
	if (!passthrough) {
		res = -ENOMEM;
		goto err_free_file;
	}

	passthrough->filp = passthrough_filp;
	passthrough->cred = prepare_creds();
	if (!passthrough->cred) {
		res = -ENOMEM;
		goto err_free_passthrough;
	}

	spin_lock(&fc->passthrough_req_lock);
	res = idr_alloc(&fc->passthrough_req, passthrough, 1, 0, GFP_ATOMIC);
	spin_unlock(&fc->passthrough_req_lock);
	if (res < 0) {
		fuse_passthrough_release(passthrough);
		kfree(passthrough);
		return res;
	}

	return res;

err_free_passthrough:
	kfree(passthrough);
err_free_file:
	fput(passthrough_filp);
	return res;
}

int fuse_passthrough_setup(struct fuse_conn *fc, struct fuse_file *ff,
			   struct fuse_open_out *openarg)
{
	struct fuse_passthrough *passthrough;
	int passthrough_fh = openarg->passthrough_fh;

	if (!fc->passthrough)
		return 0;

	/* Default case, passthrough is not requested */
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
