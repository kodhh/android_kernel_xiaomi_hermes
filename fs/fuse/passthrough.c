// SPDX-License-Identifier: GPL-2.0
#include "fuse_i.h"

#include <linux/file.h>
#include <linux/fuse.h>
#include <linux/idr.h>
#include <linux/slab.h>
#include <linux/uio.h>
#include <linux/aio.h>
#include <linux/cred.h>

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

static inline void kiocb_clone(struct kiocb *kiocb, struct kiocb *kiocb_src,
			       struct file *filp)
{
	kiocb->ki_filp = filp;
	kiocb->ki_pos = kiocb_src->ki_pos;
}

ssize_t fuse_passthrough_read_iter(struct kiocb *iocb_fuse,
				   struct iov_iter *to)
{
	ssize_t ret;
	struct file *fuse_filp = iocb_fuse->ki_filp;
	struct fuse_file *ff = fuse_filp->private_data;
	struct file *passthrough_filp = ff->passthrough.filp;
	struct kiocb kiocb;

	const struct cred *old_cred;

	if (!passthrough_filp)
		return -EINVAL;
	if (!passthrough_filp->f_op->aio_read)
		return -EINVAL;

	old_cred = override_creds(ff->passthrough.cred);
	kiocb_clone(&kiocb, iocb_fuse, passthrough_filp);
	ret = passthrough_filp->f_op->aio_read(&kiocb, to->iov, to->nr_segs,
						iocb_fuse->ki_pos);
	revert_creds(old_cred);
	iocb_fuse->ki_pos = kiocb.ki_pos;

	fuse_file_accessed(fuse_filp, passthrough_filp);

	return ret;
}

ssize_t fuse_passthrough_write_iter(struct kiocb *iocb_fuse,
				    struct iov_iter *from)
{
	ssize_t ret;
	struct file *fuse_filp = iocb_fuse->ki_filp;
	struct fuse_file *ff = fuse_filp->private_data;
	const struct cred *old_cred;
	struct inode *fuse_inode = file_inode(fuse_filp);
	struct file *passthrough_filp = ff->passthrough.filp;
	struct kiocb kiocb;

	if (!passthrough_filp)
		return -EINVAL;
	if (!passthrough_filp->f_op->aio_write)
		return -EINVAL;

	mutex_lock(&fuse_inode->i_mutex);

	fuse_copyattr(fuse_filp, passthrough_filp);

	old_cred = override_creds(ff->passthrough.cred);
	kiocb_clone(&kiocb, iocb_fuse, passthrough_filp);
	file_start_write(passthrough_filp);
	ret = passthrough_filp->f_op->aio_write(&kiocb, from->iov, from->nr_segs,
						 iocb_fuse->ki_pos);
	file_end_write(passthrough_filp);
	revert_creds(old_cred);
	iocb_fuse->ki_pos = kiocb.ki_pos;

	if (ret > 0)
		fuse_copyattr(fuse_filp, passthrough_filp);

	fuse_file_accessed(fuse_filp, passthrough_filp);

	mutex_unlock(&fuse_inode->i_mutex);

	return ret;
}

int fuse_passthrough_mmap(struct file *file, struct vm_area_struct *vma)
{
	int ret;
	struct fuse_file *ff = file->private_data;
	struct file *passthrough_filp = ff->passthrough.filp;

	if (!passthrough_filp)
		return -EINVAL;
	if (!passthrough_filp->f_op->mmap)
		return -ENODEV;

	if (WARN_ON(file != vma->vm_file))
		return -EIO;

	vma->vm_file = get_file(passthrough_filp);
	ret = passthrough_filp->f_op->mmap(vma->vm_file, vma);
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
		return -EPERM;

	if (passthrough_fh <= 0)
		return -EINVAL;

	spin_lock(&fc->passthrough_req_lock);
	passthrough = idr_find(&fc->passthrough_req, passthrough_fh);
	if (passthrough)
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
