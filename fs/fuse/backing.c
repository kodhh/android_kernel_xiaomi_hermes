/*
 * FUSE backing file support
 * Copyright (C) 2021 Google, LLC
 *
 * This program can be distributed under the terms of the GNU GPL.
 */

#include <linux/sched.h>

#include "fuse_i.h"

#ifndef FUSE_SUPER_MAGIC
#define FUSE_SUPER_MAGIC 0x65735546
#endif

#include <linux/bpf.h>
#include <linux/file.h>
#include <linux/namei.h>
#include <linux/uio.h>
#include <linux/slab.h>
#include <linux/xattr.h>
#include <linux/aio.h>
#include <linux/fs_stack.h>
#include <linux/sched.h>
#include <linux/cred.h>
#include <linux/pagemap.h>

/*
 * Lock/unlock helpers using 3.10's i_mutex (not inode_lock)
 */
bool fuse_lock_inode(struct inode *inode)
{
	if (inode)
		mutex_lock(&inode->i_mutex);
	return inode != NULL;
}

void fuse_unlock_inode(struct inode *inode, bool locked)
{
	if (locked && inode)
		mutex_unlock(&inode->i_mutex);
}

static void fuse_file_accessed(struct file *dst_file, struct file *src_file)
{
	struct inode *dst_inode;
	struct inode *src_inode;

	if (dst_file->f_flags & O_NOATIME)
		return;

	dst_inode = dst_file->f_path.dentry->d_inode;
	src_inode = src_file->f_path.dentry->d_inode;

	if ((!timespec_equal(&dst_inode->i_mtime, &src_inode->i_mtime) ||
	     !timespec_equal(&dst_inode->i_ctime, &src_inode->i_ctime))) {
		dst_inode->i_mtime = src_inode->i_mtime;
		dst_inode->i_ctime = src_inode->i_ctime;
	}

	touch_atime(&dst_file->f_path);
}

static struct dentry *fuse_get_backing_dentry(struct dentry *dentry)
{
	struct fuse_dentry *fd = get_fuse_dentry(dentry);
	return fd ? fd->backing_path.dentry : NULL;
}

static struct path *fuse_get_backing_path(struct dentry *dentry)
{
	struct fuse_dentry *fd = get_fuse_dentry(dentry);
	if (!fd || !fd->backing_path.dentry)
		return NULL;
	return &fd->backing_path;
}

/* fuse_bpf_init/fuse_bpf_cleanup - module init/exit */
int __init fuse_bpf_init(void)
{
	return 0;
}

void __exit fuse_bpf_cleanup(void)
{
}

ssize_t fuse_bpf_simple_request(struct fuse_conn *fc, struct fuse_bpf_args *fa)
{
	struct fuse_req *req;
	ssize_t ret;

	req = fuse_get_req_nopages(fc);
	if (IS_ERR(req))
		return PTR_ERR(req);

	req->in.h.opcode = fa->opcode;
	req->in.h.nodeid = fa->nodeid;
	memcpy(req->in.args, fa->in_args,
	       sizeof(struct fuse_in_arg) * fa->in_numargs);
	memcpy(req->out.args, fa->out_args,
	       sizeof(struct fuse_arg) * fa->out_numargs);
	req->in.numargs = fa->in_numargs;
	req->out.numargs = fa->out_numargs;

	/* fuse_request_send sets unique */
	fuse_request_send(fc, req);
	ret = req->out.h.error;
	if (!ret) {
		int i;
		for (i = 0; i < fa->out_numargs && i < FUSE_MAX_OUT_ARGS; i++) {
			if (fa->out_args[i].value && req->out.args[i].size)
				memcpy(fa->out_args[i].value,
				       req->out.args[i].value,
				       min_t(size_t, fa->out_args[i].size,
					     req->out.args[i].size));
		}
	}
	fuse_put_request(fc, req);

	return ret;
}

struct bpf_prog *fuse_get_bpf_prog(struct file *file)
{
	struct bpf_prog *bpf_prog = ERR_PTR(-EINVAL);

	if (!file || IS_ERR(file))
		return bpf_prog;

	if (file->f_op != &bpf_prog_fops)
		goto out;

	bpf_prog = file->private_data;
	if (bpf_prog->type == BPF_PROG_TYPE_FUSE)
		bpf_prog_inc(bpf_prog);
	else
		bpf_prog = ERR_PTR(-EINVAL);

out:
	fput(file);
	return bpf_prog;
}

/*
 * Open
 */
int fuse_open_initialize(struct fuse_bpf_args *fa, struct fuse_open_io *foi,
			 struct inode *inode, struct file *file, bool isdir)
{
	fa->opcode = isdir ? FUSE_OPENDIR : FUSE_OPEN;
	fa->nodeid = get_fuse_inode(inode)->nodeid;
	fa->in_args[0].size = sizeof(foi->foi);
	fa->in_args[0].value = &foi->foi;
	fa->in_numargs = 1;
	foi->foi = (struct fuse_open_in) {
		.flags = file->f_flags & ~(O_CREAT | O_EXCL | O_NOCTTY | O_TRUNC),
	};
	fa->out_args[0].size = sizeof(foi->foo);
	fa->out_args[0].value = &foi->foo;
	fa->out_numargs = 1;

	return 0;
}

int fuse_open_backing(struct fuse_bpf_args *fa,
		      struct inode *inode, struct file *file, bool isdir)
{
	struct fuse_conn *fc = get_fuse_conn(inode);
	struct fuse_inode *fi = get_fuse_inode(inode);
	const struct fuse_open_in *foi = fa->in_args[0].value;
	struct fuse_file *ff;
	struct fuse_dentry *fd;
	struct file *backing_file;
	int mask;

	if (!fi->backing_inode)
		return -ENOENT;

	ff = fuse_file_alloc(fc);
	if (!ff)
		return -ENOMEM;
	file->private_data = ff;

	switch (foi->flags & O_ACCMODE) {
	case O_RDONLY:
		mask = MAY_READ;
		break;
	case O_WRONLY:
		mask = MAY_WRITE;
		break;
	case O_RDWR:
		mask = MAY_READ | MAY_WRITE;
		break;
	default:
		goto err_free;
	}

	if (inode_permission(fi->backing_inode, mask))
		goto err_free;

	fd = get_fuse_dentry(file->f_path.dentry);
	if (!fd || !fd->backing_path.dentry)
		goto err_free;

	backing_file = dentry_open(&fd->backing_path,
				   foi->flags, current_cred());
	if (IS_ERR(backing_file))
		goto err_free;

	ff->backing_file = backing_file;
	ff->backing_cred = get_current_cred();

	return 0;

err_free:
	file->private_data = NULL;
	fuse_file_free(ff);
	return -EACCES;
}

void *fuse_open_finalize(struct fuse_bpf_args *fa,
		       struct inode *inode, struct file *file, bool isdir)
{
	struct fuse_file *ff = file->private_data;
	struct fuse_open_out *foo = fa->out_args[0].value;

	if (ff) {
		ff->fh = foo->fh;
		ff->nodeid = get_fuse_inode(inode)->nodeid;
	}

	return NULL;
}

/*
 * Create + Open
 */
int fuse_create_open_initialize(
	struct fuse_bpf_args *fa, struct fuse_create_open_io *fcoi,
	struct inode *dir, struct dentry *entry,
	struct file *file, unsigned int flags, umode_t mode)
{
	fa->opcode = FUSE_CREATE;
	fa->nodeid = get_node_id(dir);
	fa->in_args[0].size = sizeof(fcoi->fci);
	fa->in_args[0].value = &fcoi->fci;
	fa->in_args[1].size = entry->d_name.len;
	fa->in_args[1].value = entry->d_name.name;
	fa->in_numargs = 2;
	fcoi->fci = (struct fuse_create_in) {
		.flags = flags,
		.mode = mode,
		.umask = current_umask(),
	};
	fa->out_args[0].size = sizeof(fcoi->feo);
	fa->out_args[0].value = &fcoi->feo;
	fa->out_args[1].size = sizeof(fcoi->foo);
	fa->out_args[1].value = &fcoi->foo;
	fa->out_numargs = 2;

	return 0;
}

int fuse_create_open_backing(
	struct fuse_bpf_args *fa,
	struct inode *dir, struct dentry *entry,
	struct file *file, unsigned int flags, umode_t mode)
{
	struct fuse_inode *dir_fi = get_fuse_inode(dir);
	struct fuse_create_in *fci = (struct fuse_create_in *)fa->in_args[0].value;
	struct path *dir_backing_path = fuse_get_backing_path(entry->d_parent);
	struct fuse_dentry *fd;
	struct dentry *backing_dentry = NULL;
	struct inode *backing_inode;
	struct file *backing_file;
	int ret;

	if (!dir_fi->backing_inode || !dir_backing_path)
		return -ENOENT;

	mutex_lock_nested(&dir_fi->backing_inode->i_mutex, I_MUTEX_PARENT);

	backing_dentry = lookup_one_len(entry->d_name.name,
					dir_backing_path->dentry,
					entry->d_name.len);
	if (IS_ERR(backing_dentry)) {
		mutex_unlock(&dir_fi->backing_inode->i_mutex);
		return PTR_ERR(backing_dentry);
	}

	if (backing_dentry->d_inode) {
		mutex_unlock(&dir_fi->backing_inode->i_mutex);
		dput(backing_dentry);
		return -EEXIST;
	}

	ret = vfs_create(dir_fi->backing_inode, backing_dentry, fci->mode,
			 true);
	mutex_unlock(&dir_fi->backing_inode->i_mutex);
	if (ret) {
		dput(backing_dentry);
		return ret;
	}

	backing_inode = backing_dentry->d_inode;
	if (!backing_inode) {
		dput(backing_dentry);
		return -ENOENT;
	}

	fd = get_fuse_dentry(entry);
	if (!fd) {
		fd = kzalloc(sizeof(struct fuse_dentry), GFP_KERNEL);
		if (!fd) {
			dput(backing_dentry);
			return -ENOMEM;
		}
		entry->d_fsdata = fd;
	}

	path_put(&fd->backing_path);
	fd->backing_path = (struct path) {
		.mnt = dir_backing_path->mnt,
		.dentry = backing_dentry,
	};
	path_get(&fd->backing_path);

	backing_file = dentry_open(&fd->backing_path,
				   fci->flags, current_cred());
	if (IS_ERR(backing_file)) {
		dput(backing_dentry);
		return PTR_ERR(backing_file);
	}

	get_file(backing_file);
	((struct fuse_file *)file->private_data)->backing_file = backing_file;
	((struct fuse_file *)file->private_data)->backing_cred = get_current_cred();

	return 0;
}

void *fuse_create_open_finalize(
	struct fuse_bpf_args *fa,
	struct inode *dir, struct dentry *entry,
	struct file *file, unsigned int flags, umode_t mode)
{
	struct fuse_entry_out *feo =
		(struct fuse_entry_out *)fa->out_args[0].value;
	struct fuse_open_out *foo =
		(struct fuse_open_out *)fa->out_args[1].value;
	struct fuse_file *ff = file->private_data;

	if (feo->nodeid)
		ff->nodeid = feo->nodeid;
	ff->fh = foo->fh;

	return NULL;
}

/*
 * Release
 */
int fuse_release_initialize(struct fuse_bpf_args *fa,
			    struct fuse_release_in *fri,
			    struct inode *inode, struct file *file)
{
	struct fuse_file *ff = file->private_data;

	fa->opcode = FUSE_RELEASE;
	fa->nodeid = ff->nodeid;
	fa->in_args[0].size = sizeof(*fri);
	fa->in_args[0].value = fri;
	fa->in_numargs = 1;
	*fri = (struct fuse_release_in) {
		.fh = ff->fh,
		.flags = file->f_flags,
	};
	fa->out_numargs = 0;

	return 0;
}

int fuse_releasedir_initialize(struct fuse_bpf_args *fa,
				struct fuse_release_in *fri,
				struct inode *inode, struct file *file)
{
	struct fuse_file *ff = file->private_data;

	fa->opcode = FUSE_RELEASEDIR;
	fa->nodeid = ff->nodeid;
	fa->in_args[0].size = sizeof(*fri);
	fa->in_args[0].value = fri;
	fa->in_numargs = 1;
	*fri = (struct fuse_release_in) {
		.fh = ff->fh,
		.flags = file->f_flags,
	};
	fa->out_numargs = 0;

	return 0;
}

int fuse_release_backing(struct fuse_bpf_args *fa,
			 struct inode *inode, struct file *file)
{
	return 0;
}

void *fuse_release_finalize(struct fuse_bpf_args *fa,
			    struct inode *inode, struct file *file)
{
	return NULL;
}

/*
 * Flush
 */
int fuse_flush_initialize(struct fuse_bpf_args *fa, struct fuse_flush_in *ffi,
			  struct file *file, fl_owner_t id)
{
	struct fuse_file *ff = file->private_data;

	fa->opcode = FUSE_FLUSH;
	fa->nodeid = ff->nodeid;
	fa->in_args[0].size = sizeof(*ffi);
	fa->in_args[0].value = ffi;
	fa->in_numargs = 1;
	*ffi = (struct fuse_flush_in) {
		.fh = ff->fh,
	};
	fa->out_numargs = 0;

	return 0;
}

int fuse_flush_backing(struct fuse_bpf_args *fa,
		       struct file *file, fl_owner_t id)
{
	struct fuse_file *ff = file->private_data;

	if (ff->backing_file && ff->backing_file->f_op->flush)
		return ff->backing_file->f_op->flush(ff->backing_file, id);

	return 0;
}

void *fuse_flush_finalize(struct fuse_bpf_args *fa,
			  struct file *file, fl_owner_t id)
{
	return NULL;
}

/*
 * Lseek
 */
int fuse_lseek_initialize(struct fuse_bpf_args *fa, struct fuse_lseek_io *fli,
			  struct file *file, loff_t offset, int whence)
{
	struct fuse_file *ff = file->private_data;

	fa->opcode = FUSE_LSEEK;
	fa->nodeid = ff->nodeid;
	fa->in_args[0].size = sizeof(fli->fli);
	fa->in_args[0].value = &fli->fli;
	fa->in_numargs = 1;
	fli->fli = (struct fuse_lseek_in) {
		.fh = ff->fh,
		.offset = offset,
		.whence = whence,
	};
	fa->out_args[0].size = sizeof(fli->flo);
	fa->out_args[0].value = &fli->flo;
	fa->out_numargs = 1;

	return 0;
}

int fuse_lseek_backing(struct fuse_bpf_args *fa,
		       struct file *file, loff_t offset, int whence)
{
	struct fuse_file *ff = file->private_data;
	struct file *backing_file = ff->backing_file;
	struct inode *inode;
	loff_t ret;

	if (!backing_file)
		return -ENOTCONN;

	inode = backing_file->f_path.dentry->d_inode;
	mutex_lock(&inode->i_mutex);
	ret = vfs_llseek(backing_file, offset, whence);
	mutex_unlock(&inode->i_mutex);

	if (ret < 0)
		return ret;

	return 0;
}

void *fuse_lseek_finalize(struct fuse_bpf_args *fa,
			  struct file *file, loff_t offset, int whence)
{
	struct fuse_lseek_out *flo =
		(struct fuse_lseek_out *)fa->out_args[0].value;

	file->f_pos = flo->offset;

	return NULL;
}

/*
 * Copy File Range (stub - not available in 3.10)
 */
int fuse_copy_file_range_initialize(struct fuse_bpf_args *fa,
				   struct fuse_copy_file_range_io *fcf,
				   struct file *file_in, loff_t pos_in,
				   struct file *file_out, loff_t pos_out,
				   size_t len, unsigned int flags)
{
	struct fuse_file *ff_in = file_in->private_data;

	fa->opcode = FUSE_COPY_FILE_RANGE;
	fa->nodeid = ff_in->nodeid;
	fa->in_args[0].size = sizeof(fcf->fci);
	fa->in_args[0].value = &fcf->fci;
	fa->in_numargs = 1;
	fcf->fci = (struct fuse_copy_file_range_in) {
		.fh_in = ff_in->fh,
		.off_in = pos_in,
		.nodeid_out = get_node_id(file_out->f_path.dentry->d_inode),
		.fh_out = ((struct fuse_file *)file_out->private_data)->fh,
		.off_out = pos_out,
		.len = len,
		.flags = flags,
	};
	fa->out_args[0].size = sizeof(fcf->fwo);
	fa->out_args[0].value = &fcf->fwo;
	fa->out_numargs = 1;

	return 0;
}

int fuse_copy_file_range_backing(struct fuse_bpf_args *fa,
				 struct file *file_in, loff_t pos_in,
				 struct file *file_out, loff_t pos_out,
				 size_t len, unsigned int flags)
{
	struct fuse_file *ff_in = file_in->private_data;
	struct fuse_file *ff_out = file_out->private_data;
	struct file *backing_in = ff_in->backing_file;
	struct file *backing_out = ff_out->backing_file;
	ssize_t ret;

	if (!backing_in || !backing_out)
		return -ENOTCONN;

	ret = generic_copy_file_range(backing_in, pos_in, backing_out, pos_out,
				      len, flags);
	return ret;
}

void *fuse_copy_file_range_finalize(struct fuse_bpf_args *fa,
				    struct file *file_in, loff_t pos_in,
				    struct file *file_out, loff_t pos_out,
				    size_t len, unsigned int flags)
{
	return NULL;
}

/*
 * Clone File Range
 */
int fuse_clone_file_range_initialize(struct fuse_bpf_args *fa,
				     struct fuse_clone_file_range_io *fcf,
				     struct file *file_in, loff_t pos_in,
				     struct file *file_out, loff_t pos_out,
				     u64 len)
{
	struct fuse_file *ff_in = file_in->private_data;

	fa->opcode = FUSE_COPY_FILE_RANGE;
	fa->nodeid = ff_in->nodeid;
	fa->in_args[0].size = sizeof(fcf->fci);
	fa->in_args[0].value = &fcf->fci;
	fa->in_numargs = 1;
	fcf->fci = (struct fuse_copy_file_range_in) {
		.fh_in = ff_in->fh,
		.off_in = pos_in,
		.nodeid_out = get_node_id(file_out->f_path.dentry->d_inode),
		.fh_out = ((struct fuse_file *)file_out->private_data)->fh,
		.off_out = pos_out,
		.len = len,
		.flags = 0,
	};
	fa->out_numargs = 0;

	return 0;
}

int fuse_clone_file_range_backing(struct fuse_bpf_args *fa,
				  struct file *file_in, loff_t pos_in,
				  struct file *file_out, loff_t pos_out,
				  u64 len)
{
	struct fuse_file *ff_in = file_in->private_data;
	struct fuse_file *ff_out = file_out->private_data;
	struct file *backing_in = ff_in->backing_file;
	struct file *backing_out = ff_out->backing_file;

	if (!backing_in || !backing_out)
		return -ENOTCONN;

	return do_clone_file_range(backing_in, pos_in, backing_out, pos_out,
				   len);
}

void *fuse_clone_file_range_finalize(struct fuse_bpf_args *fa,
				     struct file *file_in, loff_t pos_in,
				     struct file *file_out, loff_t pos_out,
				     u64 len)
{
	return NULL;
}

/*
 * Fsync
 */
int fuse_fsync_initialize(struct fuse_bpf_args *fa, struct fuse_fsync_in *ffi,
		   struct file *file, loff_t start, loff_t end, int datasync)
{
	struct fuse_file *ff = file->private_data;

	fa->opcode = FUSE_FSYNC;
	fa->nodeid = ff->nodeid;
	fa->in_args[0].size = sizeof(*ffi);
	fa->in_args[0].value = ffi;
	fa->in_numargs = 1;
	*ffi = (struct fuse_fsync_in) {
		.fh = ff->fh,
		.fsync_flags = datasync ? 1 : 0,
	};
	fa->out_numargs = 0;

	return 0;
}

int fuse_fsync_backing(struct fuse_bpf_args *fa,
		   struct file *file, loff_t start, loff_t end, int datasync)
{
	struct fuse_file *ff = file->private_data;
	struct file *backing_file = ff->backing_file;

	if (!backing_file)
		return -ENOTCONN;

	return vfs_fsync(backing_file, datasync);
}

void *fuse_fsync_finalize(struct fuse_bpf_args *fa,
		   struct file *file, loff_t start, loff_t end, int datasync)
{
	return NULL;
}

int fuse_dir_fsync_initialize(struct fuse_bpf_args *fa,
			      struct fuse_fsync_in *ffi,
			      struct file *file, loff_t start, loff_t end,
			      int datasync)
{
	struct fuse_file *ff = file->private_data;

	fa->opcode = FUSE_FSYNCDIR;
	fa->nodeid = ff->nodeid;
	fa->in_args[0].size = sizeof(*ffi);
	fa->in_args[0].value = ffi;
	fa->in_numargs = 1;
	*ffi = (struct fuse_fsync_in) {
		.fh = ff->fh,
		.fsync_flags = datasync ? 1 : 0,
	};
	fa->out_numargs = 0;

	return 0;
}

/*
 * Getxattr
 */
int fuse_getxattr_initialize(
		struct fuse_bpf_args *fa, struct fuse_getxattr_io *fgio,
		struct dentry *dentry, const char *name, void *value,
		size_t size)
{
	fa->opcode = FUSE_GETXATTR;
	fa->nodeid = get_node_id(dentry->d_inode);
	fa->in_args[0].size = sizeof(fgio->fgi);
	fa->in_args[0].value = &fgio->fgi;
	fa->in_args[1].size = strlen(name) + 1;
	fa->in_args[1].value = (void *)name;
	fa->in_numargs = 2;
	fgio->fgi = (struct fuse_getxattr_in) {
		.size = size,
	};
	fa->out_args[0].size = sizeof(fgio->fgo);
	fa->out_args[0].value = &fgio->fgo;
	fa->out_numargs = 1;

	return 0;
}

int fuse_getxattr_backing(
		struct fuse_bpf_args *fa,
		struct dentry *dentry, const char *name, void *value,
		size_t size)
{
	struct dentry *backing_dentry = fuse_get_backing_dentry(dentry);

	if (!backing_dentry)
		return -ENOENT;

	return vfs_getxattr(backing_dentry, name, value, size);
}

void *fuse_getxattr_finalize(
		struct fuse_bpf_args *fa,
		struct dentry *dentry, const char *name, void *value,
		size_t size)
{
	struct fuse_getxattr_out *fgo =
		(struct fuse_getxattr_out *)fa->out_args[0].value;

	return ERR_PTR(fgo->size);
}

/*
 * Listxattr
 */
int fuse_listxattr_initialize(struct fuse_bpf_args *fa,
			       struct fuse_getxattr_io *fgio,
			       struct dentry *dentry, char *list, size_t size)
{
	fa->opcode = FUSE_LISTXATTR;
	fa->nodeid = get_node_id(dentry->d_inode);
	fa->in_args[0].size = sizeof(fgio->fgi);
	fa->in_args[0].value = &fgio->fgi;
	fa->in_numargs = 1;
	fgio->fgi = (struct fuse_getxattr_in) {
		.size = size,
	};
	fa->out_args[0].size = sizeof(fgio->fgo);
	fa->out_args[0].value = &fgio->fgo;
	fa->out_numargs = 1;

	return 0;
}

int fuse_listxattr_backing(struct fuse_bpf_args *fa, struct dentry *dentry,
			   char *list, size_t size)
{
	struct dentry *backing_dentry = fuse_get_backing_dentry(dentry);

	if (!backing_dentry)
		return -ENOENT;

	return vfs_listxattr(backing_dentry, list, size);
}

void *fuse_listxattr_finalize(struct fuse_bpf_args *fa, struct dentry *dentry,
			      char *list, size_t size)
{
	struct fuse_getxattr_out *fgo =
		(struct fuse_getxattr_out *)fa->out_args[0].value;

	return ERR_PTR(fgo->size);
}

/*
 * Setxattr
 */
int fuse_setxattr_initialize(struct fuse_bpf_args *fa,
			     struct fuse_setxattr_in *fsxi,
			     struct dentry *dentry, const char *name,
			     const void *value, size_t size, int flags)
{
	fa->opcode = FUSE_SETXATTR;
	fa->nodeid = get_node_id(dentry->d_inode);
	fa->in_args[0].size = sizeof(*fsxi);
	fa->in_args[0].value = fsxi;
	fa->in_args[1].size = strlen(name) + 1;
	fa->in_args[1].value = (void *)name;
	if (value && size > 0) {
		fa->in_args[2].size = size;
		fa->in_args[2].value = value;
		fa->in_numargs = 3;
	} else {
		fa->in_numargs = 2;
	}
	*fsxi = (struct fuse_setxattr_in) {
		.size = size,
		.flags = flags,
	};
	fa->out_numargs = 0;

	return 0;
}

int fuse_setxattr_backing(struct fuse_bpf_args *fa, struct dentry *dentry,
			  const char *name, const void *value, size_t size,
			  int flags)
{
	struct dentry *backing_dentry = fuse_get_backing_dentry(dentry);

	if (!backing_dentry)
		return -ENOENT;

	return vfs_setxattr(backing_dentry, name, value, size, flags);
}

void *fuse_setxattr_finalize(struct fuse_bpf_args *fa, struct dentry *dentry,
			     const char *name, const void *value, size_t size,
			     int flags)
{
	return NULL;
}

/*
 * Removexattr
 */
int fuse_removexattr_initialize(struct fuse_bpf_args *fa,
				struct fuse_dummy_io *unused,
				struct dentry *dentry, const char *name)
{
	fa->opcode = FUSE_REMOVEXATTR;
	fa->nodeid = get_node_id(dentry->d_inode);
	fa->in_args[0].size = strlen(name) + 1;
	fa->in_args[0].value = (void *)name;
	fa->in_numargs = 1;
	fa->out_numargs = 0;

	return 0;
}

int fuse_removexattr_backing(struct fuse_bpf_args *fa,
			     struct dentry *dentry, const char *name)
{
	struct dentry *backing_dentry = fuse_get_backing_dentry(dentry);

	if (!backing_dentry)
		return -ENOENT;

	return vfs_removexattr(backing_dentry, name);
}

void *fuse_removexattr_finalize(struct fuse_bpf_args *fa,
				struct dentry *dentry, const char *name)
{
	return NULL;
}

/*
 * Read/Write (adapted for 3.10 aio_read/aio_write API)
 */
int fuse_file_read_iter_initialize(
		struct fuse_bpf_args *fa, struct fuse_file_read_iter_io *frio,
		struct kiocb *iocb, struct iov_iter *to)
{
	struct file *file = iocb->ki_filp;
	struct fuse_file *ff = file->private_data;

	fa->opcode = FUSE_READ;
	fa->nodeid = ff->nodeid;
	fa->in_args[0].size = sizeof(frio->fri);
	fa->in_args[0].value = &frio->fri;
	fa->in_numargs = 1;
	frio->fri = (struct fuse_read_in) {
		.fh = ff->fh,
		.offset = iocb->ki_pos,
		.size = iov_iter_count(to),
	};
	fa->out_args[0].size = sizeof(frio->frio);
	fa->out_args[0].value = &frio->frio;
	fa->out_numargs = 1;

	return 0;
}

int fuse_file_read_iter_backing(struct fuse_bpf_args *fa,
		struct kiocb *iocb, struct iov_iter *to)
{
	struct file *file = iocb->ki_filp;
	struct fuse_file *ff = file->private_data;
	struct file *backing_file = ff->backing_file;
	const struct cred *old_cred;
	struct kiocb local_iocb;
	ssize_t ret;

	if (!backing_file)
		return -ENOTCONN;

	old_cred = override_creds(ff->backing_cred);
	init_sync_kiocb(&local_iocb, backing_file);
	local_iocb.ki_pos = iocb->ki_pos;
	local_iocb.ki_nbytes = iov_iter_count(to);

	ret = backing_file->f_op->aio_read(&local_iocb, to->iov, to->nr_segs,
					   local_iocb.ki_pos);
	revert_creds(old_cred);

	if (ret >= 0)
		iocb->ki_pos = local_iocb.ki_pos;

	return ret;
}

void *fuse_file_read_iter_finalize(struct fuse_bpf_args *fa,
		struct kiocb *iocb, struct iov_iter *to)
{
	struct fuse_read_iter_out *frio =
		(struct fuse_read_iter_out *)fa->out_args[0].value;

	return ERR_PTR(frio->ret);
}

int fuse_file_write_iter_initialize(
		struct fuse_bpf_args *fa, struct fuse_file_write_iter_io *fwio,
		struct kiocb *iocb, struct iov_iter *from)
{
	struct file *file = iocb->ki_filp;
	struct fuse_file *ff = file->private_data;

	fa->opcode = FUSE_WRITE;
	fa->nodeid = ff->nodeid;
	fa->in_args[0].size = sizeof(fwio->fwi);
	fa->in_args[0].value = &fwio->fwi;
	fa->in_numargs = 1;
	fwio->fwi = (struct fuse_write_in) {
		.fh = ff->fh,
		.offset = iocb->ki_pos,
		.size = iov_iter_count(from),
	};
	fa->out_args[0].size = sizeof(fwio->fwo);
	fa->out_args[0].value = &fwio->fwo;
	fa->out_numargs = 1;

	return 0;
}

int fuse_file_write_iter_backing(struct fuse_bpf_args *fa,
		struct kiocb *iocb, struct iov_iter *from)
{
	struct file *file = iocb->ki_filp;
	struct fuse_file *ff = file->private_data;
	struct file *backing_file = ff->backing_file;
	const struct cred *old_cred;
	struct kiocb local_iocb;
	ssize_t ret;

	if (!backing_file)
		return -ENOTCONN;

	mutex_lock(&backing_file->f_path.dentry->d_inode->i_mutex);

	fuse_copyattr(file, backing_file);

	old_cred = override_creds(ff->backing_cred);
	init_sync_kiocb(&local_iocb, backing_file);
	local_iocb.ki_pos = iocb->ki_pos;
	local_iocb.ki_nbytes = iov_iter_count(from);

	file_start_write(backing_file);
	ret = backing_file->f_op->aio_write(&local_iocb, from->iov,
					    from->nr_segs, local_iocb.ki_pos);
	file_end_write(backing_file);
	revert_creds(old_cred);

	if (ret >= 0) {
		iocb->ki_pos = local_iocb.ki_pos;
		fuse_copyattr(file, backing_file);
	}

	mutex_unlock(&backing_file->f_path.dentry->d_inode->i_mutex);

	return ret;
}

void *fuse_file_write_iter_finalize(struct fuse_bpf_args *fa,
		struct kiocb *iocb, struct iov_iter *from)
{
	struct fuse_file_write_iter_io *fwio =
		(struct fuse_file_write_iter_io *)fa->out_args[0].value;

	return ERR_PTR(fwio->fwio.ret);
}

/*
 * Mmap
 */
ssize_t fuse_backing_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct fuse_file *ff = file->private_data;
	struct file *backing_file = ff->backing_file;
	const struct cred *old_cred;
	int ret;

	if (!backing_file)
		return -ENOTCONN;

	if (!backing_file->f_op->mmap)
		return -ENODEV;

	if (WARN_ON(file != vma->vm_file))
		return -EIO;

	vma->vm_file = get_file(backing_file);
	old_cred = override_creds(ff->backing_cred);
	ret = call_mmap(vma->vm_file, vma);
	revert_creds(old_cred);

	if (ret)
		fput(backing_file);
	else
		fput(file);

	fuse_file_accessed(file, backing_file);

	return ret;
}

/*
 * Fallocate
 */
int fuse_file_fallocate_initialize(struct fuse_bpf_args *fa,
		struct fuse_fallocate_in *ffi,
		struct file *file, int mode, loff_t offset, loff_t length)
{
	struct fuse_file *ff = file->private_data;

	fa->opcode = FUSE_FALLOCATE;
	fa->nodeid = ff->nodeid;
	fa->in_args[0].size = sizeof(*ffi);
	fa->in_args[0].value = ffi;
	fa->in_numargs = 1;
	*ffi = (struct fuse_fallocate_in) {
		.fh = ff->fh,
		.offset = offset,
		.length = length,
		.mode = mode,
	};
	fa->out_numargs = 0;

	return 0;
}

int fuse_file_fallocate_backing(struct fuse_bpf_args *fa,
		struct file *file, int mode, loff_t offset, loff_t length)
{
	struct fuse_file *ff = file->private_data;
	struct file *backing_file = ff->backing_file;

	if (!backing_file)
		return -ENOTCONN;

	return do_fallocate(backing_file, mode, offset, length);
}

void *fuse_file_fallocate_finalize(struct fuse_bpf_args *fa,
		struct file *file, int mode, loff_t offset, loff_t length)
{
	return NULL;
}

/*
 * Lookup
 */
int fuse_lookup_initialize(struct fuse_bpf_args *fa, struct fuse_lookup_io *feo,
	       struct inode *dir, struct dentry *entry, unsigned int flags)
{
	fa->opcode = FUSE_LOOKUP;
	fa->nodeid = get_node_id(dir);
	fa->in_args[0].size = entry->d_name.len + 1;
	fa->in_args[0].value = (void *)entry->d_name.name;
	fa->in_numargs = 1;
	fa->out_args[0].size = sizeof(feo->feo);
	fa->out_args[0].value = &feo->feo;
	fa->out_args[1].size = sizeof(feo->feb);
	fa->out_args[1].value = &feo->feb;
	fa->out_numargs = 2;

	return 0;
}

int fuse_lookup_backing(struct fuse_bpf_args *fa, struct inode *dir,
			  struct dentry *entry, unsigned int flags)
{
	struct fuse_inode *dir_fi = get_fuse_inode(dir);
	struct path *dir_backing_path = fuse_get_backing_path(entry->d_parent);
	struct dentry *backing_dentry;
	struct fuse_dentry *fuse_entry;

	if (!dir_fi->backing_inode || !dir_backing_path)
		return -ENOENT;

	mutex_lock_nested(&dir_fi->backing_inode->i_mutex, I_MUTEX_PARENT);
	backing_dentry = lookup_one_len(entry->d_name.name,
					dir_backing_path->dentry,
					entry->d_name.len);
	mutex_unlock(&dir_fi->backing_inode->i_mutex);

	if (IS_ERR(backing_dentry))
		return PTR_ERR(backing_dentry);

	if (!backing_dentry->d_inode) {
		dput(backing_dentry);
		return -ENOENT;
	}

	fuse_entry = get_fuse_dentry(entry);
	if (!fuse_entry) {
		fuse_entry = kzalloc(sizeof(struct fuse_dentry), GFP_KERNEL);
		if (!fuse_entry) {
			dput(backing_dentry);
			return -ENOMEM;
		}
		entry->d_fsdata = fuse_entry;
	}
	path_put(&fuse_entry->backing_path);
	fuse_entry->backing_path = (struct path) {
		.mnt = mntget(dir_backing_path->mnt),
		.dentry = backing_dentry,
	};

	return 0;
}

int fuse_handle_backing(struct fuse_entry_bpf *feb, struct inode **backing_inode,
			struct path *backing_path)
{
	switch (feb->out.backing_action) {
	case FUSE_ACTION_KEEP:
		break;

	case FUSE_ACTION_REMOVE:
		iput(*backing_inode);
		*backing_inode = NULL;
		path_put(backing_path);
		*backing_path = (struct path) {};
		break;

	case FUSE_ACTION_REPLACE: {
		struct file *backing_file = feb->backing_file;

		if (!backing_file || IS_ERR(backing_file))
			return backing_file ? PTR_ERR(backing_file) : -EINVAL;

		if (*backing_inode)
			iput(*backing_inode);
		*backing_inode = backing_file->f_inode;
		ihold(*backing_inode);

		path_put(backing_path);
		*backing_path = backing_file->f_path;
		path_get(backing_path);

		fput(backing_file);
		break;
	}

	default:
		return -EINVAL;
	}

	return 0;
}

int fuse_handle_bpf_prog(struct fuse_entry_bpf *feb, struct inode *parent,
			 struct bpf_prog **bpf)
{
	struct fuse_inode *pi;

	if (feb->out.bpf_action == FUSE_ACTION_KEEP && !parent)
		return 0;

	if (*bpf) {
		bpf_prog_put(*bpf);
		*bpf = NULL;
	}

	switch (feb->out.bpf_action) {
	case FUSE_ACTION_KEEP:
		pi = get_fuse_inode(parent);
		*bpf = pi->bpf;
		if (*bpf)
			bpf_prog_inc(*bpf);
		break;

	case FUSE_ACTION_REMOVE:
		break;

	case FUSE_ACTION_REPLACE: {
		struct file *bpf_file = feb->bpf_file;
		struct bpf_prog *bpf_prog = ERR_PTR(-EINVAL);

		if (bpf_file && !IS_ERR(bpf_file))
			bpf_prog = fuse_get_bpf_prog(bpf_file);

		if (IS_ERR(bpf_prog))
			return PTR_ERR(bpf_prog);

		*bpf = bpf_prog;
		break;
	}

	default:
		return -EINVAL;
	}

	return 0;
}

struct dentry *fuse_lookup_finalize(struct fuse_bpf_args *fa,
				    struct inode *dir,
				    struct dentry *entry, unsigned int flags)
{
	struct fuse_entry_bpf *feb = (struct fuse_entry_bpf *)fa->out_args[1].value;
	struct inode *inode = NULL;
	struct dentry *d;

	if (fa->out_args[0].value) {
		struct fuse_entry_out *feo =
			(struct fuse_entry_out *)fa->out_args[0].value;
		if (feo->nodeid) {
			inode = fuse_iget(dir->i_sb, feo->nodeid, feo->generation,
					  &feo->attr, feo->entry_valid,
					  feo->attr_valid);
		}
	}

	/*
	 * BPF-only lookup path: feo->nodeid is always 0 because it was
	 * never filled by a userspace LOOKUP reply.  Create the FUSE inode
	 * from the backing dentry directly, matching 5.10 behaviour.
	 */
	if (!inode) {
		struct fuse_dentry *fd = get_fuse_dentry(entry);
		if (fd && fd->backing_path.dentry &&
		    fd->backing_path.dentry->d_inode) {
			struct inode *backing_inode =
				fd->backing_path.dentry->d_inode;
			inode = fuse_iget_backing(dir->i_sb, backing_inode);
			if (inode) {
				struct fuse_inode *fi = get_fuse_inode(inode);
				fi->nodeid = (unsigned long)backing_inode;
			}
		}
	}

	if (!IS_ERR_OR_NULL(inode)) {
		d = d_splice_alias(inode, entry);
		if (IS_ERR(d))
			return d;
		if (d)
			entry = d;

		if (entry->d_inode) {
			struct fuse_inode *fi = get_fuse_inode(entry->d_inode);
			int err;

			err = fuse_handle_bpf_prog(feb, dir, &fi->bpf);
			if (err)
				return ERR_PTR(err);

			if (feb->out.backing_action != FUSE_ACTION_KEEP) {
				struct fuse_dentry *fd = get_fuse_dentry(entry);
				if (fd)
					fuse_handle_backing(feb, &fi->backing_inode,
							    &fd->backing_path);
			}
		}
	}

	return entry;
}

int fuse_revalidate_backing(struct fuse_bpf_args *fa, struct inode *dir,
			   struct dentry *entry, unsigned int flags)
{
	struct dentry *backing_dentry = fuse_get_backing_dentry(entry);

	if (!backing_dentry)
		return -ENOENT;

	spin_lock(&backing_dentry->d_lock);
	if (d_unhashed(backing_dentry)) {
		spin_unlock(&backing_dentry->d_lock);
		return -ENOENT;
	}
	spin_unlock(&backing_dentry->d_lock);

	if (backing_dentry->d_op && backing_dentry->d_op->d_revalidate) {
		int ret = backing_dentry->d_op->d_revalidate(backing_dentry,
							     flags);
		if (ret <= 0)
			return ret ?: -ENOENT;
	}

	return 0;
}

void *fuse_revalidate_finalize(struct fuse_bpf_args *fa, struct inode *dir,
			   struct dentry *entry, unsigned int flags)
{
	return NULL;
}

/*
 * Canonical Path
 */
int fuse_canonical_path_initialize(struct fuse_bpf_args *fa,
				   struct fuse_dummy_io *fdi,
				   const struct path *path,
				   struct path *canonical_path)
{
	fa->opcode = FUSE_CANONICAL_PATH;
	fa->nodeid = get_node_id(path->dentry->d_inode);
	fa->in_numargs = 0;
	fa->out_numargs = 0;

	return 0;
}

int fuse_canonical_path_backing(struct fuse_bpf_args *fa,
				const struct path *path,
				struct path *canonical_path)
{
	get_fuse_backing_path(path->dentry, canonical_path);
	return 0;
}

void *fuse_canonical_path_finalize(struct fuse_bpf_args *fa,
				   const struct path *path,
				   struct path *canonical_path)
{
	return NULL;
}

/*
 * Mknod
 */
int fuse_mknod_initialize(
		struct fuse_bpf_args *fa, struct fuse_mknod_in *fmi,
		struct inode *dir, struct dentry *entry, umode_t mode, dev_t rdev)
{
	fa->opcode = FUSE_MKNOD;
	fa->nodeid = get_node_id(dir);
	fa->in_args[0].size = sizeof(*fmi);
	fa->in_args[0].value = fmi;
	fa->in_args[1].size = entry->d_name.len;
	fa->in_args[1].value = entry->d_name.name;
	fa->in_numargs = 2;
	*fmi = (struct fuse_mknod_in) {
		.mode = mode,
		.rdev = new_encode_dev(rdev),
		.umask = current_umask(),
	};
	fa->out_numargs = 0;

	return 0;
}

int fuse_mknod_backing(
		struct fuse_bpf_args *fa,
		struct inode *dir, struct dentry *entry, umode_t mode, dev_t rdev)
{
	struct fuse_inode *dir_fi = get_fuse_inode(dir);
	struct path *dir_backing_path = fuse_get_backing_path(entry->d_parent);
	struct fuse_dentry *fd;
	struct path backing_path;
	struct inode *inode;
	struct dentry *backing_dentry;
	int ret;

	if (!dir_fi->backing_inode || !dir_backing_path)
		return -ENOENT;

	mutex_lock_nested(&dir_fi->backing_inode->i_mutex, I_MUTEX_PARENT);
	backing_dentry = lookup_one_len(entry->d_name.name,
					dir_backing_path->dentry,
					entry->d_name.len);
	if (IS_ERR(backing_dentry)) {
		mutex_unlock(&dir_fi->backing_inode->i_mutex);
		return PTR_ERR(backing_dentry);
	}

	ret = vfs_mknod(dir_fi->backing_inode, backing_dentry, mode, rdev);
	mutex_unlock(&dir_fi->backing_inode->i_mutex);

	if (ret) {
		dput(backing_dentry);
		return ret;
	}

	if (!backing_dentry->d_inode) {
		dput(backing_dentry);
		return -ENOENT;
	}

	backing_path = (struct path) {
		.mnt = mntget(dir_backing_path->mnt),
		.dentry = backing_dentry,
	};

	fd = get_fuse_dentry(entry);
	if (!fd) {
		fd = kzalloc(sizeof(struct fuse_dentry), GFP_KERNEL);
		if (!fd) {
			path_put(&backing_path);
			return -ENOMEM;
		}
		entry->d_fsdata = fd;
	}
	path_put(&fd->backing_path);
	fd->backing_path = backing_path;

	inode = fuse_iget_backing(dir->i_sb, backing_dentry->d_inode);
	if (IS_ERR_OR_NULL(inode))
		return inode ? PTR_ERR(inode) : -ENOMEM;

	d_instantiate(entry, inode);

	if (get_fuse_inode(inode)->bpf)
		bpf_prog_put(get_fuse_inode(inode)->bpf);
	get_fuse_inode(inode)->bpf = fd->bpf;
	fd->bpf = NULL;

	return 0;
}

void *fuse_mknod_finalize(
		struct fuse_bpf_args *fa,
		struct inode *dir, struct dentry *entry, umode_t mode, dev_t rdev)
{
	return NULL;
}

/*
 * Mkdir
 */
int fuse_mkdir_initialize(
		struct fuse_bpf_args *fa, struct fuse_mkdir_in *fmi,
		struct inode *dir, struct dentry *entry, umode_t mode)
{
	fa->opcode = FUSE_MKDIR;
	fa->nodeid = get_node_id(dir);
	fa->in_args[0].size = sizeof(*fmi);
	fa->in_args[0].value = fmi;
	fa->in_args[1].size = entry->d_name.len;
	fa->in_args[1].value = entry->d_name.name;
	fa->in_numargs = 2;
	*fmi = (struct fuse_mkdir_in) {
		.mode = mode,
		.umask = current_umask(),
	};
	fa->out_numargs = 0;

	return 0;
}

int fuse_mkdir_backing(
		struct fuse_bpf_args *fa,
		struct inode *dir, struct dentry *entry, umode_t mode)
{
	struct fuse_inode *dir_fi = get_fuse_inode(dir);
	struct path *dir_backing_path = fuse_get_backing_path(entry->d_parent);
	struct fuse_dentry *fd;
	struct path backing_path;
	struct inode *inode;
	struct dentry *backing_dentry;
	int ret;

	if (!dir_fi->backing_inode || !dir_backing_path)
		return -ENOENT;

	mutex_lock_nested(&dir_fi->backing_inode->i_mutex, I_MUTEX_PARENT);
	backing_dentry = lookup_one_len(entry->d_name.name,
					dir_backing_path->dentry,
					entry->d_name.len);
	if (IS_ERR(backing_dentry)) {
		mutex_unlock(&dir_fi->backing_inode->i_mutex);
		return PTR_ERR(backing_dentry);
	}

	ret = vfs_mkdir(dir_fi->backing_inode, backing_dentry, mode);
	mutex_unlock(&dir_fi->backing_inode->i_mutex);

	if (ret) {
		dput(backing_dentry);
		return ret;
	}

	if (!backing_dentry->d_inode) {
		dput(backing_dentry);
		return -ENOENT;
	}

	backing_path = (struct path) {
		.mnt = mntget(dir_backing_path->mnt),
		.dentry = backing_dentry,
	};

	fd = get_fuse_dentry(entry);
	if (!fd) {
		fd = kzalloc(sizeof(struct fuse_dentry), GFP_KERNEL);
		if (!fd) {
			path_put(&backing_path);
			return -ENOMEM;
		}
		entry->d_fsdata = fd;
	}
	path_put(&fd->backing_path);
	fd->backing_path = backing_path;

	inode = fuse_iget_backing(dir->i_sb, backing_dentry->d_inode);
	if (IS_ERR_OR_NULL(inode))
		return inode ? PTR_ERR(inode) : -ENOMEM;

	d_instantiate(entry, inode);

	if (get_fuse_inode(inode)->bpf)
		bpf_prog_put(get_fuse_inode(inode)->bpf);
	get_fuse_inode(inode)->bpf = fd->bpf;
	fd->bpf = NULL;

	return 0;
}

void *fuse_mkdir_finalize(
		struct fuse_bpf_args *fa,
		struct inode *dir, struct dentry *entry, umode_t mode)
{
	return NULL;
}

/*
 * Rmdir
 */
int fuse_rmdir_initialize(
		struct fuse_bpf_args *fa, struct fuse_dummy_io *fmi,
		struct inode *dir, struct dentry *entry)
{
	fa->opcode = FUSE_RMDIR;
	fa->nodeid = get_node_id(dir);
	fa->in_args[0].size = entry->d_name.len;
	fa->in_args[0].value = entry->d_name.name;
	fa->in_numargs = 1;
	fa->out_numargs = 0;

	return 0;
}

int fuse_rmdir_backing(
		struct fuse_bpf_args *fa,
		struct inode *dir, struct dentry *entry)
{
	struct fuse_inode *dir_fi = get_fuse_inode(dir);
	struct path *backing_path = fuse_get_backing_path(entry);
	struct dentry *backing_parent;
	struct inode *backing_inode;
	int ret;

	if (!dir_fi->backing_inode || !backing_path)
		return -ENOENT;

	backing_parent = dget_parent(backing_path->dentry);
	backing_inode = backing_parent->d_inode;

	mutex_lock_nested(&backing_inode->i_mutex, I_MUTEX_PARENT);
	ret = vfs_rmdir(backing_inode, backing_path->dentry);
	mutex_unlock(&backing_inode->i_mutex);

	dput(backing_parent);

	if (ret == 0)
		d_drop(entry);

	return ret;
}

void *fuse_rmdir_finalize(
		struct fuse_bpf_args *fa,
		struct inode *dir, struct dentry *entry)
{
	return NULL;
}

/*
 * Unlink
 */
int fuse_unlink_initialize(
		struct fuse_bpf_args *fa, struct fuse_dummy_io *fmi,
		struct inode *dir, struct dentry *entry)
{
	fa->opcode = FUSE_UNLINK;
	fa->nodeid = get_node_id(dir);
	fa->in_args[0].size = entry->d_name.len;
	fa->in_args[0].value = entry->d_name.name;
	fa->in_numargs = 1;
	fa->out_numargs = 0;

	return 0;
}

int fuse_unlink_backing(
		struct fuse_bpf_args *fa,
		struct inode *dir, struct dentry *entry)
{
	struct fuse_inode *dir_fi = get_fuse_inode(dir);
	struct path *backing_path = fuse_get_backing_path(entry);
	struct dentry *backing_parent;
	struct inode *backing_inode;
	int ret;

	if (!dir_fi->backing_inode || !backing_path)
		return -ENOENT;

	backing_parent = dget_parent(backing_path->dentry);
	backing_inode = backing_parent->d_inode;

	mutex_lock_nested(&backing_inode->i_mutex, I_MUTEX_PARENT);
	ret = vfs_unlink(backing_inode, backing_path->dentry, NULL);
	mutex_unlock(&backing_inode->i_mutex);

	dput(backing_parent);

	if (ret == 0)
		d_drop(entry);

	return ret;
}

void *fuse_unlink_finalize(
		struct fuse_bpf_args *fa,
		struct inode *dir, struct dentry *entry)
{
	return NULL;
}

/*
 * Rename
 */
static int fuse_rename_backing_common(struct fuse_bpf_args *fa,
	struct inode *olddir, struct dentry *oldent,
	struct inode *newdir, struct dentry *newent,
	unsigned int flags)
{
	struct fuse_inode *olddir_fi = get_fuse_inode(olddir);
	struct fuse_inode *newdir_fi = get_fuse_inode(newdir);
	struct path *old_backing_path;
	struct path *new_backing_path;
	struct dentry *old_backing_dir_dentry;
	struct dentry *new_backing_dir_dentry;
	struct dentry *old_backing_dentry;
	struct dentry *new_backing_dentry;
	struct inode *target_inode;
	int ret;

	if (!olddir_fi->backing_inode || !newdir_fi->backing_inode)
		return -ENOENT;

	old_backing_path = fuse_get_backing_path(oldent);
	new_backing_path = fuse_get_backing_path(newent);
	if (!old_backing_path || !new_backing_path)
		return -ENOENT;

	old_backing_dentry = old_backing_path->dentry;
	new_backing_dentry = new_backing_path->dentry;
	old_backing_dir_dentry = dget_parent(old_backing_dentry);
	new_backing_dir_dentry = dget_parent(new_backing_dentry);

	lock_rename(old_backing_dir_dentry, new_backing_dir_dentry);

	target_inode = new_backing_dentry->d_inode;
	ret = vfs_rename(old_backing_dir_dentry->d_inode, old_backing_dentry,
			 new_backing_dir_dentry->d_inode, new_backing_dentry,
			 NULL, flags);

	if (!ret) {
		if (target_inode)
			fsstack_copy_attr_all(target_inode, target_inode);
		fsstack_copy_attr_all(old_backing_dir_dentry->d_inode,
				     old_backing_dir_dentry->d_inode);
	}

	unlock_rename(old_backing_dir_dentry, new_backing_dir_dentry);
	dput(old_backing_dir_dentry);
	dput(new_backing_dir_dentry);

	return ret;
}

int fuse_rename2_initialize(struct fuse_bpf_args *fa,
			    struct fuse_rename2_in *fri,
			    struct inode *olddir, struct dentry *oldent,
			    struct inode *newdir, struct dentry *newent,
			    unsigned int flags)
{
	fa->opcode = FUSE_RENAME2;
	fa->nodeid = get_node_id(olddir);
	fa->in_args[0].size = sizeof(*fri);
	fa->in_args[0].value = fri;
	fa->in_args[1].size = oldent->d_name.len;
	fa->in_args[1].value = oldent->d_name.name;
	fa->in_args[2].size = newent->d_name.len;
	fa->in_args[2].value = newent->d_name.name;
	fa->in_numargs = 3;
	*fri = (struct fuse_rename2_in) {
		.newdir = get_node_id(newdir),
		.flags = flags,
	};
	fa->out_numargs = 0;

	return 0;
}

int fuse_rename2_backing(struct fuse_bpf_args *fa,
			 struct inode *olddir, struct dentry *oldent,
			 struct inode *newdir, struct dentry *newent,
			 unsigned int flags)
{
	return fuse_rename_backing_common(fa, olddir, oldent, newdir, newent,
					 flags);
}

void *fuse_rename2_finalize(struct fuse_bpf_args *fa,
			    struct inode *olddir, struct dentry *oldent,
			    struct inode *newdir, struct dentry *newent,
			    unsigned int flags)
{
	return NULL;
}

int fuse_rename_initialize(struct fuse_bpf_args *fa,
			   struct fuse_rename_in *fri,
			   struct inode *olddir, struct dentry *oldent,
			   struct inode *newdir, struct dentry *newent)
{
	fa->opcode = FUSE_RENAME;
	fa->nodeid = get_node_id(olddir);
	fa->in_args[0].size = sizeof(*fri);
	fa->in_args[0].value = fri;
	fa->in_args[1].size = oldent->d_name.len;
	fa->in_args[1].value = oldent->d_name.name;
	fa->in_args[2].size = newent->d_name.len;
	fa->in_args[2].value = newent->d_name.name;
	fa->in_numargs = 3;
	*fri = (struct fuse_rename_in) {
		.newdir = get_node_id(newdir),
	};
	fa->out_numargs = 0;

	return 0;
}

int fuse_rename_backing(struct fuse_bpf_args *fa,
			struct inode *olddir, struct dentry *oldent,
			struct inode *newdir, struct dentry *newent)
{
	return fuse_rename_backing_common(fa, olddir, oldent, newdir, newent,
					 0);
}

void *fuse_rename_finalize(struct fuse_bpf_args *fa,
			   struct inode *olddir, struct dentry *oldent,
			   struct inode *newdir, struct dentry *newent)
{
	return NULL;
}

/*
 * Link
 */
int fuse_link_initialize(struct fuse_bpf_args *fa, struct fuse_link_in *fli,
			  struct dentry *entry, struct inode *dir,
			  struct dentry *newent)
{
	fa->opcode = FUSE_LINK;
	fa->nodeid = get_node_id(entry->d_inode);
	fa->in_args[0].size = sizeof(*fli);
	fa->in_args[0].value = fli;
	fa->in_args[1].size = newent->d_name.len;
	fa->in_args[1].value = newent->d_name.name;
	fa->in_numargs = 2;
	*fli = (struct fuse_link_in) {
		.oldnodeid = get_node_id(entry->d_inode),
	};
	fa->out_numargs = 0;

	return 0;
}

int fuse_link_backing(struct fuse_bpf_args *fa, struct dentry *entry,
		      struct inode *dir, struct dentry *newent)
{
	struct fuse_inode *newdir_fi = get_fuse_inode(dir);
	struct path *old_backing_path = fuse_get_backing_path(entry);
	struct path *new_backing_path = fuse_get_backing_path(newent);
	struct fuse_dentry *new_fuse_entry;
	int ret;

	if (!newdir_fi->backing_inode || !old_backing_path || !new_backing_path)
		return -ENOENT;

	mutex_lock_nested(&newdir_fi->backing_inode->i_mutex, I_MUTEX_PARENT);
	ret = vfs_link(old_backing_path->dentry, newdir_fi->backing_inode,
		       new_backing_path->dentry, NULL);
	mutex_unlock(&newdir_fi->backing_inode->i_mutex);

	if (ret)
		return ret;

	new_fuse_entry = get_fuse_dentry(newent);
	if (!new_fuse_entry) {
		new_fuse_entry = kzalloc(sizeof(struct fuse_dentry), GFP_KERNEL);
		if (!new_fuse_entry)
			return -ENOMEM;
		newent->d_fsdata = new_fuse_entry;
	}
	path_put(&new_fuse_entry->backing_path);
	new_fuse_entry->backing_path = (struct path) {
		.mnt = mntget(old_backing_path->mnt),
		.dentry = dget(new_backing_path->dentry),
	};

	return 0;
}

void *fuse_link_finalize(struct fuse_bpf_args *fa, struct dentry *entry,
			 struct inode *dir, struct dentry *newent)
{
	return NULL;
}

/*
 * Symlink
 */
int fuse_symlink_initialize(
		struct fuse_bpf_args *fa, struct fuse_dummy_io *unused,
		struct inode *dir, struct dentry *entry, const char *link, int len)
{
	fa->opcode = FUSE_SYMLINK;
	fa->nodeid = get_node_id(dir);
	fa->in_args[0].size = entry->d_name.len;
	fa->in_args[0].value = entry->d_name.name;
	fa->in_args[1].size = len;
	fa->in_args[1].value = (void *)link;
	fa->in_numargs = 2;
	fa->out_numargs = 0;

	return 0;
}

int fuse_symlink_backing(
		struct fuse_bpf_args *fa,
		struct inode *dir, struct dentry *entry, const char *link, int len)
{
	struct fuse_inode *dir_fi = get_fuse_inode(dir);
	struct path *dir_backing_path = fuse_get_backing_path(entry->d_parent);
	struct fuse_dentry *fd;
	struct path backing_path;
	struct inode *inode;
	struct dentry *backing_dentry;
	int ret;

	if (!dir_fi->backing_inode || !dir_backing_path)
		return -ENOENT;

	mutex_lock_nested(&dir_fi->backing_inode->i_mutex, I_MUTEX_PARENT);
	backing_dentry = lookup_one_len(entry->d_name.name,
					dir_backing_path->dentry,
					entry->d_name.len);
	if (IS_ERR(backing_dentry)) {
		mutex_unlock(&dir_fi->backing_inode->i_mutex);
		return PTR_ERR(backing_dentry);
	}

	ret = vfs_symlink(dir_fi->backing_inode, backing_dentry, link);
	mutex_unlock(&dir_fi->backing_inode->i_mutex);

	if (ret) {
		dput(backing_dentry);
		return ret;
	}

	if (!backing_dentry->d_inode) {
		dput(backing_dentry);
		return -ENOENT;
	}

	backing_path = (struct path) {
		.mnt = mntget(dir_backing_path->mnt),
		.dentry = backing_dentry,
	};

	fd = get_fuse_dentry(entry);
	if (!fd) {
		fd = kzalloc(sizeof(struct fuse_dentry), GFP_KERNEL);
		if (!fd) {
			path_put(&backing_path);
			return -ENOMEM;
		}
		entry->d_fsdata = fd;
	}
	path_put(&fd->backing_path);
	fd->backing_path = backing_path;

	inode = fuse_iget_backing(dir->i_sb, backing_dentry->d_inode);
	if (IS_ERR_OR_NULL(inode))
		return inode ? PTR_ERR(inode) : -ENOMEM;

	d_instantiate(entry, inode);

	if (get_fuse_inode(inode)->bpf)
		bpf_prog_put(get_fuse_inode(inode)->bpf);
	get_fuse_inode(inode)->bpf = fd->bpf;
	fd->bpf = NULL;

	return 0;
}

void *fuse_symlink_finalize(
		struct fuse_bpf_args *fa,
		struct inode *dir, struct dentry *entry, const char *link, int len)
{
	return NULL;
}

/*
 * Getattr
 */
int fuse_getattr_initialize(struct fuse_bpf_args *fa,
			    struct fuse_getattr_io *fgio,
			    const struct dentry *entry, struct kstat *stat,
			    u32 request_mask, unsigned int flags)
{
	fa->opcode = FUSE_GETATTR;
	fa->nodeid = get_node_id(entry->d_inode);
	fa->in_args[0].size = sizeof(fgio->fgi);
	fa->in_args[0].value = &fgio->fgi;
	fa->in_numargs = 1;
	fgio->fgi = (struct fuse_getattr_in) {
		.getattr_flags = flags,
		.fh = -1,
	};
	fa->out_args[0].size = sizeof(fgio->fao);
	fa->out_args[0].value = &fgio->fao;
	fa->out_numargs = 1;

	return 0;
}

static void fuse_stat_to_attr(struct kstat *stat, struct fuse_attr *attr)
{
	unsigned int blkbits;

	attr->ino = stat->ino;
	attr->mode = stat->mode;
	attr->nlink = stat->nlink;
	attr->uid = from_kuid_munged(&init_user_ns, stat->uid);
	attr->gid = from_kgid_munged(&init_user_ns, stat->gid);
	attr->rdev = new_encode_dev(stat->rdev);
	attr->size = stat->size;
	attr->atime = stat->atime.tv_sec;
	attr->atimensec = stat->atime.tv_nsec;
	attr->mtime = stat->mtime.tv_sec;
	attr->mtimensec = stat->mtime.tv_nsec;
	attr->ctime = stat->ctime.tv_sec;
	attr->ctimensec = stat->ctime.tv_nsec;
	blkbits = 10;
	attr->blksize = 1 << blkbits;
	attr->blocks = stat->blocks;
}

int fuse_getattr_backing(struct fuse_bpf_args *fa,
			const struct dentry *entry, struct kstat *stat,
			u32 request_mask, unsigned int flags)
{
	struct path *backing_path = fuse_get_backing_path((struct dentry *)entry);

	if (!backing_path)
		return -ENOENT;

	return vfs_getattr(backing_path, stat);
}

void *fuse_getattr_finalize(struct fuse_bpf_args *fa,
			    const struct dentry *entry, struct kstat *stat,
			    u32 request_mask, unsigned int flags)
{
	struct fuse_attr_out *outarg =
		(struct fuse_attr_out *)fa->out_args[0].value;

	if (!IS_ERR(stat))
		fuse_stat_to_attr(stat, &outarg->attr);

	return NULL;
}

/*
 * Setattr
 */
int fuse_setattr_initialize(struct fuse_bpf_args *fa,
			    struct fuse_setattr_io *fsi,
			    struct dentry *dentry, struct iattr *attr,
			    struct file *file)
{
	fa->opcode = FUSE_SETATTR;
	fa->nodeid = get_node_id(dentry->d_inode);
	fa->in_args[0].size = sizeof(fsi->fsi);
	fa->in_args[0].value = &fsi->fsi;
	fa->in_numargs = 1;
	iattr_to_fattr(attr, &fsi->fsi, false);
	fa->out_args[0].size = sizeof(fsi->fao);
	fa->out_args[0].value = &fsi->fao;
	fa->out_numargs = 1;

	return 0;
}

static void fattr_to_iattr(struct fuse_setattr_in *fsi, struct iattr *iattr)
{
	memset(iattr, 0, sizeof(*iattr));

	if (fsi->valid & FATTR_MODE) {
		iattr->ia_valid |= ATTR_MODE;
		iattr->ia_mode = fsi->mode;
	}
	if (fsi->valid & FATTR_UID) {
		iattr->ia_valid |= ATTR_UID;
		iattr->ia_uid = make_kuid(&init_user_ns, fsi->uid);
	}
	if (fsi->valid & FATTR_GID) {
		iattr->ia_valid |= ATTR_GID;
		iattr->ia_gid = make_kgid(&init_user_ns, fsi->gid);
	}
	if (fsi->valid & FATTR_SIZE) {
		iattr->ia_valid |= ATTR_SIZE;
		iattr->ia_size = fsi->size;
	}
	if (fsi->valid & FATTR_ATIME) {
		iattr->ia_valid |= ATTR_ATIME;
		iattr->ia_atime = (struct timespec) {
			fsi->atime, fsi->atimensec
		};
	}
	if (fsi->valid & FATTR_MTIME) {
		iattr->ia_valid |= ATTR_MTIME;
		iattr->ia_mtime = (struct timespec) {
			fsi->mtime, fsi->mtimensec
		};
	}
}

int fuse_setattr_backing(struct fuse_bpf_args *fa,
			 struct dentry *dentry, struct iattr *attr,
			 struct file *file)
{
	struct fuse_setattr_in *fsi =
		(struct fuse_setattr_in *)fa->in_args[0].value;
	struct path *backing_path = fuse_get_backing_path(dentry);
	struct iattr new_attr;
	int ret;

	if (!backing_path)
		return -ENOENT;

	fattr_to_iattr(fsi, &new_attr);

	mutex_lock(&backing_path->dentry->d_inode->i_mutex);
	ret = notify_change(backing_path->dentry, &new_attr, NULL);
	mutex_unlock(&backing_path->dentry->d_inode->i_mutex);

	if (!ret && (new_attr.ia_valid & ATTR_SIZE))
		i_size_write(dentry->d_inode, new_attr.ia_size);

	return ret;
}

void *fuse_setattr_finalize(struct fuse_bpf_args *fa,
			    struct dentry *dentry, struct iattr *attr,
			    struct file *file)
{
	return NULL;
}

/*
 * Statfs
 */
int fuse_statfs_initialize(struct fuse_bpf_args *fa,
			   struct fuse_statfs_out *fso,
			   struct dentry *dentry, struct kstatfs *buf)
{
	fa->opcode = FUSE_STATFS;
	fa->nodeid = get_node_id(dentry->d_inode);
	fa->in_numargs = 0;
	fa->out_args[0].size = sizeof(*fso);
	fa->out_args[0].value = fso;
	fa->out_numargs = 1;

	return 0;
}

int fuse_statfs_backing(struct fuse_bpf_args *fa,
			struct dentry *dentry, struct kstatfs *buf)
{
	struct path *backing_path = fuse_get_backing_path(dentry);
	struct fuse_kstatfs fkstat;
	int ret;

	if (!backing_path)
		return -ENOENT;

	ret = vfs_statfs(backing_path, buf);
	if (ret)
		return ret;

	buf->f_type = FUSE_SUPER_MAGIC;
	convert_statfs_to_fuse(&fkstat, buf);
	return 0;
}

void *fuse_statfs_finalize(struct fuse_bpf_args *fa,
			   struct dentry *dentry, struct kstatfs *buf)
{
	struct fuse_statfs_out *fso =
		(struct fuse_statfs_out *)fa->out_args[0].value;

	convert_fuse_statfs(buf, &fso->st);
	return NULL;
}

/*
 * Get Link (3.10 uses follow_link)
 */
int fuse_get_link_initialize(struct fuse_bpf_args *fa,
			     struct fuse_dummy_io *dummy,
			     struct inode *inode, struct dentry *dentry,
			     struct delayed_call *callback, const char **out)
{
	fa->opcode = FUSE_READLINK;
	fa->nodeid = get_node_id(inode);
	fa->in_numargs = 0;
	fa->out_numargs = 0;

	return 0;
}

int fuse_get_link_backing(struct fuse_bpf_args *fa,
			  struct inode *inode, struct dentry *dentry,
			  struct delayed_call *callback, const char **out)
{
	struct path *backing_path = fuse_get_backing_path(dentry);
	struct page *page;
	char *link;

	if (!backing_path)
		return -ENOENT;

	page = read_mapping_page_async(backing_path->dentry->d_inode->i_mapping, 0,
				       NULL);
	if (IS_ERR(page))
		return PTR_ERR(page);

	link = kstrdup(page_address(page), GFP_KERNEL);
	put_page(page);
	if (!link)
		return -ENOMEM;

	*out = link;

	return 0;
}

void *fuse_get_link_finalize(struct fuse_bpf_args *fa,
			     struct inode *inode, struct dentry *dentry,
			     struct delayed_call *callback, const char **out)
{
	return NULL;
}

/*
 * Readdir
 */
int fuse_readdir_initialize(struct fuse_bpf_args *fa,
			    struct fuse_read_io *frio,
			    struct file *file, struct dir_context *ctx,
			    bool *force_again, bool *allow_force,
			    bool is_continued)
{
	struct fuse_file *ff = file->private_data;

	fa->opcode = FUSE_READDIR;
	fa->nodeid = ff->nodeid;
	fa->in_args[0].size = sizeof(frio->fri);
	fa->in_args[0].value = &frio->fri;
	fa->in_numargs = 1;
	frio->fri = (struct fuse_read_in) {
		.fh = ff->fh,
		.offset = ctx->pos,
		.size = PAGE_SIZE,
	};
	fa->out_args[0].size = sizeof(frio->fro);
	fa->out_args[0].value = &frio->fro;
	fa->out_numargs = 1;

	return 0;
}

int fuse_readdir_backing(struct fuse_bpf_args *fa,
			 struct file *file, struct dir_context *ctx,
			 bool *force_again, bool *allow_force,
			 bool is_continued)
{
	struct fuse_file *ff = file->private_data;
	struct file *backing_file = ff->backing_file;
	int ret;

	if (!backing_file)
		return -ENOTCONN;

	ret = iterate_dir(backing_file, ctx);

	return ret;
}

void *fuse_readdir_finalize(struct fuse_bpf_args *fa,
			    struct file *file, struct dir_context *ctx,
			    bool *force_again, bool *allow_force,
			    bool is_continued)
{
	return NULL;
}

/*
 * Access
 */
int fuse_access_initialize(struct fuse_bpf_args *fa,
			   struct fuse_access_in *fai,
			   struct inode *inode, int mask)
{
	fa->opcode = FUSE_ACCESS;
	fa->nodeid = get_node_id(inode);
	fa->in_args[0].size = sizeof(*fai);
	fa->in_args[0].value = fai;
	fa->in_numargs = 1;
	*fai = (struct fuse_access_in) {
		.mask = mask,
	};
	fa->out_numargs = 0;

	return 0;
}

int fuse_access_backing(struct fuse_bpf_args *fa, struct inode *inode, int mask)
{
	struct fuse_inode *fi = get_fuse_inode(inode);

	if (!fi->backing_inode)
		return -ENOENT;

	return inode_permission(fi->backing_inode, mask);
}

void *fuse_access_finalize(struct fuse_bpf_args *fa,
			   struct inode *inode, int mask)
{
	return NULL;
}

/*
 * Flock
 */
int fuse_file_flock_initialize(struct fuse_bpf_args *fa,
			       struct fuse_dummy_io *dummy,
			       struct file *file, int cmd,
			       struct file_lock *fl)
{
	/* No FUSE opcode for flock - handled entirely by backing fs */
	fa->opcode = 0;
	fa->in_numargs = 0;
	fa->out_numargs = 0;

	return 0;
}

int fuse_file_flock_backing(struct fuse_bpf_args *fa,
			    struct file *file, int cmd,
			    struct file_lock *fl)
{
	struct fuse_file *ff = file->private_data;

	if (!ff->backing_file)
		return -EBADF;

	return flock_lock_file_wait(ff->backing_file, fl);
}

void *fuse_file_flock_finalize(struct fuse_bpf_args *fa,
			       struct file *file, int cmd,
			       struct file_lock *fl)
{
	return NULL;
}
