/*
 * FUSE: Filesystem in Userspace
 * Copyright (C) 2016 Canonical Ltd. <seth.forshee@canonical.com>
 *
 * This program can be distributed under the terms of the GNU GPL.
 * See the file COPYING.
 */

#include "fuse_i.h"

#include <linux/posix_acl.h>
#include <linux/posix_acl_xattr.h>

static ssize_t fuse_getxattr_acl(struct inode *inode, const char *name,
				 void *value, size_t size)
{
	struct fuse_conn *fc = get_fuse_conn(inode);
	struct fuse_req *req;
	struct fuse_getxattr_in inarg;
	struct fuse_getxattr_out outarg;
	ssize_t ret;

	if (fc->no_getxattr)
		return -EOPNOTSUPP;

	req = fuse_get_req_nopages(fc);
	if (IS_ERR(req))
		return PTR_ERR(req);

	memset(&inarg, 0, sizeof(inarg));
	inarg.size = size;
	req->in.h.opcode = FUSE_GETXATTR;
	req->in.h.nodeid = get_node_id(inode);
	req->in.numargs = 2;
	req->in.args[0].size = sizeof(inarg);
	req->in.args[0].value = &inarg;
	req->in.args[1].size = strlen(name) + 1;
	req->in.args[1].value = name;
	req->out.numargs = 1;
	if (size) {
		req->out.argvar = 1;
		req->out.args[0].size = size;
		req->out.args[0].value = value;
	} else {
		req->out.args[0].size = sizeof(outarg);
		req->out.args[0].value = &outarg;
	}
	fuse_request_send(fc, req);
	ret = req->out.h.error;
	if (!ret)
		ret = size ? req->out.args[0].size : outarg.size;
	else {
		if (ret == -ENOSYS) {
			fc->no_getxattr = 1;
			ret = -EOPNOTSUPP;
		}
	}
	fuse_put_request(fc, req);
	return ret;
}

static int fuse_setxattr_acl(struct inode *inode, const char *name,
			     const void *value, size_t size, int flags)
{
	struct fuse_conn *fc = get_fuse_conn(inode);
	struct fuse_req *req;
	struct fuse_setxattr_in inarg;
	int err;

	if (fc->no_setxattr)
		return -EOPNOTSUPP;

	req = fuse_get_req_nopages(fc);
	if (IS_ERR(req))
		return PTR_ERR(req);

	memset(&inarg, 0, sizeof(inarg));
	inarg.size = size;
	inarg.flags = flags;
	req->in.h.opcode = FUSE_SETXATTR;
	req->in.h.nodeid = get_node_id(inode);
	req->in.numargs = 3;
	req->in.args[0].size = sizeof(inarg);
	req->in.args[0].value = &inarg;
	req->in.args[1].size = strlen(name) + 1;
	req->in.args[1].value = name;
	req->in.args[2].size = size;
	req->in.args[2].value = value;
	fuse_request_send(fc, req);
	err = req->out.h.error;
	fuse_put_request(fc, req);
	if (err == -ENOSYS) {
		fc->no_setxattr = 1;
		err = -EOPNOTSUPP;
	}
	return err;
}

static int fuse_removexattr_acl(struct inode *inode, const char *name)
{
	struct fuse_conn *fc = get_fuse_conn(inode);
	struct fuse_req *req;
	struct fuse_setxattr_in inarg;
	int err;

	req = fuse_get_req_nopages(fc);
	if (IS_ERR(req))
		return PTR_ERR(req);

	memset(&inarg, 0, sizeof(inarg));
	req->in.h.opcode = FUSE_REMOVEXATTR;
	req->in.h.nodeid = get_node_id(inode);
	req->in.numargs = 1;
	req->in.args[0].size = sizeof(inarg);
	req->in.args[0].value = &inarg;
	fuse_request_send(fc, req);
	err = req->out.h.error;
	fuse_put_request(fc, req);
	if (err == -ENOSYS) {
		fc->no_getxattr = 1;
		err = -EOPNOTSUPP;
	}
	return err;
}

struct posix_acl *fuse_get_acl(struct inode *inode, int type)
{
	struct fuse_conn *fc = get_fuse_conn(inode);
	int size;
	const char *name;
	void *value = NULL;
	struct posix_acl *acl;

	if (!fc->posix_acl)
		return NULL;

	if (type == ACL_TYPE_ACCESS)
		name = XATTR_NAME_POSIX_ACL_ACCESS;
	else if (type == ACL_TYPE_DEFAULT)
		name = XATTR_NAME_POSIX_ACL_DEFAULT;
	else
		return ERR_PTR(-EOPNOTSUPP);

	value = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!value)
		return ERR_PTR(-ENOMEM);
	size = fuse_getxattr_acl(inode, name, value, PAGE_SIZE);
	if (size > 0)
		acl = posix_acl_from_xattr(&init_user_ns, value, size);
	else if ((size == 0) || (size == -ENODATA) ||
		 (size == -EOPNOTSUPP && fc->no_getxattr))
		acl = NULL;
	else if (size == -ERANGE)
		acl = ERR_PTR(-E2BIG);
	else
		acl = ERR_PTR(size);

	kfree(value);
	return acl;
}

int fuse_set_acl(struct inode *inode, struct posix_acl *acl, int type)
{
	struct fuse_conn *fc = get_fuse_conn(inode);
	const char *name;
	int ret;

	if (!fc->posix_acl)
		return -EOPNOTSUPP;

	if (type == ACL_TYPE_ACCESS)
		name = XATTR_NAME_POSIX_ACL_ACCESS;
	else if (type == ACL_TYPE_DEFAULT)
		name = XATTR_NAME_POSIX_ACL_DEFAULT;
	else
		return -EINVAL;

	if (acl) {
		size_t size = posix_acl_xattr_size(acl->a_count);
		void *value;

		if (size > PAGE_SIZE)
			return -E2BIG;

		value = kmalloc(size, GFP_KERNEL);
		if (!value)
			return -ENOMEM;

		ret = posix_acl_to_xattr(&init_user_ns, acl, value, size);
		if (ret < 0) {
			kfree(value);
			return ret;
		}

		ret = fuse_setxattr_acl(inode, name, value, size, 0);
		kfree(value);
	} else {
		ret = fuse_removexattr_acl(inode, name);
	}
	forget_all_cached_acls(inode);
	fuse_invalidate_attr(inode);

	return ret;
}

/*
 * xattr handlers for posix ACLs (used via s_xattr)
 */
static size_t fuse_xattr_acl_list_access(struct dentry *dentry, char *list,
					 size_t list_size, const char *name,
					 size_t name_len, int handler_flags)
{
	const size_t len = sizeof(POSIX_ACL_XATTR_ACCESS);

	if (list && len <= list_size)
		memcpy(list, POSIX_ACL_XATTR_ACCESS, len);
	return len;
}

static size_t fuse_xattr_acl_list_default(struct dentry *dentry, char *list,
					  size_t list_size, const char *name,
					  size_t name_len, int handler_flags)
{
	const size_t len = sizeof(POSIX_ACL_XATTR_DEFAULT);

	if (list && len <= list_size)
		memcpy(list, POSIX_ACL_XATTR_DEFAULT, len);
	return len;
}

static int fuse_xattr_get_acl(struct dentry *dentry, const char *name,
			      void *buffer, size_t size, int handler_flags)
{
	struct inode *inode = dentry->d_inode;
	struct posix_acl *acl;
	int type, err;

	if (!(inode->i_sb->s_flags & MS_POSIXACL))
		return -EOPNOTSUPP;

	if (strcmp(name, POSIX_ACL_XATTR_ACCESS) == 0)
		type = ACL_TYPE_ACCESS;
	else if (strcmp(name, POSIX_ACL_XATTR_DEFAULT) == 0)
		type = ACL_TYPE_DEFAULT;
	else
		return -EINVAL;

	acl = fuse_get_acl(inode, type);
	if (IS_ERR(acl))
		return PTR_ERR(acl);
	if (!acl)
		return -ENODATA;
	err = posix_acl_to_xattr(&init_user_ns, acl, buffer, size);
	posix_acl_release(acl);

	return err;
}

static int fuse_xattr_set_acl(struct dentry *dentry, const char *name,
			      const void *buffer, size_t size, int flags,
			      int handler_flags)
{
	struct inode *inode = dentry->d_inode;
	struct posix_acl *acl;
	int type, err;

	if (!(inode->i_sb->s_flags & MS_POSIXACL))
		return -EOPNOTSUPP;

	if (strcmp(name, POSIX_ACL_XATTR_ACCESS) == 0)
		type = ACL_TYPE_ACCESS;
	else if (strcmp(name, POSIX_ACL_XATTR_DEFAULT) == 0)
		type = ACL_TYPE_DEFAULT;
	else
		return -EINVAL;

	if (!buffer) {
		acl = NULL;
	} else {
		acl = posix_acl_from_xattr(&init_user_ns, buffer, size);
		if (IS_ERR(acl))
			return PTR_ERR(acl);
		if (!acl)
			return -EINVAL;
		err = posix_acl_valid(acl);
		if (err) {
			posix_acl_release(acl);
			return err;
		}
	}

	err = fuse_set_acl(inode, acl, type);
	posix_acl_release(acl);

	return err;
}

static const struct xattr_handler fuse_xattr_acl_access_handler = {
	.prefix	= POSIX_ACL_XATTR_ACCESS,
	.flags	= ACL_TYPE_ACCESS,
	.list	= fuse_xattr_acl_list_access,
	.get	= fuse_xattr_get_acl,
	.set	= fuse_xattr_set_acl,
};

static const struct xattr_handler fuse_xattr_acl_default_handler = {
	.prefix	= POSIX_ACL_XATTR_DEFAULT,
	.flags	= ACL_TYPE_DEFAULT,
	.list	= fuse_xattr_acl_list_default,
	.get	= fuse_xattr_get_acl,
	.set	= fuse_xattr_set_acl,
};

const struct xattr_handler *fuse_acl_xattr_handlers[] = {
	&fuse_xattr_acl_access_handler,
	&fuse_xattr_acl_default_handler,
	NULL,
};
