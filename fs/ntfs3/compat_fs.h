#include <linux/fs.h>
#include <linux/uio.h>
#include <linux/dcache.h>

static inline int setattr_prepare(struct dentry *dentry, struct iattr *attr)
{
	struct inode *inode = d_inode(dentry);
	return inode_change_ok(inode, attr);
}

static inline void iov_iter_truncate(struct iov_iter *i, u64 count)
{
	if (i->count > count)
		i->count = count;
}

static inline void inode_nohighmem(struct inode *inode)
{
	mapping_set_gfp_mask(inode->i_mapping, GFP_USER);
}

extern struct backing_dev_info *inode_to_bdi(struct inode *inode);
struct posix_acl *posix_acl_clone(const struct posix_acl *acl, gfp_t flags);