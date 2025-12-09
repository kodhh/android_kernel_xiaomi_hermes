#include <linux/fs.h>
#include <linux/uio.h>
#include <linux/dcache.h>

static inline struct inode *d_inode(const struct dentry *dentry)
{
	return dentry->d_inode;
}

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

extern struct backing_dev_info *inode_to_bdi(struct inode *inode);