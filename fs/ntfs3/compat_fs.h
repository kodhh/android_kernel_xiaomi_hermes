#include <linux/fs.h>
#include <linux/uio.h>
#include <linux/dcache.h>

#define FOLL_TRIED   0x800   /* a retry, previous pass started an IO */
#define DCACHE_PAR_LOOKUP                0x10000000 /* being looked up (with parent locked shared) */

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

static inline void inode_nohighmem(struct inode *inode)
{
	mapping_set_gfp_mask(inode->i_mapping, GFP_USER);
}

static inline int d_in_lookup(const struct dentry *dentry)
{
	return dentry->d_flags & DCACHE_PAR_LOOKUP;
}

static inline bool d_really_is_positive(const struct dentry *dentry)
{
	return dentry->d_inode != NULL;
}

extern struct backing_dev_info *inode_to_bdi(struct inode *inode);
struct posix_acl *posix_acl_clone(const struct posix_acl *acl, gfp_t flags);