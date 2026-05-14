#ifndef _COMPAT_H_
#define _COMPAT_H_

#ifndef mapping_gfp_constraint
static inline gfp_t mapping_gfp_constraint(struct address_space *mapping,
					   gfp_t gfp_mask)
{
	return mapping_gfp_mask(mapping) & gfp_mask;
}
#endif

#ifndef smp_mb__before_atomic
#define smp_mb__before_atomic()	smp_mb()
#endif
#ifndef smp_mb__after_atomic
#define smp_mb__after_atomic()	smp_mb()
#endif

#ifndef strchrnul
static inline char *strchrnul(const char *s, int c)
{
	char *p = strchr(s, c);
	return p ? p : (char *)s + strlen(s);
}
#endif

#ifndef rwsem_is_contended
static inline int rwsem_is_contended(struct rw_semaphore *sem)
{
	return !list_empty(&sem->wait_list);
}
#endif

#undef percpu_counter_init
#define percpu_counter_init(fbc, value, gfp)				\
	({								\
		static struct lock_class_key __key;			\
		__percpu_counter_init(fbc, value, &__key);		\
	})

/*
 * In 3.10, struct bio has no bi_error field. 
 * bio_err() reads error status (0 = success, negative = errno).
 * bio_set_err() stores error (used before bio_endio conversion).
 */
static inline int bio_err(struct bio *bio)
{
	return bio_flagged(bio, BIO_UPTODATE) ? 0 : -EIO;
}

static inline void bio_set_err(struct bio *bio, int error)
{
	if (error)
		clear_bit(BIO_UPTODATE, &bio->bi_flags);
	else
		set_bit(BIO_UPTODATE, &bio->bi_flags);
}

#ifndef __percpu_counter_compare
#define __percpu_counter_compare(fbc, rhs, batch)	\
	percpu_counter_compare(fbc, rhs)
#endif

#ifndef __sb_writers_acquired
#define __sb_writers_acquired(sb, level)	do { } while (0)
#endif

#ifndef __sb_writers_release
#define __sb_writers_release(sb, level)		do { } while (0)
#endif

#ifndef inode_dio_begin
static inline void inode_dio_begin(struct inode *inode) { }
#endif

#ifndef inode_dio_end
static inline void inode_dio_end(struct inode *inode) { }
#endif

#ifndef wait_on_atomic_t
static inline int wait_on_atomic_t(atomic_t *val,
				   int (*action)(atomic_t *),
				   unsigned mode)
{
	return 0;
}
#endif

#ifndef iov_iter_alignment
#define iov_iter_alignment(i)	1
#endif

/*
 * iov_iter_rw is not available in 3.10 (struct iov_iter has no type field).
 * check_direct_IO in inode.c is patched to accept rw directly instead.
 */
#ifndef iov_iter_rw
#define iov_iter_rw(i)		0
#endif

#ifdef CONFIG_BTRFS_FS_POSIX_ACL
/*
 * 4.4 has posix_acl_chmod(inode, mode) (high-level)
 * 3.10 has posix_acl_chmod(acl**, gfp, mode) (low-level)
 * Use btrfs's internal ACL handling
 */
int btrfs_set_acl(struct inode *inode, struct posix_acl *acl, int type);
struct posix_acl *btrfs_get_acl(struct inode *inode, int type);

#define posix_acl_chmod(inode, mode)					\
({									\
	struct posix_acl *acl;						\
	int err = 0;							\
	acl = btrfs_get_acl(inode, ACL_TYPE_ACCESS);			\
	if (acl && !IS_ERR(acl)) {					\
		err = posix_acl_chmod(&acl, GFP_KERNEL, mode);		\
		btrfs_set_acl(inode, acl, ACL_TYPE_ACCESS);		\
		posix_acl_release(acl);					\
	}								\
	err;								\
})
#endif

/*
 * file_remove_privs was introduced in 4.x kernels.
 * Not available in 3.10 - provide a stub.
 */
#ifndef file_remove_privs
static inline int file_remove_privs(struct file *file)
{
	return 0;
}
#endif

/*
 * file_dentry - 4.4 convenience macro.
 * In 3.10, file->f_dentry exists directly.
 */
#ifndef file_dentry
#define file_dentry(file) ((file)->f_dentry)
#endif

/*
 * __GFP_DIRECT_RECLAIM - 4.4 name for __GFP_WAIT (which exists in 3.10).
 */
#ifndef __GFP_DIRECT_RECLAIM
#define __GFP_DIRECT_RECLAIM	__GFP_WAIT
#endif

/*
 * __bi_cnt - 4.4 renamed bi_cnt to __bi_cnt.
 */
#ifndef __bi_cnt
#define __bi_cnt		bi_cnt
#endif

/*
 * BTRFS error codes from 4.4 uapi - defined here for 3.10.
 */
#ifndef BTRFS_ERROR_DEV_RAID10_MIN_NOT_MET
#define BTRFS_ERROR_DEV_RAID10_MIN_NOT_MET	1
#define BTRFS_ERROR_DEV_RAID1_MIN_NOT_MET	2
#define BTRFS_ERROR_DEV_RAID5_MIN_NOT_MET	3
#define BTRFS_ERROR_DEV_RAID6_MIN_NOT_MET	4
#define BTRFS_ERROR_DEV_MISSING_NOT_FOUND	5
#define BTRFS_ERROR_DEV_TGT_REPLACE		6
#define BTRFS_ERROR_DEV_ONLY_WRITABLE		7
#endif
#ifndef BTRFS_UUID_UNPARSED_SIZE
#define BTRFS_UUID_UNPARSED_SIZE	37
#endif

/* Missing BTRFS error code from 4.4 uapi */
#ifndef BTRFS_ERROR_DEV_EXCL_RUN_IN_PROGRESS
#define BTRFS_ERROR_DEV_EXCL_RUN_IN_PROGRESS	8
#endif

/* SHASH_DESC_ON_STACK - 4.x macro for on-stack shash descriptor */
#ifndef SHASH_DESC_ON_STACK
#include <crypto/hash.h>
#define SHASH_DESC_ON_STACK(shash, tfm)					\
	char __##shash##_desc[sizeof(struct shash_desc) +		\
			      crypto_shash_descsize(tfm)]		\
		__aligned(__alignof__(struct shash_desc));		\
	struct shash_desc *shash = (struct shash_desc *)__##shash##_desc
#endif

/* XATTR_BTRFS_PREFIX - btrfs-specific xattr namespace */
#ifndef XATTR_BTRFS_PREFIX
#define XATTR_BTRFS_PREFIX "btrfs."
#define XATTR_BTRFS_PREFIX_LEN (sizeof(XATTR_BTRFS_PREFIX) - 1)
#endif

/* BTRFS_SAME_DATA_DIFFERS from 4.4 uapi */
#ifndef BTRFS_SAME_DATA_DIFFERS
#define BTRFS_SAME_DATA_DIFFERS	1
#endif

/* wake_up_atomic_t - 4.4 function for waking waiters on atomic_t.
 * 3.10 has no var_waitqueue; wait_on_atomic_t is also stubbed out,
 * so this is a no-op.
 */
#ifndef wake_up_atomic_t
static inline void wake_up_atomic_t(atomic_t *val) { }
#endif

/* d_is_dir - 4.4+ helper */
#ifndef d_is_dir
#define d_is_dir(d)		((d)->d_inode && S_ISDIR((d)->d_inode->i_mode))
#endif

/*
 * d_really_is_negative / d_really_is_positive - 4.4+ helpers for
 * union-mount aware dentry checks. In 3.10, just check d_inode.
 */
#ifndef d_really_is_negative
#define d_really_is_negative(dentry)	((dentry)->d_inode == NULL)
#endif
#ifndef d_really_is_positive
#define d_really_is_positive(dentry)	((dentry)->d_inode != NULL)
#endif

/*
 * i_blocksize - 4.4 helper.
 */
#ifndef i_blocksize
#define i_blocksize(inode) (1 << (inode)->i_blkbits)
#endif

/*
 * vfs_setpos - not exported in 3.10 (only static in f2fs).
 */
#ifndef vfs_setpos
static inline loff_t vfs_setpos(struct file *file, loff_t offset, loff_t maxsize)
{
	if (offset > maxsize)
		return -EINVAL;
	file->f_pos = offset;
	return offset;
}
#endif

/*
 * gfpflags_allow_blocking - 4.4 function. In 3.10, check __GFP_WAIT.
 */
#ifndef gfpflags_allow_blocking
#define gfpflags_allow_blocking(gfp)	((gfp) & __GFP_WAIT)
#endif

/*
 * wbc_account_io / wbc_init_bio - 4.4 cgroup writeback functions.
 * No-op in 3.10 (no cgroup writeback).
 */
#ifndef wbc_account_io
#define wbc_account_io(wbc, page, bytes)	do { } while (0)
#endif
#ifndef wbc_init_bio
#define wbc_init_bio(wbc, bio)			do { } while (0)
#endif

/*
 * pagevec_lookup_range_tag - 4.4 function with end bound.
 * 3.10 has pagevec_lookup_tag without end. The caller's loop
 * condition handles the end check.
 */
#ifndef pagevec_lookup_range_tag
#define pagevec_lookup_range_tag(pvec, mapping, index, end, tag)	\
	pagevec_lookup_tag(pvec, mapping, index, tag, PAGEVEC_SIZE)
#endif

/*
 * inode_to_bdi - exists in fs/fs-writeback.c but may not be
 * declared in headers visible to btrfs.
 */
#ifndef inode_to_bdi
static inline struct backing_dev_info *inode_to_bdi(struct inode *inode)
{
	struct super_block *sb = inode->i_sb;

	if (strcmp(sb->s_type->name, "bdev") == 0)
		return inode->i_mapping->backing_dev_info;
	return sb->s_bdi;
}
#endif

#endif /* _COMPAT_H_ */
