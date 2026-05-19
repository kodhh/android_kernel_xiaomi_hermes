#ifndef _CIFS_COMPAT_H
#define _CIFS_COMPAT_H

#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/backing-dev.h>
#include <linux/random.h>
#include <linux/socket.h>
#include <linux/aio.h>

/* 3.10 kernel compatibility shims */

#ifndef SLAB_ACCOUNT
#define SLAB_ACCOUNT 0
#endif

#ifndef seq_show_option
#define seq_show_option(s, name, value)	seq_printf(s, ",%s=%s", name, value)
#endif

#ifndef lookup_one_len_unlocked
#define lookup_one_len_unlocked(name, parent, len) \
	lookup_one_len(name, parent, len)
#endif

#ifndef get_random_u32
static inline u32 get_random_u32(void)
{
	return prandom_u32();
}
#endif

#ifndef user_key_payload_locked
#define user_key_payload_locked(key) \
	((struct user_key_payload *)rcu_dereference((key)->payload.data))
#endif

#ifndef allow_kernel_signal
#define allow_kernel_signal(sig)	allow_signal(sig)
#endif

#ifndef sock_allow_reclassification
#define sock_allow_reclassification(sk) true
#endif

#ifndef kstrtobool_from_user
#include <linux/uaccess.h>
static inline int kstrtobool_from_user(const char __user *s, size_t count,
				       bool *res)
{
	char buf[32];
	if (count >= sizeof(buf))
		return -EINVAL;
	if (copy_from_user(buf, s, count))
		return -EFAULT;
	buf[count] = '\0';
	return strtobool(buf, res);
}
#endif

/* file_dentry compat */
#define file_dentry(file) ((file)->f_path.dentry)

/* inode_lock/unlock compat (3.10 uses i_mutex) */
#define inode_lock(inode)   mutex_lock(&(inode)->i_mutex)
#define inode_unlock(inode) mutex_unlock(&(inode)->i_mutex)

/* locks_lock_file_wait compat */
#define locks_lock_file_wait(file, flock) posix_lock_file_wait(file, flock)

/* file_write_and_wait_range compat */
#define file_write_and_wait_range(file, start, end) \
	filemap_write_and_wait_range((file)->f_mapping, start, end)

/* readahead_gfp_mask compat */
#define readahead_gfp_mask(mapping) mapping_gfp_mask(mapping)

/*
 * generic_write_checks compat: 4.14 takes (iocb, from), 3.10 takes
 * (file, pos, count, isblk). 4.14 returns count (>0) on success.
 */
static inline ssize_t
cifs_generic_write_checks(struct kiocb *iocb, struct iov_iter *from)
{
	struct file *file = iocb->ki_filp;
	loff_t pos = iocb->ki_pos;
	size_t count = iov_iter_count(from);
	int ret;

	ret = generic_write_checks(file, &pos, &count, 0);
	if (ret)
		return ret;

	iocb->ki_pos = pos;
	from->count = count;
	return count;
}
#define generic_write_checks(iocb, from) cifs_generic_write_checks(iocb, from)

/*
 * __generic_file_write_iter compat: 4.14 takes (iocb, from), 3.10 takes
 * (iocb, iov, nr_segs, pos)
 */
static inline ssize_t
cifs___generic_file_write_iter(struct kiocb *iocb, struct iov_iter *from)
{
	loff_t pos = iocb->ki_pos;
	ssize_t ret = __generic_file_aio_write(iocb, from->iov, from->nr_segs, &pos);
	iocb->ki_pos = pos;
	return ret;
}
#define __generic_file_write_iter(iocb, from) \
	cifs___generic_file_write_iter(iocb, from)

/*
 * generic_file_write_iter compat
 */
static inline ssize_t
cifs_generic_file_write_iter(struct kiocb *iocb, struct iov_iter *from)
{
	return generic_file_aio_write(iocb, from->iov, from->nr_segs,
				      iocb->ki_pos);
}
#define generic_file_write_iter(iocb, from) \
	cifs_generic_file_write_iter(iocb, from)

/*
 * generic_file_read_iter compat
 */
static inline ssize_t
cifs_generic_file_read_iter(struct kiocb *iocb, struct iov_iter *to)
{
	return generic_file_aio_read(iocb, to->iov, to->nr_segs,
				     iocb->ki_pos);
}
#define generic_file_read_iter(iocb, to) \
	cifs_generic_file_read_iter(iocb, to)

/*
 * generic_write_sync compat: 4.14 takes (iocb, count), 3.10 takes
 * (file, pos, count)
 */
static inline int
cifs_generic_write_sync(struct kiocb *iocb, ssize_t count)
{
	return generic_write_sync(iocb->ki_filp, iocb->ki_pos, count);
}
#define generic_write_sync(iocb, count) \
	cifs_generic_write_sync(iocb, count)

#endif /* _CIFS_COMPAT_H */
