#ifndef _CIFS_COMPAT_H_
#define _CIFS_COMPAT_H_

/*
 * Compatibility shims for porting cifs from 4.4 to 3.10 kernel.
 * Modeled after fs/btrfs/compat.h
 */

#include <linux/uio.h>
#include <linux/uaccess.h>
#include <linux/highmem.h>

/* mapping_gfp_constraint - added in 3.11 */
#ifndef mapping_gfp_constraint
static inline gfp_t mapping_gfp_constraint(struct address_space *mapping,
					   gfp_t gfp_mask)
{
	return (mapping->flags & __GFP_BITS_MASK) & gfp_mask;
}
#endif

/* copy_page_from_iter - 4.0+ API, use iov_iter_copy_from_user in 3.10 */
static inline size_t copy_page_from_iter(struct page *page, size_t offset,
					 size_t bytes, struct iov_iter *i)
{
	return iov_iter_copy_from_user(page, i, offset, bytes);
}

/* copy_page_to_iter - not in 3.10, implement via kmap + copy_to_user */
static inline size_t copy_page_to_iter(struct page *page, size_t offset,
				       size_t bytes, struct iov_iter *i)
{
	size_t copied = 0;
	size_t left = min(bytes, i->count);
	char *kaddr;

	if (!left)
		return 0;

	kaddr = kmap(page);
	while (left) {
		const struct iovec *iov = i->iov;
		size_t base = i->iov_offset;
		size_t seg = min(left, iov->iov_len - base);

		if (copy_to_user(iov->iov_base + base, kaddr + offset, seg))
			break;

		i->iov_offset += seg;
		i->count -= seg;
		copied += seg;
		offset += seg;
		left -= seg;

		if (i->iov_offset >= iov->iov_len) {
			i->iov++;
			i->nr_segs--;
			i->iov_offset = 0;
		}
	}
	kunmap(page);
	return copied;
}

/* __SetPageLocked/__ClearPageLocked -> __set_page_locked/__clear_page_locked */
#define __SetPageLocked(page)	__set_page_locked(page)
#define __ClearPageLocked(page)	__clear_page_locked(page)

/* bit_wait - generic bit wait action for 3.10's wait_on_bit(word, bit, action, mode) API */
static inline int cifs_bit_wait(void *word)
{
	if (signal_pending_state(current->state, current))
		return 1;
	schedule();
	return 0;
}

#endif /* _CIFS_COMPAT_H_ */