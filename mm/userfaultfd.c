/*
 *  mm/userfaultfd.c
 *
 *  Copyright (C) 2015  Red Hat, Inc.
 *
 *  This work is licensed under the terms of the GNU GPL, version 2. See
 *  the COPYING file in the top-level directory.
 */

#include <linux/mm.h>
#include <linux/pagemap.h>
#include <linux/rmap.h>
#include <linux/swap.h>
#include <linux/swapops.h>
#include <linux/userfaultfd_k.h>
#include <linux/mmu_notifier.h>
#include <asm/tlbflush.h>
#include "internal.h"

static int mcopy_atomic_pte(struct mm_struct *dst_mm,
			    pmd_t *dst_pmd,
			    struct vm_area_struct *dst_vma,
			    unsigned long dst_addr,
			    unsigned long src_addr,
			    struct page **pagep)
{
	struct mem_cgroup *memcg;
	pte_t _dst_pte, *dst_pte;
	spinlock_t *ptl;
	void *page_kaddr;
	int ret;
	struct page *page;

	if (!*pagep) {
		ret = -ENOMEM;
		page = alloc_page_vma(GFP_HIGHUSER_MOVABLE, dst_vma, dst_addr);
		if (!page)
			goto out;

		page_kaddr = kmap_atomic(page);
		ret = copy_from_user(page_kaddr,
				     (const void __user *) src_addr,
				     PAGE_SIZE);
		kunmap_atomic(page_kaddr);

		/* fallback to copy_from_user outside mmap_sem */
		if (unlikely(ret)) {
			ret = -EFAULT;
			*pagep = page;
			/* don't free the page */
			goto out;
		}
	} else {
		page = *pagep;
		*pagep = NULL;
	}

	/*
	 * The memory barrier inside __SetPageUptodate makes sure that
	 * preceeding stores to the page contents become visible before
	 * the set_pte_at() write.
	 */
	__SetPageUptodate(page);

	ret = -ENOMEM;
	if (mem_cgroup_newpage_charge(page, dst_mm, GFP_KERNEL))
		goto out_release;

	_dst_pte = mk_pte(page, dst_vma->vm_page_prot);
	if (dst_vma->vm_flags & VM_WRITE)
		_dst_pte = pte_mkwrite(pte_mkdirty(_dst_pte));

	ret = -EEXIST;
	dst_pte = pte_offset_map_lock(dst_mm, dst_pmd, dst_addr, &ptl);
	if (!pte_none(*dst_pte))
		goto out_release_uncharge_unlock;

	inc_mm_counter(dst_mm, MM_ANONPAGES);
	page_add_new_anon_rmap(page, dst_vma, dst_addr);
	SetPageActive(page);
	__lru_cache_add(page, LRU_ACTIVE_ANON);

	set_pte_at(dst_mm, dst_addr, dst_pte, _dst_pte);

	/* No need to invalidate - it was non-present before */
	update_mmu_cache(dst_vma, dst_addr, dst_pte);

	pte_unmap_unlock(dst_pte, ptl);
	ret = 0;
out:
	return ret;
out_release_uncharge_unlock:
	pte_unmap_unlock(dst_pte, ptl);
	mem_cgroup_uncharge_page(page);
out_release:
	page_cache_release(page);
	goto out;
}

static int mfill_zeropage_pte(struct mm_struct *dst_mm,
			      pmd_t *dst_pmd,
			      struct vm_area_struct *dst_vma,
			      unsigned long dst_addr)
{
	pte_t _dst_pte, *dst_pte;
	spinlock_t *ptl;
	int ret;

	_dst_pte = pte_mkspecial(pfn_pte(my_zero_pfn(dst_addr),
					 dst_vma->vm_page_prot));
	ret = -EEXIST;
	dst_pte = pte_offset_map_lock(dst_mm, dst_pmd, dst_addr, &ptl);
	if (!pte_none(*dst_pte))
		goto out_unlock;
	set_pte_at(dst_mm, dst_addr, dst_pte, _dst_pte);
	/* No need to invalidate - it was non-present before */
	update_mmu_cache(dst_vma, dst_addr, dst_pte);
	ret = 0;
out_unlock:
	pte_unmap_unlock(dst_pte, ptl);
	return ret;
}

static pmd_t *mm_alloc_pmd(struct mm_struct *mm, unsigned long address)
{
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd = NULL;

	pgd = pgd_offset(mm, address);
	pud = pud_alloc(mm, pgd, address);
	if (pud)
		/*
		 * Note that we didn't run this because the pmd was
		 * missing, the *pmd may be already established and in
		 * turn it may also be a trans_huge_pmd.
		 */
		pmd = pmd_alloc(mm, pud, address);
	return pmd;
}

static __always_inline ssize_t __mcopy_atomic(struct mm_struct *dst_mm,
					      unsigned long dst_start,
					      unsigned long src_start,
					      unsigned long len,
					      bool zeropage)
{
	struct vm_area_struct *dst_vma;
	ssize_t err;
	pmd_t *dst_pmd;
	unsigned long src_addr, dst_addr;
	long copied;
	struct page *page;

	/*
	 * Sanitize the command parameters:
	 */
	BUG_ON(dst_start & ~PAGE_MASK);
	BUG_ON(len & ~PAGE_MASK);

	/* Does the address range wrap, or is the span zero-sized? */
	BUG_ON(src_start + len <= src_start);
	BUG_ON(dst_start + len <= dst_start);

	src_addr = src_start;
	dst_addr = dst_start;
	copied = 0;
	page = NULL;
retry:
	down_read(&dst_mm->mmap_sem);

	/*
	 * Make sure the vma is not shared, that the dst range is
	 * both valid and fully within a single existing vma.
	 */
	err = -EINVAL;
	dst_vma = find_vma(dst_mm, dst_start);
	if (!dst_vma || (dst_vma->vm_flags & VM_SHARED))
		goto out_unlock;
	if (dst_start < dst_vma->vm_start ||
	    dst_start + len > dst_vma->vm_end)
		goto out_unlock;

	/*
	 * Be strict and only allow __mcopy_atomic on userfaultfd
	 * registered ranges to prevent userland errors going
	 * unnoticed. As far as the VM consistency is concerned, it
	 * would be perfectly safe to remove this check, but there's
	 * no useful usage for __mcopy_atomic ouside of userfaultfd
	 * registered ranges. This is after all why these are ioctls
	 * belonging to the userfaultfd and not syscalls.
	 */
	if (!dst_vma->vm_userfaultfd_ctx.ctx)
		goto out_unlock;

	/*
	 * FIXME: only allow copying on anonymous vmas, tmpfs should
	 * be added.
	 */
	if (!vma_is_anonymous(dst_vma))
		goto out_unlock;

	/*
	 * Ensure the dst_vma has a anon_vma or this page
	 * would get a NULL anon_vma when moved in the
	 * dst_vma.
	 */
	err = -ENOMEM;
	if (unlikely(anon_vma_prepare(dst_vma)))
		goto out_unlock;

	while (src_addr < src_start + len) {
		pmd_t dst_pmdval;

		BUG_ON(dst_addr >= dst_start + len);

		dst_pmd = mm_alloc_pmd(dst_mm, dst_addr);
		if (unlikely(!dst_pmd)) {
			err = -ENOMEM;
			break;
		}

		dst_pmdval = pmd_read_atomic(dst_pmd);
		/*
		 * If the dst_pmd is mapped as THP don't
		 * override it and just be strict.
		 */
		if (unlikely(pmd_trans_huge(dst_pmdval))) {
			err = -EEXIST;
			break;
		}
		if (unlikely(pmd_none(dst_pmdval)) &&
		    unlikely(__pte_alloc(dst_mm, dst_vma, dst_pmd,
					 dst_addr))) {
			err = -ENOMEM;
			break;
		}
		/* If an huge pmd materialized from under us fail */
		if (unlikely(pmd_trans_huge(*dst_pmd))) {
			err = -EFAULT;
			break;
		}

		BUG_ON(pmd_none(*dst_pmd));
		BUG_ON(pmd_trans_huge(*dst_pmd));

		if (!zeropage)
			err = mcopy_atomic_pte(dst_mm, dst_pmd, dst_vma,
					       dst_addr, src_addr, &page);
		else
			err = mfill_zeropage_pte(dst_mm, dst_pmd, dst_vma,
						 dst_addr);

		cond_resched();

		if (unlikely(err == -EFAULT)) {
			void *page_kaddr;

			up_read(&dst_mm->mmap_sem);
			BUG_ON(!page);

			page_kaddr = kmap(page);
			err = copy_from_user(page_kaddr,
					     (const void __user *) src_addr,
					     PAGE_SIZE);
			kunmap(page);
			if (unlikely(err)) {
				err = -EFAULT;
				goto out;
			}
			goto retry;
		} else
			BUG_ON(page);

		if (!err) {
			dst_addr += PAGE_SIZE;
			src_addr += PAGE_SIZE;
			copied += PAGE_SIZE;

			if (fatal_signal_pending(current))
				err = -EINTR;
		}
		if (err)
			break;
	}

out_unlock:
	up_read(&dst_mm->mmap_sem);
out:
	if (page)
		page_cache_release(page);
	BUG_ON(copied < 0);
	BUG_ON(err > 0);
	BUG_ON(!copied && !err);
	return copied ? copied : err;
}

ssize_t mcopy_atomic(struct mm_struct *dst_mm, unsigned long dst_start,
		     unsigned long src_start, unsigned long len)
{
	return __mcopy_atomic(dst_mm, dst_start, src_start, len, false);
}

ssize_t mfill_zeropage(struct mm_struct *dst_mm, unsigned long start,
		       unsigned long len)
{
	return __mcopy_atomic(dst_mm, start, 0, len, true);
}

static __always_inline
struct vm_area_struct *find_vma_and_prepare_anon(struct mm_struct *mm,
						 unsigned long addr)
{
	struct vm_area_struct *vma;

	vma = find_vma(mm, addr);
	if (!vma || addr < vma->vm_start)
		vma = ERR_PTR(-ENOENT);
	else if (!(vma->vm_flags & VM_SHARED) &&
		 unlikely(anon_vma_prepare(vma)))
		vma = ERR_PTR(-ENOMEM);

	return vma;
}

static __always_inline
int find_vmas_mm_locked(struct mm_struct *mm,
			unsigned long dst_start,
			unsigned long src_start,
			struct vm_area_struct **dst_vmap,
			struct vm_area_struct **src_vmap)
{
	struct vm_area_struct *vma;

	vma = find_vma_and_prepare_anon(mm, dst_start);
	if (IS_ERR(vma))
		return PTR_ERR(vma);

	*dst_vmap = vma;
	/* Skip finding src_vma if src_start is in dst_vma */
	if (src_start >= vma->vm_start && src_start < vma->vm_end)
		goto out_success;

	vma = find_vma(mm, src_start);
	if (!vma || src_start < vma->vm_start)
		return -ENOENT;
out_success:
	*src_vmap = vma;
	return 0;
}

static int uffd_move_lock(struct mm_struct *mm,
			  unsigned long dst_start,
			  unsigned long src_start,
			  struct vm_area_struct **dst_vmap,
			  struct vm_area_struct **src_vmap)
{
	int err;

	down_read(&mm->mmap_sem);
	err = find_vmas_mm_locked(mm, dst_start, src_start, dst_vmap, src_vmap);
	if (err)
		up_read(&mm->mmap_sem);
	return err;
}

static void uffd_move_unlock(struct vm_area_struct *dst_vma,
			     struct vm_area_struct *src_vma)
{
	up_read(&dst_vma->vm_mm->mmap_sem);
}

void double_pt_lock(spinlock_t *ptl1,
		    spinlock_t *ptl2)
	__acquires(ptl1)
	__acquires(ptl2)
{
	spinlock_t *ptl_tmp;

	if (ptl1 > ptl2) {
		/* exchange ptl1 and ptl2 */
		ptl_tmp = ptl1;
		ptl1 = ptl2;
		ptl2 = ptl_tmp;
	}
	/* lock in virtual address order to avoid lock inversion */
	spin_lock(ptl1);
	if (ptl1 != ptl2)
		spin_lock_nested(ptl2, SINGLE_DEPTH_NESTING);
	else
		__acquire(ptl2);
}

void double_pt_unlock(spinlock_t *ptl1,
		      spinlock_t *ptl2)
	__releases(ptl1)
	__releases(ptl2)
{
	spin_unlock(ptl1);
	if (ptl1 != ptl2)
		spin_unlock(ptl2);
	else
		__release(ptl2);
}

/*
 * Checks if the two ptes and the corresponding page are eligible for batched
 * move. If so, then returns pointer to the locked page.
 *
 * NOTE: page's reference is not required as the whole operation is within
 * PTL's critical section.
 */
static struct page *check_ptes_for_batched_move(struct vm_area_struct *src_vma,
						unsigned long src_addr,
						pte_t *src_pte, pte_t *dst_pte,
						struct anon_vma *src_anon_vma)
{
	pte_t orig_dst_pte, orig_src_pte;
	struct page *page;

	orig_dst_pte = *dst_pte;
	if (!pte_none(orig_dst_pte))
		return NULL;

	orig_src_pte = *src_pte;
	if (!pte_present(orig_src_pte) || is_zero_pfn(pte_pfn(orig_src_pte)))
		return NULL;

	page = vm_normal_page(src_vma, src_addr, orig_src_pte);
	if (!page)
		return NULL;
	page = compound_head(page);
	if (!trylock_page(page))
		return NULL;
	if (page_mapcount(page) != 1 || PageTransCompound(page) ||
	    page_anon_vma(page) != src_anon_vma) {
		unlock_page(page);
		return NULL;
	}
	return page;
}

/*
 * Moves src pages to dst in a batch as long as they share the same
 * anon_vma as the first page, are not large, and can successfully
 * take the lock via trylock_page().
 */
static long move_present_ptes(struct mm_struct *mm,
			      struct vm_area_struct *dst_vma,
			      struct vm_area_struct *src_vma,
			      unsigned long dst_addr, unsigned long src_addr,
			      pte_t *dst_pte, pte_t *src_pte,
			      pte_t orig_dst_pte, pte_t orig_src_pte,
			      spinlock_t *dst_ptl, spinlock_t *src_ptl,
			      struct page **first_src_page, unsigned long len,
			      struct anon_vma *src_anon_vma)
{
	int err = 0;
	struct page *src_page = *first_src_page;
	unsigned long src_start = src_addr;
	unsigned long src_end;

	len = pmd_addr_end(dst_addr, dst_addr + len) - dst_addr;
	src_end = pmd_addr_end(src_addr, src_addr + len);
	flush_cache_range(src_vma, src_addr, src_end);
	double_pt_lock(dst_ptl, src_ptl);

	if (!pte_same(*src_pte, orig_src_pte) ||
	    !pte_same(*dst_pte, orig_dst_pte)) {
		err = -EAGAIN;
		goto out;
	}
	if (PageTransCompound(src_page) ||
	    page_mapcount(src_page) != 1) {
		err = -EBUSY;
		goto out;
	}
	/* It's safe to drop the reference now as the page-table is holding one. */
	put_page(*first_src_page);
	*first_src_page = NULL;
	arch_enter_lazy_mmu_mode();

	while (true) {
		orig_src_pte = ptep_get_and_clear(mm, src_addr, src_pte);

		page_move_anon_rmap(src_page, dst_vma, dst_addr);
		WRITE_ONCE(src_page->index, linear_page_index(dst_vma, dst_addr));

		orig_dst_pte = mk_pte(src_page, dst_vma->vm_page_prot);
		/* Set soft dirty bit so userspace can notice the pte was moved */
#ifdef CONFIG_MEM_SOFT_DIRTY
		orig_dst_pte = pte_mksoft_dirty(orig_dst_pte);
#endif
		if (pte_dirty(orig_src_pte))
			orig_dst_pte = pte_mkdirty(orig_dst_pte);
		orig_dst_pte = pte_mkwrite(orig_dst_pte);
		set_pte_at(mm, dst_addr, dst_pte, orig_dst_pte);

		src_addr += PAGE_SIZE;
		if (src_addr == src_end)
			break;
		dst_addr += PAGE_SIZE;
		dst_pte++;
		src_pte++;

		unlock_page(src_page);
		src_page = check_ptes_for_batched_move(src_vma, src_addr, src_pte,
							dst_pte, src_anon_vma);
		if (!src_page)
			break;
	}

	arch_leave_lazy_mmu_mode();
	if (src_addr > src_start)
		flush_tlb_range(src_vma, src_start, src_addr);

	if (src_page)
		unlock_page(src_page);
out:
	double_pt_unlock(dst_ptl, src_ptl);
	return src_addr > src_start ? src_addr - src_start : err;
}

static int move_swap_pte(struct mm_struct *mm, struct vm_area_struct *dst_vma,
			 unsigned long dst_addr, unsigned long src_addr,
			 pte_t *dst_pte, pte_t *src_pte,
			 pte_t orig_dst_pte, pte_t orig_src_pte,
			 spinlock_t *dst_ptl, spinlock_t *src_ptl,
			 struct page *src_page,
			 swp_entry_t entry)
{
	/*
	 * Check if the page still belongs to the target swap entry after
	 * acquiring the lock. The page can be freed in the swap cache
	 * while not locked.
	 */
	if (src_page && unlikely(!PageSwapCache(src_page) ||
				  entry.val != page_private(src_page)))
		return -EAGAIN;

	double_pt_lock(dst_ptl, src_ptl);

	if (!pte_same(*src_pte, orig_src_pte) ||
	    !pte_same(*dst_pte, orig_dst_pte)) {
		double_pt_unlock(dst_ptl, src_ptl);
		return -EAGAIN;
	}

	/*
	 * The src_page resides in the swapcache, requiring an update to its
	 * index and mapping to align with the dst_vma, where a swap-in may
	 * occur and hit the swapcache after moving the PTE.
	 */
	if (src_page) {
		page_move_anon_rmap(src_page, dst_vma, dst_addr);
		src_page->index = linear_page_index(dst_vma, dst_addr);
	}

	orig_src_pte = ptep_get_and_clear(mm, src_addr, src_pte);
#ifdef CONFIG_MEM_SOFT_DIRTY
	orig_src_pte = pte_swp_mksoft_dirty(orig_src_pte);
#endif
	set_pte_at(mm, dst_addr, dst_pte, orig_src_pte);
	double_pt_unlock(dst_ptl, src_ptl);

	return PAGE_SIZE;
}

static int move_zeropage_pte(struct mm_struct *mm,
			     struct vm_area_struct *dst_vma,
			     struct vm_area_struct *src_vma,
			     unsigned long dst_addr, unsigned long src_addr,
			     pte_t *dst_pte, pte_t *src_pte,
			     pte_t orig_dst_pte, pte_t orig_src_pte,
			     spinlock_t *dst_ptl, spinlock_t *src_ptl)
{
	pte_t zero_pte;

	double_pt_lock(dst_ptl, src_ptl);
	if (!pte_same(*src_pte, orig_src_pte) ||
	    !pte_same(*dst_pte, orig_dst_pte)) {
		double_pt_unlock(dst_ptl, src_ptl);
		return -EAGAIN;
	}

	zero_pte = pte_mkspecial(pfn_pte(my_zero_pfn(dst_addr),
					 dst_vma->vm_page_prot));
	ptep_clear_flush(src_vma, src_addr, src_pte);
	set_pte_at(mm, dst_addr, dst_pte, zero_pte);
	double_pt_unlock(dst_ptl, src_ptl);

	return PAGE_SIZE;
}

/*
 * The mmap_sem for reading is held by the caller. Just move the page(s)
 * from src_pmd to dst_pmd if possible, and return number of bytes moved.
 * On failure, an error code is returned.
 */
static long move_pages_ptes(struct mm_struct *mm, pmd_t *dst_pmd, pmd_t *src_pmd,
			    struct vm_area_struct *dst_vma,
			    struct vm_area_struct *src_vma,
			    unsigned long dst_addr, unsigned long src_addr,
			    unsigned long len, __u64 mode)
{
	swp_entry_t entry;
	pte_t orig_src_pte, orig_dst_pte;
	pte_t src_page_pte;
	spinlock_t *src_ptl, *dst_ptl;
	pte_t *src_pte = NULL;
	pte_t *dst_pte = NULL;

	struct page *src_page = NULL;
	struct anon_vma *src_anon_vma = NULL;
	long ret = 0;

	mmu_notifier_invalidate_range_start(mm, src_addr, src_addr + len);
retry:
	dst_pte = pte_offset_map(dst_pmd, dst_addr);
	dst_ptl = pte_lockptr(mm, dst_pmd);

	/* Retry if a huge pmd materialized from under us */
	if (unlikely(!dst_pte)) {
		ret = -EAGAIN;
		goto out;
	}

	src_pte = pte_offset_map(src_pmd, src_addr);
	src_ptl = pte_lockptr(mm, src_pmd);

	/*
	 * We held the mmap_sem for reading so MADV_DONTNEED
	 * can zap transparent huge pages under us, or the
	 * transparent huge page fault can establish new
	 * transparent huge pages under us.
	 */
	if (unlikely(!src_pte)) {
		ret = -EAGAIN;
		goto out;
	}

	/* Sanity checks before the operation */
	if (WARN_ON_ONCE(pmd_none(*dst_pmd)) ||	WARN_ON_ONCE(pmd_none(*src_pmd)) ||
	    WARN_ON_ONCE(pmd_trans_huge(*dst_pmd)) || WARN_ON_ONCE(pmd_trans_huge(*src_pmd))) {
		ret = -EINVAL;
		goto out;
	}

	spin_lock(dst_ptl);
	orig_dst_pte = *dst_pte;
	spin_unlock(dst_ptl);
	if (!pte_none(orig_dst_pte)) {
		ret = -EEXIST;
		goto out;
	}

	spin_lock(src_ptl);
	orig_src_pte = *src_pte;
	spin_unlock(src_ptl);
	if (pte_none(orig_src_pte)) {
		if (!(mode & UFFDIO_MOVE_MODE_ALLOW_SRC_HOLES))
			ret = -ENOENT;
		else /* nothing to do to move a hole */
			ret = PAGE_SIZE;
		goto out;
	}

	/* If PTE changed after we locked the page then start over */
	if (src_page && unlikely(!pte_same(src_page_pte, orig_src_pte))) {
		ret = -EAGAIN;
		goto out;
	}

	if (pte_present(orig_src_pte)) {
		if (is_zero_pfn(pte_pfn(orig_src_pte))) {
			ret = move_zeropage_pte(mm, dst_vma, src_vma,
					       dst_addr, src_addr, dst_pte, src_pte,
					       orig_dst_pte, orig_src_pte,
					       dst_ptl, src_ptl);
			goto out;
		}

		/*
		 * Pin and lock both source page and anon_vma. Since we are in
		 * RCU read section, we can't block, so on contention have to
		 * unmap the ptes, obtain the lock and retry.
		 */
		if (!src_page) {
			struct page *page;
			bool locked;

			/*
			 * Pin the page while holding the lock to be sure the
			 * page isn't freed under us
			 */
			spin_lock(src_ptl);
			if (!pte_same(orig_src_pte, *src_pte)) {
				spin_unlock(src_ptl);
				ret = -EAGAIN;
				goto out;
			}

			page = vm_normal_page(src_vma, src_addr, orig_src_pte);
			if (!page) {
				spin_unlock(src_ptl);
				ret = -EBUSY;
				goto out;
			}
			page = compound_head(page);
			if (page_mapcount(page) != 1) {
				spin_unlock(src_ptl);
				ret = -EBUSY;
				goto out;
			}

			locked = trylock_page(page);
			/*
			 * We avoid waiting for page lock with a raised
			 * refcount for large pages because extra refcounts
			 * will result in split_huge_page() failing later and
			 * retrying. If multiple tasks are trying to move a
			 * large page we can end up livelocking.
			 */
			if (!locked && PageTransCompound(page)) {
				spin_unlock(src_ptl);
				ret = -EAGAIN;
				goto out;
			}

			get_page(page);
			src_page = page;
			src_page_pte = orig_src_pte;
			spin_unlock(src_ptl);

			if (!locked) {
				pte_unmap(src_pte);
				pte_unmap(dst_pte);
				src_pte = dst_pte = NULL;
				/* now we can block and wait */
				lock_page(src_page);
				goto retry;
			}

			if (WARN_ON_ONCE(!PageAnon(src_page))) {
				ret = -EBUSY;
				goto out;
			}
		}

		/* at this point we have src_page locked */
		if (PageTransCompound(src_page)) {
			/* split_huge_page() can block */
			pte_unmap(src_pte);
			pte_unmap(dst_pte);
			src_pte = dst_pte = NULL;
			ret = split_huge_page(src_page);
			if (ret)
				goto out;
			/* have to reacquire the page after it got split */
			unlock_page(src_page);
			put_page(src_page);
			src_page = NULL;
			goto retry;
		}

		if (!src_anon_vma) {
			/*
			 * page_referenced walks the anon_vma chain
			 * without the page lock. Serialize against it with
			 * the anon_vma lock, the page lock is not enough.
			 */
			src_anon_vma = page_get_anon_vma(src_page);
			if (!src_anon_vma) {
				/* page was unmapped from under us */
				ret = -EAGAIN;
				goto out;
			}
			anon_vma_lock_write(src_anon_vma);
		}

		ret = move_present_ptes(mm, dst_vma, src_vma,
					dst_addr, src_addr, dst_pte, src_pte,
					orig_dst_pte, orig_src_pte,
					dst_ptl, src_ptl, &src_page,
					len, src_anon_vma);
	} else {
		struct page *page = NULL;

		entry = pte_to_swp_entry(orig_src_pte);
		if (non_swap_entry(entry)) {
			if (is_migration_entry(entry)) {
				pte_unmap(src_pte);
				pte_unmap(dst_pte);
				src_pte = dst_pte = NULL;
				migration_entry_wait(mm, src_pmd, src_addr);
				ret = -EAGAIN;
			} else
				ret = -EFAULT;
			goto out;
		}

		/*
		 * Verify the existence of the swapcache. If present, the page's
		 * index and mapping must be updated even when the PTE is a swap
		 * entry. lookup_swap_cache() pins the page; keep it locked
		 * across the PTE move.
		 */
		if (!src_page)
			page = lookup_swap_cache(entry);
		if (page && PageTransCompound(page)) {
			ret = -EBUSY;
			put_page(page);
			goto out;
		}
		if (page) {
			src_page = page;
			src_page_pte = orig_src_pte;
			if (!trylock_page(src_page)) {
				pte_unmap(src_pte);
				pte_unmap(dst_pte);
				src_pte = dst_pte = NULL;
				/* now we can block and wait */
				lock_page(src_page);
				goto retry;
			}
		}
		ret = move_swap_pte(mm, dst_vma, dst_addr, src_addr, dst_pte, src_pte,
				    orig_dst_pte, orig_src_pte,
				    dst_ptl, src_ptl, src_page, entry);
	}

out:
	if (src_anon_vma) {
		anon_vma_unlock_write(src_anon_vma);
		put_anon_vma(src_anon_vma);
	}
	if (src_page) {
		unlock_page(src_page);
		put_page(src_page);
	}
	/*
	 * We mapped dst_pte first, then src_pte, so we must unmap src_pte
	 * first, then dst_pte.
	 */
	if (src_pte)
		pte_unmap(src_pte);
	if (dst_pte)
		pte_unmap(dst_pte);
	mmu_notifier_invalidate_range_end(mm, src_addr, src_addr + len);
	return ret;
}

#ifdef CONFIG_TRANSPARENT_HUGEPAGE
static inline bool move_splits_huge_pmd(unsigned long dst_addr,
					unsigned long src_addr,
					unsigned long src_end)
{
	return (src_addr & ~HPAGE_PMD_MASK) || (dst_addr & ~HPAGE_PMD_MASK) ||
		src_end - src_addr < HPAGE_PMD_SIZE;
}
#else
static inline bool move_splits_huge_pmd(unsigned long dst_addr,
					unsigned long src_addr,
					unsigned long src_end)
{
	/* This is unreachable anyway, just to avoid warnings when HPAGE_PMD_SIZE==0 */
	return false;
}
#endif

static inline bool vma_move_compatible(struct vm_area_struct *vma)
{
	return !(vma->vm_flags & (VM_PFNMAP | VM_IO |  VM_HUGETLB |
				  VM_MIXEDMAP));
}

static int validate_move_areas(struct vm_area_struct *src_vma,
			       struct vm_area_struct *dst_vma)
{
	/* Only allow moving if both have the same access and protection */
	if ((src_vma->vm_flags & (VM_READ | VM_WRITE | VM_EXEC)) !=
	    (dst_vma->vm_flags & (VM_READ | VM_WRITE | VM_EXEC)) ||
	    pgprot_val(src_vma->vm_page_prot) != pgprot_val(dst_vma->vm_page_prot))
		return -EINVAL;

	/* Only allow moving if both are mlocked or both aren't */
	if ((src_vma->vm_flags & VM_LOCKED) != (dst_vma->vm_flags & VM_LOCKED))
		return -EINVAL;

	/*
	 * For now, we keep it simple and only move between writable VMAs.
	 * Access flags are equal, therefore checking only the source is enough.
	 */
	if (!(src_vma->vm_flags & VM_WRITE))
		return -EINVAL;

	/* Check if vma flags indicate content which can be moved */
	if (!vma_move_compatible(src_vma) || !vma_move_compatible(dst_vma))
		return -EINVAL;

	/* Ensure dst_vma is registered in uffd we are operating on */
	if (!dst_vma->vm_userfaultfd_ctx.ctx)
		return -EINVAL;

	/* Only allow moving across anonymous vmas */
	if (!vma_is_anonymous(src_vma) || !vma_is_anonymous(dst_vma))
		return -EINVAL;

	return 0;
}

ssize_t move_pages(struct mm_struct *mm, unsigned long dst_start,
		   unsigned long src_start, unsigned long len,
		   __u64 mode)
{
	struct vm_area_struct *src_vma, *dst_vma;
	unsigned long src_addr, dst_addr, src_end;
	pmd_t *src_pmd, *dst_pmd;
	long err = -EINVAL;
	ssize_t moved = 0;

	/* Sanitize the command parameters. */
	if (WARN_ON_ONCE(src_start & ~PAGE_MASK) ||
	    WARN_ON_ONCE(dst_start & ~PAGE_MASK) ||
	    WARN_ON_ONCE(len & ~PAGE_MASK))
		goto out;

	/* Does the address range wrap, or is the span zero-sized? */
	if (WARN_ON_ONCE(src_start + len <= src_start) ||
	    WARN_ON_ONCE(dst_start + len <= dst_start))
		goto out;

	err = uffd_move_lock(mm, dst_start, src_start, &dst_vma, &src_vma);
	if (err)
		goto out;

	/*
	 * Make sure the vma is not shared, that the src and dst remap
	 * ranges are both valid and fully within a single existing
	 * vma.
	 */
	err = -EINVAL;
	if (src_vma->vm_flags & VM_SHARED)
		goto out_unlock;
	if (src_start + len > src_vma->vm_end)
		goto out_unlock;

	if (dst_vma->vm_flags & VM_SHARED)
		goto out_unlock;
	if (dst_start + len > dst_vma->vm_end)
		goto out_unlock;

	err = validate_move_areas(src_vma, dst_vma);
	if (err)
		goto out_unlock;

	for (src_addr = src_start, dst_addr = dst_start, src_end = src_start + len;
	     src_addr < src_end;) {
#ifdef CONFIG_TRANSPARENT_HUGEPAGE
		spinlock_t *ptl;
#endif
		pmd_t dst_pmdval;
		unsigned long step_size;

		/*
		 * Below works because anonymous area would not have a
		 * transparent huge PUD. If file-backed support is added,
		 * that case would need to be handled here.
		 */
		src_pmd = mm_find_pmd(mm, src_addr);
		if (unlikely(!src_pmd)) {
			if (!(mode & UFFDIO_MOVE_MODE_ALLOW_SRC_HOLES)) {
				err = -ENOENT;
				break;
			}
			src_pmd = mm_alloc_pmd(mm, src_addr);
			if (unlikely(!src_pmd)) {
				err = -ENOMEM;
				break;
			}
		}
		dst_pmd = mm_alloc_pmd(mm, dst_addr);
		if (unlikely(!dst_pmd)) {
			err = -ENOMEM;
			break;
		}

		dst_pmdval = pmd_read_atomic(dst_pmd);
		/*
		 * If the dst_pmd is mapped as THP don't override it and just
		 * be strict. If dst_pmd changes into THP after this check, the
		 * move_pages_huge_pmd() will detect the change and retry
		 * while move_pages_ptes() will detect the change and fail.
		 */
		if (unlikely(pmd_trans_huge(dst_pmdval))) {
			err = -EEXIST;
			break;
		}

#ifdef CONFIG_TRANSPARENT_HUGEPAGE
		ptl = pmd_trans_huge_lock(src_pmd, src_vma);
		if (ptl) {
			if (pmd_devmap(*src_pmd)) {
				spin_unlock(ptl);
				err = -ENOENT;
				break;
			}

			/* Check if we can move the pmd without splitting it. */
			if (move_splits_huge_pmd(dst_addr, src_addr, src_start + len) ||
			    !pmd_none(dst_pmdval)) {
				/* Can be a migration entry */
				if (pmd_present(*src_pmd)) {
					struct page *page = pfn_to_page(pmd_pfn(*src_pmd));

					if (!is_huge_zero_page(page) &&
					    page_mapcount(page) != 1) {
						spin_unlock(ptl);
						err = -EBUSY;
						break;
					}
				}

				spin_unlock(ptl);
				split_huge_pmd(src_vma, src_pmd, src_addr);
				/* The page will be split by move_pages_ptes() */
				continue;
			}

			err = move_pages_huge_pmd(mm, dst_pmd, src_pmd,
						  dst_pmdval, dst_vma, src_vma,
						  dst_addr, src_addr);
			step_size = HPAGE_PMD_SIZE;
		} else
#endif
		{
			long ret;

			if (pmd_none(*src_pmd)) {
				if (!(mode & UFFDIO_MOVE_MODE_ALLOW_SRC_HOLES)) {
					err = -ENOENT;
					break;
				}
				if (unlikely(__pte_alloc(mm, src_vma, src_pmd, src_addr))) {
					err = -ENOMEM;
					break;
				}
			}

			if (unlikely(pmd_none(*dst_pmd) &&
				     __pte_alloc(mm, dst_vma, dst_pmd, dst_addr))) {
				err = -ENOMEM;
				break;
			}

			ret = move_pages_ptes(mm, dst_pmd, src_pmd,
					      dst_vma, src_vma, dst_addr,
					      src_addr, src_end - src_addr, mode);
			if (ret < 0)
				err = ret;
			else
				step_size = ret;
		}

		cond_resched();

		if (fatal_signal_pending(current)) {
			/* Do not override an error */
			if (!err || err == -EAGAIN)
				err = -EINTR;
			break;
		}

		if (err) {
			if (err == -EAGAIN)
				continue;
			break;
		}

		/* Proceed to the next page */
		dst_addr += step_size;
		src_addr += step_size;
		moved += step_size;
	}

out_unlock:
	uffd_move_unlock(dst_vma, src_vma);
out:
	WARN_ON(moved < 0);
	WARN_ON(err > 0);
	WARN_ON(!moved && !err);
	return moved ? moved : err;
}
