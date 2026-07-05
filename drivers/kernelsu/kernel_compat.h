#ifndef __KSU_H_KERNEL_COMPAT
#define __KSU_H_KERNEL_COMPAT

#include <linux/fs.h>
#include <linux/version.h>
#include "ss/policydb.h"
#include "linux/key.h"

/*
 * Adapt to Huawei HISI kernel without affecting other kernels ,
 * Huawei Hisi Kernel EBITMAP Enable or Disable Flag ,
 * From ss/ebitmap.h
 */
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 9, 0)) &&                           \
		(LINUX_VERSION_CODE < KERNEL_VERSION(4, 10, 0)) ||               \
	(LINUX_VERSION_CODE >= KERNEL_VERSION(4, 14, 0)) &&                      \
		(LINUX_VERSION_CODE < KERNEL_VERSION(4, 15, 0))
#ifdef HISI_SELINUX_EBITMAP_RO
#define CONFIG_IS_HW_HISI
#endif
#endif

// In kernels before 3.14, current_uid() and cred UIDs are plain uid_t/gid_t
// In 3.14+, they are kuid_t/kgid_t with .val member
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 14, 0)
#define ksu_current_uid_val() (uid_t)current_uid()
#define ksu_kuid_t uid_t
#define ksu_kgid_t gid_t
#define ksu_cred_uid(cred) ((cred)->uid)
#define ksu_cred_euid(cred) ((cred)->euid)
#define ksu_cred_gid(cred) ((cred)->gid)
#define ksu_cred_suid(cred) ((cred)->suid)
#define ksu_cred_fsuid(cred) ((cred)->fsuid)
#define ksu_cred_sgid(cred) ((cred)->sgid)
#define ksu_cred_egid(cred) ((cred)->egid)
#define ksu_cred_fsgid(cred) ((cred)->fsgid)
#define ksu_make_kuid(uid) (uid)
#define ksu_from_kuid(uid) (uid)
#define ksu_gid_valid(gid) 1
#else
#define ksu_current_uid_val() current_uid().val
#define ksu_kuid_t kuid_t
#define ksu_kgid_t kgid_t
#define ksu_cred_uid(cred) ((cred)->uid.val)
#define ksu_cred_euid(cred) ((cred)->euid.val)
#define ksu_cred_gid(cred) ((cred)->gid.val)
#define ksu_cred_suid(cred) ((cred)->suid.val)
#define ksu_cred_fsuid(cred) ((cred)->fsuid.val)
#define ksu_cred_sgid(cred) ((cred)->sgid.val)
#define ksu_cred_egid(cred) ((cred)->egid.val)
#define ksu_cred_fsgid(cred) ((cred)->fsgid.val)
#define ksu_make_kuid(uid) make_kuid(current_user_ns(), uid)
#define ksu_from_kuid(uid) (uid).val
#define ksu_gid_valid(gid) gid_valid(gid)
#endif

extern long ksu_strncpy_from_user_nofault(char *dst,
					  const void __user *unsafe_addr,
					  long count);
extern long ksu_strncpy_from_user_retry(char *dst,
					  const void __user *unsafe_addr,
					  long count);

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 10, 0) || defined(CONFIG_IS_HW_HISI) || defined(CONFIG_KSU_ALLOWLIST_WORKAROUND)
extern struct key *init_session_keyring;
#endif

extern void ksu_android_ns_fs_check();
extern struct file *ksu_filp_open_compat(const char *filename, int flags,
					 umode_t mode);
extern ssize_t ksu_kernel_read_compat(struct file *p, void *buf, size_t count,
				      loff_t *pos);
extern ssize_t ksu_kernel_write_compat(struct file *p, const void *buf,
				       size_t count, loff_t *pos);

#endif
