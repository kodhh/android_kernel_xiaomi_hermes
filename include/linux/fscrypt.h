#ifndef _LINUX_FSCRYPT_H
#define _LINUX_FSCRYPT_H

#include <linux/fs.h>
#include <linux/mm.h>

#ifdef CONFIG_FS_ENCRYPTION
#include <linux/fscrypt_supp.h>
#else
#include <linux/fscrypt_notsupp.h>
#endif

#endif /* _LINUX_FSCRYPT_H */
