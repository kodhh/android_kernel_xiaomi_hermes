#ifndef _LINUX_MEMFD_H
#define _LINUX_MEMFD_H

#include <linux/file.h>

long memfd_fcntl(struct file *file, unsigned int cmd, unsigned long arg);

#endif
