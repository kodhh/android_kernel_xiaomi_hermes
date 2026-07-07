/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _FS_FUSE_SHORTCIRCUIT_H
#define _FS_FUSE_SHORTCIRCUIT_H

#include "fuse_i.h"

static inline void fuse_setup_shortcircuit(struct fuse_conn *fc,
					   struct fuse_req *req) {}
static inline void fuse_shortcircuit_release(struct fuse_file *ff) {}
static inline ssize_t fuse_shortcircuit_aio_read(struct kiocb *iocb,
						 const struct iovec *iov,
						 unsigned long nr_segs,
						 loff_t pos) { return 0; }
static inline ssize_t fuse_shortcircuit_aio_write(struct kiocb *iocb,
						  const struct iovec *iov,
						  unsigned long nr_segs,
						  loff_t pos) { return 0; }

#endif /* _FS_FUSE_SHORTCIRCUIT_H */
