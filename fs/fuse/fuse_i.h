/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2001-2008  Miklos Szeredi <miklos@szeredi.hu>

  This program can be distributed under the terms of the GNU GPL.
  See the file COPYING.
*/

#ifndef _FS_FUSE_I_H
#define _FS_FUSE_I_H

#include <linux/fuse.h>
#include <linux/fs.h>
#include <linux/statfs.h>
#include <linux/filter.h>
#include <linux/idr.h>
#include <linux/mount.h>
#include <linux/cred.h>
#include <linux/fs_stack.h>
#include <linux/xattr.h>
#include <linux/wait.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/mm.h>
#include <linux/backing-dev.h>
#include <linux/mutex.h>
#include <linux/rwsem.h>
#include <linux/rbtree.h>
#include <linux/poll.h>
#include <linux/workqueue.h>

/** Default max number of pages that can be used in a single read request */
#define FUSE_DEFAULT_MAX_PAGES_PER_REQ 32

/* Backward compatibility for code still using the old name */
#define FUSE_MAX_PAGES_PER_REQ FUSE_DEFAULT_MAX_PAGES_PER_REQ

/** Maximum of max_pages received in init_out */
#define FUSE_MAX_MAX_PAGES 256

/** Bias for fi->writectr, meaning new writepages must not be sent */
#define FUSE_NOWRITE INT_MIN

/** It could be as large as PATH_MAX, but would that have any uses? */
#define FUSE_NAME_MAX 1024

/** Number of dentries for each connection in the control filesystem */
#define FUSE_CTL_NUM_DENTRIES 5

/** If the FUSE_DEFAULT_PERMISSIONS flag is given, the filesystem
    module will check permissions based on the file mode.  Otherwise no
    permission checking is done in the kernel */
#define FUSE_DEFAULT_PERMISSIONS (1 << 0)

/** If the FUSE_ALLOW_OTHER flag is given, then not only the user
    doing the mount will be allowed to access the filesystem */
#define FUSE_ALLOW_OTHER         (1 << 1)

/** Number of page pointers embedded in fuse_req */
#define FUSE_REQ_INLINE_PAGES 1

/** List of active connections */
extern struct list_head fuse_conn_list;

/** Global mutex protecting fuse_conn_list and the control filesystem */
extern struct mutex fuse_mutex;

/** Module parameters */
extern unsigned max_user_bgreq;
extern unsigned max_user_congthresh;

struct bpf_prog;
struct delayed_call;

/* One forget request */
struct fuse_forget_link {
	struct fuse_forget_one forget_one;
	struct fuse_forget_link *next;
};

#ifdef CONFIG_FUSE_BPF
struct fuse_dentry {
	struct path backing_path;
	struct bpf_prog *bpf;
};

static inline struct fuse_dentry *get_fuse_dentry(const struct dentry *entry)
{
	return entry->d_fsdata;
}

static inline void get_fuse_backing_path(const struct dentry *d,
					  struct path *path)
{
	struct fuse_dentry *di = get_fuse_dentry(d);

	if (!di) {
		*path = (struct path) {};
		return;
	}

	*path = di->backing_path;
	path_get(path);
}
#endif

/** FUSE inode */
struct fuse_inode {
	/** Inode data */
	struct inode inode;

#ifdef CONFIG_FUSE_BPF
	struct inode *backing_inode;
	struct bpf_prog *bpf;
#endif

	/** Unique ID, which identifies the inode between userspace
	 * and kernel */
	u64 nodeid;

	/** Number of lookups on this inode */
	u64 nlookup;

	/** The request used for sending the FORGET message */
	struct fuse_forget_link *forget;

	/** Time in jiffies until the file attributes are valid */
	u64 i_time;

	/* Which attributes are invalid */
	u32 inval_mask;

	/** The sticky bit in inode->i_mode may have been removed, so
	    preserve the original mode */
	umode_t orig_i_mode;

	/** 64 bit inode number */
	u64 orig_ino;

	/** Version of last attribute change */
	u64 attr_version;

	union {
		/* Write related fields (regular file only) */
		struct {
			/* Files usable in writepage.  Protected by fi->lock */
			struct list_head write_files;

			/* Writepages pending on truncate or fsync */
			struct list_head queued_writes;

			/* Number of sent writes, a negative bias
			 * (FUSE_NOWRITE) means more writes are blocked */
			int writectr;

			/* Waitq for writepage completion */
			wait_queue_head_t page_waitq;

			/* List of writepage requestst (pending or sent) */
			struct rb_root writepages;
		};

		/* readdir cache (directory only) */
		struct {
			/* true if fully cached */
			bool cached;

			/* size of cache */
			loff_t size;

			/* position at end of cache (position of next entry) */
			loff_t pos;

			/* version of the cache */
			u64 version;

			/* protects above fields */
			spinlock_t lock;
		} rdc;
	};

	/** Miscellaneous bits describing inode state */
	unsigned long state;

	/** Lock for serializing lookup and readdir for back compatibility*/
	struct mutex mutex;

	/** Lock to protect write related fields */
	spinlock_t lock;

	/**
	 * Can't take inode lock in fault path (leads to circular dependency).
	 * Introduce another semaphore which can be taken in fault path and
	 * then other filesystem paths can take this to block faults.
	 */
	struct rw_semaphore i_mmap_sem;
};

/** FUSE inode state bits */
enum {
	/** Advise readdirplus  */
	FUSE_I_ADVISE_RDPLUS,
	/** Initialized with readdirplus */
	FUSE_I_INIT_RDPLUS,
	/** An operation changing file size is in progress  */
	FUSE_I_SIZE_UNSTABLE,
	/* Bad inode */
	FUSE_I_BAD,
};

struct fuse_conn;

/**
 * Reference to lower filesystem file for read/write operations handled in
 * passthrough mode.
 * This struct also tracks the credentials to be used for handling read/write
 * operations.
 */
struct fuse_passthrough {
	struct file *filp;
	struct cred *cred;
};

/** FUSE specific file data */
struct fuse_file {
	/** Fuse connection for this file */
	struct fuse_conn *fc;

	/** Request reserved for flush and release */
	struct fuse_req *reserved_req;

	/** Kernel file handle guaranteed to be unique */
	u64 kh;

	/** File handle used by userspace */
	u64 fh;

	/** Node id of this file */
	u64 nodeid;

	/** Refcount */
	atomic_t count;

	/** FOPEN_* flags returned by open */
	u32 open_flags;

	/** Entry on inode's write_files list */
	struct list_head write_entry;

	/** Container for data related to the passthrough functionality */
	struct fuse_passthrough passthrough;

#ifdef CONFIG_FUSE_BPF
	struct file *backing_file;
	const struct cred *backing_cred;
#endif

	/** RB node to be linked on fuse_conn->polled_files */
	struct rb_node polled_node;

	/** Wait queue head for poll */
	wait_queue_head_t poll_wait;

	/** Has flock been performed on this file? */
	bool flock:1;
};

/** One input argument of a request */
struct fuse_in_arg {
	unsigned size;
	const void *value;
};

/** The request input */
struct fuse_in {
	/** The request header */
	struct fuse_in_header h;

	/** True if the data for the last argument is in req->pages */
	unsigned argpages:1;

	/** Number of arguments */
	unsigned numargs;

	/** Array of arguments */
	struct fuse_in_arg args[3];
};

/** One output argument of a request */
struct fuse_arg {
	unsigned size;
	void *value;
};

/** The request output */
struct fuse_out {
	/** Header returned from userspace */
	struct fuse_out_header h;

	/*
	 * The following bitfields are not changed during the request
	 * processing
	 */

	/** Last argument is variable length (can be shorter than
	    arg->size) */
	unsigned argvar:1;

	/** Last argument is a list of pages to copy data to */
	unsigned argpages:1;

	/** Zero partially or not copied pages */
	unsigned page_zeroing:1;

	/** Pages may be replaced with new ones */
	unsigned page_replace:1;

	/** Number or arguments */
	unsigned numargs;

	/** Array of arguments */
	struct fuse_arg args[3];
};

/** FUSE page descriptor */
struct fuse_page_desc {
	unsigned int length;
	unsigned int offset;
};

/** The request state */
enum fuse_req_state {
	FUSE_REQ_INIT = 0,
	FUSE_REQ_PENDING,
	FUSE_REQ_READING,
	FUSE_REQ_SENT,
	FUSE_REQ_WRITING,
	FUSE_REQ_FINISHED
};

/** The request IO state (for asynchronous processing) */
struct fuse_io_priv {
	int async;
	spinlock_t lock;
	unsigned reqs;
	ssize_t bytes;
	size_t size;
	__u64 offset;
	bool write;
	bool should_dirty;
	int err;
	struct kiocb *iocb;
	struct file *file;
};

/**
 * A request to the client
 */
struct fuse_req {
	/** This can be on either pending processing or io lists in
	    fuse_conn */
	struct list_head list;

	/** Entry on the interrupts list  */
	struct list_head intr_entry;

	/** refcount */
	atomic_t count;

	/** Unique ID for the interrupt request */
	u64 intr_unique;

	/*
	 * The following bitfields are either set once before the
	 * request is queued or setting/clearing them is protected by
	 * fuse_conn->lock
	 */

	/** True if the request has reply */
	unsigned isreply:1;

	/** Force sending of the request even if interrupted */
	unsigned force:1;

	/** The request was aborted */
	unsigned aborted:1;

	/** Request is sent in the background */
	unsigned background:1;

	/** The request has been interrupted */
	unsigned interrupted:1;

	/** Data is being copied to/from the request */
	unsigned locked:1;

	/** Request is counted as "waiting" */
	unsigned waiting:1;

	/** State of the request */
	enum fuse_req_state state;

	/** The request input */
	struct fuse_in in;

	/** The request output */
	struct fuse_out out;

	/** Used to wake up the task waiting for completion of request*/
	wait_queue_head_t waitq;

	/** Data for asynchronous requests */
	union {
		struct {
			union {
				struct fuse_release_in in;
				struct work_struct work;
			};
			struct path path;
		} release;
		struct fuse_init_in init_in;
		struct fuse_init_out init_out;
		struct cuse_init_in cuse_init_in;
		struct {
			struct fuse_read_in in;
			u64 attr_ver;
		} read;
		struct {
			struct fuse_write_in in;
			struct fuse_write_out out;
			struct fuse_req *next;
		} write;
		struct fuse_notify_retrieve_in retrieve_in;
		struct fuse_lk_in lk_in;
	} misc;

	/** page vector */
	struct page **pages;

	/** page-descriptor vector */
	struct fuse_page_desc *page_descs;

	/** size of the 'pages' array */
	unsigned max_pages;

	/** inline page vector */
	struct page *inline_pages[FUSE_REQ_INLINE_PAGES];

	/** inline page-descriptor vector */
	struct fuse_page_desc inline_page_descs[FUSE_REQ_INLINE_PAGES];

	/** number of pages in vector */
	unsigned num_pages;

	/** File used in the request (or NULL) */
	struct fuse_file *ff;

	/** Inode used in the request or NULL */
	struct inode *inode;

	/** Path used for completing d_canonical_path */
	struct path *canonical_path;

	/** AIO control block */
	struct fuse_io_priv *io;

	/** Link on fi->writepages */
	struct rb_node writepages_entry;

	/** Request completion callback */
	void (*end)(struct fuse_conn *, struct fuse_req *);

	/** Request is stolen from fuse_file->reserved_req */
	struct file *stolen_file;
};

struct fuse_iqueue;

/**
 * Input queue callbacks
 */
struct fuse_iqueue_ops {
	void (*wake_forget_and_unlock)(struct fuse_iqueue *fiq, bool sync)
		__releases(fiq->lock);
	void (*wake_interrupt_and_unlock)(struct fuse_iqueue *fiq, bool sync)
		__releases(fiq->lock);
	void (*wake_pending_and_unlock)(struct fuse_iqueue *fiq, bool sync)
		__releases(fiq->lock);
	void (*release)(struct fuse_iqueue *fiq);
};

extern const struct fuse_iqueue_ops fuse_dev_fiq_ops;

struct fuse_iqueue {
	unsigned connected;
	spinlock_t lock;
	wait_queue_head_t waitq;
	u64 reqctr;
	struct list_head pending;
	struct list_head interrupts;
	struct fuse_forget_link forget_list_head;
	struct fuse_forget_link *forget_list_tail;
	int forget_batch;
	struct fasync_struct *fasync;
	const struct fuse_iqueue_ops *ops;
	void *priv;
};

#define FUSE_PQ_HASH_BITS 8
#define FUSE_PQ_HASH_SIZE (1 << FUSE_PQ_HASH_BITS)

struct fuse_pqueue {
	unsigned connected;
	spinlock_t lock;
	struct list_head *processing;
	struct list_head io;
};

/**
 * Fuse device instance
 */
struct fuse_dev {
	/** Fuse connection for this device */
	struct fuse_conn *fc;

	/** Processing queue */
	struct fuse_pqueue pq;

	/** list entry on fc->devices */
	struct list_head entry;
};

/**
 * A Fuse connection.
 *
 * This structure is created, when the filesystem is mounted, and is
 * destroyed, when the client device is closed and the filesystem is
 * unmounted.
 */
struct fuse_conn {
	/** Lock protecting accessess to  members of this structure */
	spinlock_t lock;

	/** Refcount */
	atomic_t count;

	struct rcu_head rcu;

	/** The user id for this mount */
	kuid_t user_id;

	/** The group id for this mount */
	kgid_t group_id;

	/** The fuse mount flags for this mount */
	unsigned flags;

	/** Maximum read size */
	unsigned max_read;

	/** Maximum write size */
	unsigned max_write;

	/** Input queue */
	struct fuse_iqueue iq;

	/** The next unique kernel file handle */
	u64 khctr;

	/** rbtree of fuse_files waiting for poll events indexed by ph */
	struct rb_root polled_files;

	/** Maximum number of outstanding background requests */
	unsigned max_background;

	/** Number of background requests at which congestion starts */
	unsigned congestion_threshold;

	/** Number of requests currently in the background */
	unsigned num_background;

	/** Number of background requests currently queued for userspace */
	unsigned active_background;

	/** The list of background requests set aside for later queuing */
	struct list_head bg_queue;

	/** Protects: max_background, congestion_threshold, num_background,
	 * active_background, bg_queue, blocked */
	spinlock_t bg_lock;

	/** Pending interrupts */
	struct list_head interrupts;

	/** Queue of pending forgets */
	struct fuse_forget_link forget_list_head;
	struct fuse_forget_link *forget_list_tail;

	/** Batching of FORGET requests (positive indicates FORGET batch) */
	int forget_batch;

	/** Flag indicating that INIT reply has been received. Allocating
	 * any fuse request will be suspended until the flag is set */
	int initialized;

	/** Flag indicating if connection is blocked.  This will be
	    the case before the INIT reply is received, and if there
	    are too many outstading backgrounds requests */
	int blocked;

	/** waitq for blocked connection */
	wait_queue_head_t blocked_waitq;

	/** waitq for reserved requests */
	wait_queue_head_t reserved_req_waitq;

	/** The next unique request id */
	u64 reqctr;

	/** Connection established, cleared on umount, connection
	    abort and device release */
	unsigned connected;

	/** Connection failed (version mismatch).  Cannot race with
	    setting other bitfields since it is only set once in INIT
	    reply, before any other request, and never cleared */
	unsigned conn_error:1;

	/** Connection successful.  Only set in INIT */
	unsigned conn_init:1;

	/** Do readpages asynchronously?  Only set in INIT */
	unsigned async_read:1;

	/** Do not send separate SETATTR request before open(O_TRUNC)  */
	unsigned atomic_o_trunc:1;

	/** Filesystem supports NFS exporting.  Only set in INIT */
	unsigned export_support:1;

	/** Set if bdi is valid */
	unsigned bdi_initialized:1;

	/** write-back cache policy (default is write-through) */
	unsigned writeback_cache:1;

	/*
	 * The following bitfields are only for optimization purposes
	 * and hence races in setting them will not cause malfunction
	 */

	/** Is open/release not implemented by fs? */
	unsigned no_open:1;

	/** Is fsync not implemented by fs? */
	unsigned no_fsync:1;

	/** Is fsyncdir not implemented by fs? */
	unsigned no_fsyncdir:1;

	/** Is flush not implemented by fs? */
	unsigned no_flush:1;

	/** Is setxattr not implemented by fs? */
	unsigned no_setxattr:1;

	/** Is getxattr not implemented by fs? */
	unsigned no_getxattr:1;

	/** Is listxattr not implemented by fs? */
	unsigned no_listxattr:1;

	/** Is removexattr not implemented by fs? */
	unsigned no_removexattr:1;

	/** Are posix file locking primitives not implemented by fs? */
	unsigned no_lock:1;

	/** Is access not implemented by fs? */
	unsigned no_access:1;

	/** Is create not implemented by fs? */
	unsigned no_create:1;

	/** Is interrupt not implemented by fs? */
	unsigned no_interrupt:1;

	/** Is bmap not implemented by fs? */
	unsigned no_bmap:1;

	/** Is poll not implemented by fs? */
	unsigned no_poll:1;

	/** Do multi-page cached writes */
	unsigned big_writes:1;

	/** Don't apply umask to creation modes */
	unsigned dont_mask:1;

	/** Are BSD file locking primitives not implemented by fs? */
	unsigned no_flock:1;

	/** Is fallocate not implemented by fs? */
	unsigned no_fallocate:1;

	/** Does the filesystem support copy_file_range? */
	unsigned no_copy_file_range:1;

	/** fs handles killing suid/sgid/cap on write/chown/trunc */
	unsigned handle_killpriv:1;

	/** filesystem supports posix acls */
	unsigned posix_acl:1;

	/** reading the device after abort returns ECONNABORTED */
	unsigned abort_err:1;

	/** Do permission checking based on file mode */
	unsigned default_permissions:1;

	/** Allow parallel lookups and readdir */
	unsigned parallel_dirops:1;

	/** lseek not implemented by fs */
	unsigned no_lseek:1;

	/** syncfs not implemented by fs */
	unsigned no_syncfs:1;

	/** tmpfile not implemented by fs */
	unsigned no_tmpfile:1;

	/** statx not implemented by fs */
	unsigned no_statx:1;

	/** Auto-mount directory submounts */
	unsigned auto_submounts:1;

	/** Allow non-mounter access */
	unsigned allow_other:1;

	/** Cache symlinks in dentry */
	unsigned cache_symlinks:1;

	/** Explicitly invalidate data pages (not automatic) */
	unsigned explicit_inval_data:1;

	/** Max number of pages that can be used in a single request */
	unsigned int max_pages;

	/** Constrain ->max_pages to this value during feature negotiation */
	unsigned int max_pages_limit;

	/** Connection aborted via sysfs */
	bool aborted;

	/** Is rename with flags implemented by fs? */
	unsigned no_rename2:1;

	/** Use enhanced/automatic page cache invalidation. */
	unsigned auto_inval_data:1;

	/** Does the filesystem support readdirplus? */
	unsigned do_readdirplus:1;

	/** Does the filesystem want adaptive readdirplus? */
	unsigned readdirplus_auto:1;

	/** Does the filesystem support asynchronous direct-IO submission? */
	unsigned async_dio:1;

	/** Passthrough mode for read/write IO */
	unsigned int passthrough:1;

	/** Filesystem supports security context */
	unsigned int security_ctx:1;

	/** Filesystem supports create supplementary group */
	unsigned int create_supp_group:1;

	/** Handle killing suid/sgid via v2 protocol */
	unsigned int handle_killpriv_v2:1;

	/** The number of requests waiting for completion */
	atomic_t num_waiting;

	/** Negotiated minor version */
	unsigned minor;

	/** Backing dev info */
	struct backing_dev_info bdi;

	/** Entry on the fuse_conn_list */
	struct list_head entry;

	/** Device ID from super block */
	dev_t dev;

	/** Dentries in the control filesystem */
	struct dentry *ctl_dentry[FUSE_CTL_NUM_DENTRIES];

	/** number of dentries used in the above array */
	int ctl_ndents;

	/** O_ASYNC requests */
	struct fasync_struct *fasync;

	/** Key for lock owner ID scrambling */
	u32 scramble_key[4];

	/** Reserved request for the DESTROY message */
	struct fuse_req *destroy_req;

	/** Version counter for attribute changes */
	u64 attr_version;

	/** Called on final put */
	void (*release)(struct fuse_conn *);

	/** Super block for this connection. */
	struct super_block *sb;

	/** Read/write semaphore to hold when accessing sb. */
	struct rw_semaphore killsb;

	/** List of device instances belonging to this connection */
	struct list_head devices;

	/** Number of device instances */
	atomic_t dev_count;

	/** IDR for passthrough requests */
	struct idr passthrough_req;

	/** Protects passthrough_req */
	spinlock_t passthrough_req_lock;

#ifdef CONFIG_FUSE_BPF
	/** Global BPF program for this connection (from mount option) */
	struct bpf_prog *root_bpf;
#endif
};

static inline struct fuse_conn *get_fuse_conn_super(struct super_block *sb)
{
	return sb->s_fs_info;
}

static inline struct fuse_conn *get_fuse_conn(struct inode *inode)
{
	return get_fuse_conn_super(inode->i_sb);
}

static inline struct fuse_inode *get_fuse_inode(struct inode *inode)
{
	return container_of(inode, struct fuse_inode, inode);
}

static inline u64 get_node_id(struct inode *inode)
{
	return get_fuse_inode(inode)->nodeid;
}

static inline bool inode_wrong_type(const struct inode *inode, umode_t mode)
{
	return (inode->i_mode ^ mode) & S_IFMT;
}

static inline bool fuse_stale_inode(const struct inode *inode, int generation,
				    struct fuse_attr *attr)
{
	return inode->i_generation != generation ||
		inode_wrong_type(inode, attr->mode);
}

static inline void fuse_make_bad(struct inode *inode)
{
	set_bit(FUSE_I_BAD, &get_fuse_inode(inode)->state);
}

static inline bool fuse_is_bad(struct inode *inode)
{
	return unlikely(test_bit(FUSE_I_BAD, &get_fuse_inode(inode)->state));
}

static inline u64 time_to_jiffies(u64 sec, u32 nsec)
{
	if (sec || nsec) {
		struct timespec ts = {
			sec,
			min_t(u32, nsec, NSEC_PER_SEC - 1)
		};

		return get_jiffies_64() + timespec_to_jiffies(&ts);
	} else
		return 0;
}

static inline u64 attr_timeout(struct fuse_attr_out *o)
{
	return time_to_jiffies(o->attr_valid, o->attr_valid_nsec);
}

u64 entry_attr_timeout(struct fuse_entry_out *o);

/** Device operations */
extern const struct file_operations fuse_dev_operations;

extern const struct dentry_operations fuse_dentry_operations;

struct vfsmount *fuse_dentry_automount(struct path *path);

struct fuse_submount_data {
	struct fuse_conn *fc;
	struct fuse_inode *parent_fi;
};

extern struct file_system_type fuse_submount_fs_type;
extern const struct dentry_operations fuse_root_dentry_operations;

/**
 * Inode to nodeid comparison.
 */
int fuse_inode_eq(struct inode *inode, void *_nodeidp);

/**
 * Get a filled in inode
 */
struct inode *fuse_iget(struct super_block *sb, u64 nodeid,
			int generation, struct fuse_attr *attr,
			u64 attr_valid, u64 attr_version);

int fuse_lookup_name(struct super_block *sb, u64 nodeid, struct qstr *name,
		     struct fuse_entry_out *outarg, struct inode **inode,
		     struct dentry *entry);

/**
 * Send FORGET command
 */
void fuse_queue_forget(struct fuse_conn *fc, struct fuse_forget_link *forget,
		       u64 nodeid, u64 nlookup);

struct fuse_forget_link *fuse_alloc_forget(void);

/* Used by READDIRPLUS */
void fuse_force_forget(struct file *file, u64 nodeid);

/**
 * Initialize READ or READDIR request
 */
void fuse_read_fill(struct fuse_req *req, struct file *file,
		    loff_t pos, size_t count, int opcode);

/**
 * Send OPEN or OPENDIR request
 */
int fuse_open_common(struct inode *inode, struct file *file, bool isdir);

struct fuse_file *fuse_file_alloc(struct fuse_conn *fc);
struct fuse_file *fuse_file_get(struct fuse_file *ff);
void fuse_file_free(struct fuse_file *ff);
void fuse_finish_open(struct inode *inode, struct file *file);

void fuse_sync_release(struct fuse_file *ff, int flags);

/**
 * Send RELEASE or RELEASEDIR request
 */
void fuse_release_common(struct file *file, int opcode);

/**
 * Send FSYNC or FSYNCDIR request
 */
int fuse_fsync_common(struct file *file, loff_t start, loff_t end,
		      int datasync, int isdir);

/**
 * Notify poll wakeup
 */
int fuse_notify_poll_wakeup(struct fuse_conn *fc,
			    struct fuse_notify_poll_wakeup_out *outarg);

/**
 * Initialize file operations on a regular file
 */
void fuse_init_file_inode(struct inode *inode);

/**
 * Initialize inode operations on regular files and special files
 */
void fuse_init_common(struct inode *inode);

/**
 * Initialize inode and file operations on a directory
 */
void fuse_init_dir(struct inode *inode);

/**
 * Initialize inode operations on a symlink
 */
void fuse_init_symlink(struct inode *inode);

/**
 * Tmpfile support
 */
int fuse_tmpfile(struct inode *dir, struct dentry *entry, umode_t mode);
int fuse_do_tmpfile(struct inode *dir, struct dentry *entry, struct file *file,
		    umode_t mode);

/**
 * Change attributes of an inode
 */
void fuse_change_attributes(struct inode *inode, struct fuse_attr *attr,
			    u64 attr_valid, u64 attr_version);
void convert_fuse_statfs(struct kstatfs *stbuf, struct fuse_kstatfs *attr);
void fuse_copyattr(struct file *dst_file, struct file *src_file);

void fuse_change_attributes_common(struct inode *inode, struct fuse_attr *attr,
				   u64 attr_valid);

void fuse_fillattr(struct inode *inode, struct fuse_attr *attr,
			  struct kstat *stat);

/**
 * Initialize the client device
 */
int fuse_dev_init(void);

/**
 * Cleanup the client device
 */
void fuse_dev_cleanup(void);

int fuse_ctl_init(void);
void __exit fuse_ctl_cleanup(void);

/**
 * Allocate a request
 */
struct fuse_req *fuse_request_alloc(unsigned npages);

struct fuse_req *fuse_request_alloc_nofs(unsigned npages);

/**
 * Free a request
 */
void fuse_request_free(struct fuse_req *req);

/**
 * Get a request, may fail with -ENOMEM,
 * caller should specify # elements in req->pages[] explicitly
 */
struct fuse_req *fuse_get_req(struct fuse_conn *fc, unsigned npages);
struct fuse_req *fuse_get_req_for_background(struct fuse_conn *fc,
					     unsigned npages);

/*
 * Increment reference count on request
 */
void __fuse_get_request(struct fuse_req *req);

/**
 * Get a request, may fail with -ENOMEM,
 * useful for callers who doesn't use req->pages[]
 */
static inline struct fuse_req *fuse_get_req_nopages(struct fuse_conn *fc)
{
	return fuse_get_req(fc, 0);
}

/**
 * Gets a requests for a file operation, always succeeds
 */
struct fuse_req *fuse_get_req_nofail_nopages(struct fuse_conn *fc,
					     struct file *file);

/**
 * Decrement reference count of a request.  If count goes to zero free
 * the request.
 */
void fuse_put_request(struct fuse_conn *fc, struct fuse_req *req);

/**
 * Send a request (synchronous)
 */
void fuse_request_send(struct fuse_conn *fc, struct fuse_req *req);

/**
 * Send a request in the background
 */
void fuse_request_send_background(struct fuse_conn *fc, struct fuse_req *req);

void fuse_request_send_background_locked(struct fuse_conn *fc,
					 struct fuse_req *req);

/* Abort all requests */
void fuse_abort_conn(struct fuse_conn *fc);

/**
 * Invalidate inode attributes
 */
void fuse_invalidate_attr(struct inode *inode);

void fuse_invalidate_entry_cache(struct dentry *entry);

void fuse_invalidate_atime(struct inode *inode);

/**
 * Acquire reference to fuse_conn
 */
struct fuse_conn *fuse_conn_get(struct fuse_conn *fc);

void fuse_conn_kill(struct fuse_conn *fc);

/**
 * Initialize fuse_conn
 */
void fuse_iqueue_init(struct fuse_iqueue *fiq,
		      const struct fuse_iqueue_ops *ops, void *priv);
void fuse_pqueue_init(struct fuse_pqueue *fpq);
void fuse_conn_init(struct fuse_conn *fc,
		    const struct fuse_iqueue_ops *fiq_ops, void *fiq_priv);

/**
 * Release reference to fuse_conn
 */
void fuse_conn_put(struct fuse_conn *fc);

struct fuse_dev *fuse_dev_alloc(void);
void fuse_dev_install(struct fuse_dev *fud, struct fuse_conn *fc);
struct fuse_dev *fuse_dev_alloc_install(struct fuse_conn *fc);
void fuse_dev_free(struct fuse_dev *fud);

/**
 * Add connection to control filesystem
 */
int fuse_ctl_add_conn(struct fuse_conn *fc);

/**
 * Remove connection from control filesystem
 */
void fuse_ctl_remove_conn(struct fuse_conn *fc);

/**
 * Is file type valid?
 */
int fuse_valid_type(int m);

bool fuse_invalid_attr(struct fuse_attr *attr);

static inline int finalize_attr(struct inode *inode, struct fuse_attr_out *outarg,
				u64 attr_version, struct kstat *stat)
{
	int err = 0;

	if (fuse_invalid_attr(&outarg->attr) ||
	    ((inode->i_mode ^ outarg->attr.mode) & S_IFMT)) {
		fuse_make_bad(inode);
		err = -EIO;
	} else {
		fuse_change_attributes(inode, &outarg->attr,
				       attr_timeout(outarg),
				       attr_version);
		if (stat)
			fuse_fillattr(inode, &outarg->attr, stat);
	}
	return err;
}

/**
 * Is current process allowed to perform filesystem operation?
 */
int fuse_allow_current_process(struct fuse_conn *fc);

u64 fuse_lock_owner_id(struct fuse_conn *fc, fl_owner_t id);

int fuse_update_attributes(struct inode *inode, struct kstat *stat,
			   struct file *file, bool *refreshed);

void fuse_flush_writepages(struct inode *inode);

void fuse_set_nowrite(struct inode *inode);
void fuse_release_nowrite(struct inode *inode);

u64 fuse_get_attr_version(struct fuse_conn *fc);

/**
 * File-system tells the kernel to invalidate cache for the given node id.
 */
int fuse_reverse_inval_inode(struct super_block *sb, u64 nodeid,
			     loff_t offset, loff_t len);

/**
 * File-system tells the kernel to invalidate parent attributes and
 * the dentry matching parent/name.
 *
 * If the child_nodeid is non-zero and:
 *    - matches the inode number for the dentry matching parent/name,
 *    - is not a mount point
 *    - is a file or oan empty directory
 * then the dentry is unhashed (d_delete()).
 */
int fuse_reverse_inval_entry(struct super_block *sb, u64 parent_nodeid,
			     u64 child_nodeid, struct qstr *name);

int fuse_do_open(struct fuse_conn *fc, u64 nodeid, struct file *file,
		 bool isdir);

/**
 * fuse_direct_io() flags
 */

/** If set, it is WRITE; otherwise - READ */
#define FUSE_DIO_WRITE (1 << 0)

/** CUSE pass fuse_direct_io() a file which f_mapping->host is not from FUSE */
#define FUSE_DIO_CUSE  (1 << 1)

ssize_t fuse_direct_io(struct fuse_io_priv *io, const struct iovec *iov,
		       unsigned long nr_segs, size_t count, loff_t *ppos,
		       int flags);
long fuse_do_ioctl(struct file *file, unsigned int cmd, unsigned long arg,
		   unsigned int flags);
long fuse_ioctl_common(struct file *file, unsigned int cmd,
		       unsigned long arg, unsigned int flags);
unsigned fuse_file_poll(struct file *file, poll_table *wait);
int fuse_dev_release(struct inode *inode, struct file *file);

bool fuse_write_update_size(struct inode *inode, loff_t pos);

int fuse_flush_times(struct inode *inode, struct fuse_file *ff);
int fuse_write_inode(struct inode *inode, struct writeback_control *wbc);

int fuse_syncfs(struct super_block *sb, int wait);
int fuse_statx(const struct path *path, struct kstat *stat,
	       u32 request_mask, unsigned int flags);

int fuse_do_setattr(struct dentry *entry, struct iattr *attr,
		    struct file *file);

/* passthrough.c */
int fuse_passthrough_open(struct fuse_conn *fc, u32 lower_fd);
int fuse_passthrough_setup(struct fuse_conn *fc, struct fuse_file *ff,
			   struct fuse_open_out *openarg);
void fuse_passthrough_release(struct fuse_passthrough *passthrough);
ssize_t fuse_passthrough_read_iter(struct file *file, struct kiocb *iocb_fuse,
				   const struct iovec *iov, unsigned long nr_segs,
				   loff_t *ppos);
ssize_t fuse_passthrough_write_iter(struct file *file, struct kiocb *iocb_fuse,
				    const struct iovec *iov, unsigned long nr_segs,
				    loff_t *ppos);
ssize_t fuse_passthrough_mmap(struct file *file, struct vm_area_struct *vma);
void fuse_aio_rw_complete(struct kiocb *iocb, long res, long res2, bool is_write);

static inline ssize_t call_read_iter(struct file *file, struct kiocb *kio,
				     const struct iovec *iov,
				     unsigned long nr_segs, loff_t pos)
{
	return file->f_op->aio_read(kio, iov, nr_segs, pos);
}

static inline ssize_t call_write_iter(struct file *file, struct kiocb *kio,
				      const struct iovec *iov,
				      unsigned long nr_segs, loff_t pos)
{
	return file->f_op->aio_write(kio, iov, nr_segs, pos);
}

static inline int call_mmap(struct file *file, struct vm_area_struct *vma)
{
	return file->f_op->mmap(file, vma);
}

/* BPF_PROG_RUN is defined in linux/filter.h */

void fuse_unlock_inode(struct inode *inode, bool locked);
bool fuse_lock_inode(struct inode *inode);

static inline void convert_statfs_to_fuse(struct fuse_kstatfs *attr,
					  struct kstatfs *stbuf)
{
	attr->bsize   = stbuf->f_bsize;
	attr->frsize  = stbuf->f_frsize;
	attr->blocks  = stbuf->f_blocks;
	attr->bfree   = stbuf->f_bfree;
	attr->bavail  = stbuf->f_bavail;
	attr->files   = stbuf->f_files;
	attr->ffree   = stbuf->f_ffree;
	attr->namelen = stbuf->f_namelen;
}

bool update_mtime(unsigned ivalid, bool trust_local_mtime);
void iattr_to_fattr(struct iattr *iattr, struct fuse_setattr_in *arg,
		    bool trust_local_cmtime);

#ifdef CONFIG_FUSE_BPF
struct fuse_err_ret {
	void *result;
	bool ret;
};

int __init fuse_bpf_init(void);
void __exit fuse_bpf_cleanup(void);

ssize_t fuse_bpf_simple_request(struct fuse_conn *fc, struct fuse_bpf_args *args);

struct inode *fuse_iget_backing(struct super_block *sb,
				struct inode *backing_inode);

#define fuse_bpf_backing(inode, io, initialize, backing, finalize,	\
			 args...)					\
({									\
	struct fuse_err_ret fer = {0};					\
	int ext_flags;							\
	struct fuse_inode *fuse_inode = get_fuse_inode(inode);		\
	struct fuse_conn *fc = get_fuse_conn(inode);			\
	io feo = {0};							\
	struct fuse_bpf_args fa = {0}, fa_backup = {0};			\
	bool locked;							\
	ssize_t res;							\
	void *err;							\
	int i;								\
	bool initialized = false;					\
									\
	do {								\
		if (!fuse_inode || !fuse_inode->backing_inode)		\
			break;						\
									\
		err = ERR_PTR(initialize(&fa, &feo, args));		\
		if (err) {						\
			fer = (struct fuse_err_ret) {			\
				err,					\
				true,					\
			};						\
			break;						\
		}							\
		initialized = true;					\
									\
		fa_backup = fa;						\
		fa.opcode |= FUSE_PREFILTER;				\
		for (i = 0; i < fa.in_numargs; ++i)			\
			fa.out_args[i] = (struct fuse_bpf_arg) {	\
				.size = fa.in_args[i].size,		\
				.value = (void *)fa.in_args[i].value,	\
			};						\
		fa.out_numargs = fa.in_numargs;				\
									\
		ext_flags = fuse_inode->bpf ?				\
			BPF_PROG_RUN(fuse_inode->bpf, &fa) :		\
			FUSE_BPF_BACKING;				\
		if (ext_flags < 0) {					\
			fer = (struct fuse_err_ret) {			\
				ERR_PTR(ext_flags),			\
				true,					\
			};						\
			break;						\
		}							\
									\
		if (ext_flags & FUSE_BPF_USER_FILTER) {			\
			locked = fuse_lock_inode(inode);		\
			res = fuse_bpf_simple_request(fc, &fa);		\
			fuse_unlock_inode(inode, locked);		\
			if (res < 0) {					\
				fer = (struct fuse_err_ret) {		\
					ERR_PTR(res),			\
					true,				\
				};					\
				break;					\
			}						\
		}							\
									\
		if (!(ext_flags & FUSE_BPF_BACKING))			\
			break;						\
									\
		fa.opcode &= ~FUSE_PREFILTER;				\
		for (i = 0; i < fa.in_numargs; ++i)			\
			fa.in_args[i] = (struct fuse_bpf_in_arg) {	\
				.size = fa.out_args[i].size,		\
				.value = fa.out_args[i].value,		\
			};						\
		for (i = 0; i < fa_backup.out_numargs; ++i)		\
			fa.out_args[i] = (struct fuse_bpf_arg) {	\
				.size = fa_backup.out_args[i].size,	\
				.value = fa_backup.out_args[i].value,	\
			};						\
		fa.out_numargs = fa_backup.out_numargs;			\
									\
		fer = (struct fuse_err_ret) {				\
			ERR_PTR(backing(&fa, args)),			\
			true,						\
		};							\
		if (IS_ERR(fer.result))					\
			fa.error_in = PTR_ERR(fer.result);		\
		if (!(ext_flags & FUSE_BPF_POST_FILTER))		\
			break;						\
									\
		fa.opcode |= FUSE_POSTFILTER;				\
		for (i = 0; i < fa.out_numargs; ++i)			\
			fa.in_args[fa.in_numargs++] =			\
				(struct fuse_bpf_in_arg) {		\
					.size = fa.out_args[i].size,	\
					.value = fa.out_args[i].value,	\
				};					\
		ext_flags = BPF_PROG_RUN(fuse_inode->bpf, &fa);		\
		if (ext_flags < 0) {					\
			fer = (struct fuse_err_ret) {			\
				ERR_PTR(ext_flags),			\
				true,					\
			};						\
			break;						\
		}							\
		if (!(ext_flags & FUSE_BPF_USER_FILTER))		\
			break;						\
									\
		fa.out_args[0].size = fa_backup.out_args[0].size;	\
		fa.out_args[1].size = fa_backup.out_args[1].size;	\
		fa.out_numargs = fa_backup.out_numargs;			\
		locked = fuse_lock_inode(inode);			\
		res = fuse_bpf_simple_request(fc, &fa);			\
		fuse_unlock_inode(inode, locked);			\
		if (res < 0) {						\
			fer.result = ERR_PTR(res);			\
			break;						\
		}							\
	} while (false);						\
									\
	if (initialized && fer.ret) {					\
		err = finalize(&fa, args);				\
		if (err)						\
			fer.result = err;				\
	}								\
									\
	fer;								\
})

struct bpf_prog *fuse_get_bpf_prog(struct file *file);

struct fuse_dummy_io {
	int unused;
};

struct fuse_open_io {
	struct fuse_open_in foi;
	struct fuse_open_out foo;
};

int fuse_open_initialize(struct fuse_bpf_args *fa, struct fuse_open_io *foi,
			 struct inode *inode, struct file *file, bool isdir);
int fuse_open_backing(struct fuse_bpf_args *fa,
		      struct inode *inode, struct file *file, bool isdir);
void *fuse_open_finalize(struct fuse_bpf_args *fa,
		       struct inode *inode, struct file *file, bool isdir);

struct fuse_create_open_io {
	struct fuse_create_in fci;
	struct fuse_entry_out feo;
	struct fuse_open_out foo;
};

int fuse_create_open_initialize(
		struct fuse_bpf_args *fa, struct fuse_create_open_io *fcoi,
		struct inode *dir, struct dentry *entry,
		struct file *file, unsigned int flags, umode_t mode);
int fuse_create_open_backing(
		struct fuse_bpf_args *fa,
		struct inode *dir, struct dentry *entry,
		struct file *file, unsigned int flags, umode_t mode);
void *fuse_create_open_finalize(
		struct fuse_bpf_args *fa,
		struct inode *dir, struct dentry *entry,
		struct file *file, unsigned int flags, umode_t mode);

int fuse_mknod_initialize(
		struct fuse_bpf_args *fa, struct fuse_mknod_in *fmi,
		struct inode *dir, struct dentry *entry, umode_t mode, dev_t rdev);
int fuse_mknod_backing(
		struct fuse_bpf_args *fa,
		struct inode *dir, struct dentry *entry, umode_t mode, dev_t rdev);
void *fuse_mknod_finalize(
		struct fuse_bpf_args *fa,
		struct inode *dir, struct dentry *entry, umode_t mode, dev_t rdev);

int fuse_mkdir_initialize(
		struct fuse_bpf_args *fa, struct fuse_mkdir_in *fmi,
		struct inode *dir, struct dentry *entry, umode_t mode);
int fuse_mkdir_backing(
		struct fuse_bpf_args *fa,
		struct inode *dir, struct dentry *entry, umode_t mode);
void *fuse_mkdir_finalize(
		struct fuse_bpf_args *fa,
		struct inode *dir, struct dentry *entry, umode_t mode);

int fuse_rmdir_initialize(
		struct fuse_bpf_args *fa, struct fuse_dummy_io *fmi,
		struct inode *dir, struct dentry *entry);
int fuse_rmdir_backing(
		struct fuse_bpf_args *fa,
		struct inode *dir, struct dentry *entry);
void *fuse_rmdir_finalize(
		struct fuse_bpf_args *fa,
		struct inode *dir, struct dentry *entry);

int fuse_rename2_initialize(struct fuse_bpf_args *fa, struct fuse_rename2_in *fri,
			    struct inode *olddir, struct dentry *oldent,
			    struct inode *newdir, struct dentry *newent,
			    unsigned int flags);
int fuse_rename2_backing(struct fuse_bpf_args *fa,
			 struct inode *olddir, struct dentry *oldent,
			 struct inode *newdir, struct dentry *newent,
			 unsigned int flags);
void *fuse_rename2_finalize(struct fuse_bpf_args *fa,
			    struct inode *olddir, struct dentry *oldent,
			    struct inode *newdir, struct dentry *newent,
			    unsigned int flags);

int fuse_rename_initialize(struct fuse_bpf_args *fa, struct fuse_rename_in *fri,
			   struct inode *olddir, struct dentry *oldent,
			   struct inode *newdir, struct dentry *newent);
int fuse_rename_backing(struct fuse_bpf_args *fa,
			struct inode *olddir, struct dentry *oldent,
			struct inode *newdir, struct dentry *newent);
void *fuse_rename_finalize(struct fuse_bpf_args *fa,
			   struct inode *olddir, struct dentry *oldent,
			   struct inode *newdir, struct dentry *newent);

int fuse_unlink_initialize(
		struct fuse_bpf_args *fa, struct fuse_dummy_io *fmi,
		struct inode *dir, struct dentry *entry);
int fuse_unlink_backing(
		struct fuse_bpf_args *fa,
		struct inode *dir, struct dentry *entry);
void *fuse_unlink_finalize(
		struct fuse_bpf_args *fa,
		struct inode *dir, struct dentry *entry);

int fuse_link_initialize(struct fuse_bpf_args *fa, struct fuse_link_in *fli,
			  struct dentry *entry, struct inode *dir,
			  struct dentry *newent);
int fuse_link_backing(struct fuse_bpf_args *fa, struct dentry *entry,
		      struct inode *dir, struct dentry *newent);
void *fuse_link_finalize(struct fuse_bpf_args *fa, struct dentry *entry,
			 struct inode *dir, struct dentry *newent);

int fuse_release_initialize(struct fuse_bpf_args *fa, struct fuse_release_in *fri,
			    struct inode *inode, struct file *file);
int fuse_release_backing(struct fuse_bpf_args *fa,
			 struct inode *inode, struct file *file);
void *fuse_release_finalize(struct fuse_bpf_args *fa,
			    struct inode *inode, struct file *file);

int fuse_flush_initialize(struct fuse_bpf_args *fa, struct fuse_flush_in *ffi,
			  struct file *file, fl_owner_t id);
int fuse_flush_backing(struct fuse_bpf_args *fa, struct file *file, fl_owner_t id);
void *fuse_flush_finalize(struct fuse_bpf_args *fa,
			  struct file *file, fl_owner_t id);

struct fuse_lseek_io {
	struct fuse_lseek_in fli;
	struct fuse_lseek_out flo;
};

int fuse_lseek_initialize(struct fuse_bpf_args *fa, struct fuse_lseek_io *fli,
			  struct file *file, loff_t offset, int whence);
int fuse_lseek_backing(struct fuse_bpf_args *fa, struct file *file, loff_t offset, int whence);
void *fuse_lseek_finalize(struct fuse_bpf_args *fa, struct file *file, loff_t offset, int whence);

struct fuse_copy_file_range_io {
	struct fuse_copy_file_range_in fci;
	struct fuse_write_out fwo;
};

int fuse_copy_file_range_initialize(struct fuse_bpf_args *fa,
				   struct fuse_copy_file_range_io *fcf,
				   struct file *file_in, loff_t pos_in,
				   struct file *file_out, loff_t pos_out,
				   size_t len, unsigned int flags);
int fuse_copy_file_range_backing(struct fuse_bpf_args *fa,
				 struct file *file_in, loff_t pos_in,
				 struct file *file_out, loff_t pos_out,
				 size_t len, unsigned int flags);
void *fuse_copy_file_range_finalize(struct fuse_bpf_args *fa,
				    struct file *file_in, loff_t pos_in,
				    struct file *file_out, loff_t pos_out,
				    size_t len, unsigned int flags);

int fuse_fsync_initialize(struct fuse_bpf_args *fa, struct fuse_fsync_in *ffi,
		   struct file *file, loff_t start, loff_t end, int datasync);
int fuse_fsync_backing(struct fuse_bpf_args *fa,
		   struct file *file, loff_t start, loff_t end, int datasync);
void *fuse_fsync_finalize(struct fuse_bpf_args *fa,
		   struct file *file, loff_t start, loff_t end, int datasync);
int fuse_dir_fsync_initialize(struct fuse_bpf_args *fa, struct fuse_fsync_in *ffi,
		   struct file *file, loff_t start, loff_t end, int datasync);

struct fuse_getxattr_io {
	struct fuse_getxattr_in fgi;
	struct fuse_getxattr_out fgo;
};

int fuse_getxattr_initialize(
		struct fuse_bpf_args *fa, struct fuse_getxattr_io *fgio,
		struct dentry *dentry, const char *name, void *value,
		size_t size);
int fuse_getxattr_backing(
		struct fuse_bpf_args *fa,
		struct dentry *dentry, const char *name, void *value,
		size_t size);
void *fuse_getxattr_finalize(
		struct fuse_bpf_args *fa,
		struct dentry *dentry, const char *name, void *value,
		size_t size);

int fuse_listxattr_initialize(struct fuse_bpf_args *fa,
			       struct fuse_getxattr_io *fgio,
			       struct dentry *dentry, char *list, size_t size);
int fuse_listxattr_backing(struct fuse_bpf_args *fa, struct dentry *dentry,
			   char *list, size_t size);
void *fuse_listxattr_finalize(struct fuse_bpf_args *fa, struct dentry *dentry,
			      char *list, size_t size);

int fuse_setxattr_initialize(struct fuse_bpf_args *fa,
			     struct fuse_setxattr_in *fsxi,
			     struct dentry *dentry, const char *name,
			     const void *value, size_t size, int flags);
int fuse_setxattr_backing(struct fuse_bpf_args *fa, struct dentry *dentry,
			  const char *name, const void *value, size_t size,
			  int flags);
void *fuse_setxattr_finalize(struct fuse_bpf_args *fa, struct dentry *dentry,
			     const char *name, const void *value, size_t size,
			     int flags);

int fuse_removexattr_initialize(struct fuse_bpf_args *fa,
				struct fuse_dummy_io *unused,
				struct dentry *dentry, const char *name);
int fuse_removexattr_backing(struct fuse_bpf_args *fa,
			     struct dentry *dentry, const char *name);
void *fuse_removexattr_finalize(struct fuse_bpf_args *fa,
				struct dentry *dentry, const char *name);

struct fuse_read_iter_out {
	uint64_t ret;
};
struct fuse_file_read_iter_io {
	struct fuse_read_in fri;
	struct fuse_read_iter_out frio;
};

int fuse_file_read_iter_initialize(
		struct fuse_bpf_args *fa, struct fuse_file_read_iter_io *fri,
		struct kiocb *iocb, struct iov_iter *to);
int fuse_file_read_iter_backing(struct fuse_bpf_args *fa,
		struct kiocb *iocb, struct iov_iter *to);
void *fuse_file_read_iter_finalize(struct fuse_bpf_args *fa,
		struct kiocb *iocb, struct iov_iter *to);

struct fuse_write_iter_out {
	uint64_t ret;
};
struct fuse_file_write_iter_io {
	struct fuse_write_in fwi;
	struct fuse_write_out fwo;
	struct fuse_write_iter_out fwio;
};

int fuse_file_write_iter_initialize(
		struct fuse_bpf_args *fa, struct fuse_file_write_iter_io *fwio,
		struct kiocb *iocb, struct iov_iter *from);
int fuse_file_write_iter_backing(struct fuse_bpf_args *fa,
		struct kiocb *iocb, struct iov_iter *from);
void *fuse_file_write_iter_finalize(struct fuse_bpf_args *fa,
		struct kiocb *iocb, struct iov_iter *from);

ssize_t fuse_backing_mmap(struct file *file, struct vm_area_struct *vma);

int fuse_file_fallocate_initialize(struct fuse_bpf_args *fa,
		struct fuse_fallocate_in *ffi,
		struct file *file, int mode, loff_t offset, loff_t length);
int fuse_file_fallocate_backing(struct fuse_bpf_args *fa,
		struct file *file, int mode, loff_t offset, loff_t length);
void *fuse_file_fallocate_finalize(struct fuse_bpf_args *fa,
		struct file *file, int mode, loff_t offset, loff_t length);

int fuse_handle_backing(struct fuse_entry_bpf *feb, struct inode **backing_inode,
			struct path *backing_path);
int fuse_handle_bpf_prog(struct fuse_entry_bpf *feb, struct inode *parent,
			 struct bpf_prog **bpf);

struct fuse_lookup_io {
	struct fuse_entry_out feo;
	struct fuse_entry_bpf feb;
};

int fuse_lookup_initialize(struct fuse_bpf_args *fa, struct fuse_lookup_io *feo,
	       struct inode *dir, struct dentry *entry, unsigned int flags);
int fuse_lookup_backing(struct fuse_bpf_args *fa, struct inode *dir,
			  struct dentry *entry, unsigned int flags);
struct dentry *fuse_lookup_finalize(struct fuse_bpf_args *fa, struct inode *dir,
			   struct dentry *entry, unsigned int flags);
int fuse_revalidate_backing(struct fuse_bpf_args *fa, struct inode *dir,
			   struct dentry *entry, unsigned int flags);
void *fuse_revalidate_finalize(struct fuse_bpf_args *fa, struct inode *dir,
			   struct dentry *entry, unsigned int flags);

int fuse_canonical_path_initialize(struct fuse_bpf_args *fa,
				   struct fuse_dummy_io *fdi,
				   const struct path *path,
				   struct path *canonical_path);
int fuse_canonical_path_backing(struct fuse_bpf_args *fa, const struct path *path,
				struct path *canonical_path);
void *fuse_canonical_path_finalize(struct fuse_bpf_args *fa,
				   const struct path *path,
				   struct path *canonical_path);

struct fuse_getattr_io {
	struct fuse_getattr_in fgi;
	struct fuse_attr_out fao;
};
int fuse_getattr_initialize(struct fuse_bpf_args *fa, struct fuse_getattr_io *fgio,
			const struct dentry *entry, struct kstat *stat,
			u32 request_mask, unsigned int flags);
int fuse_getattr_backing(struct fuse_bpf_args *fa,
			const struct dentry *entry, struct kstat *stat,
			u32 request_mask, unsigned int flags);
void *fuse_getattr_finalize(struct fuse_bpf_args *fa,
			const struct dentry *entry, struct kstat *stat,
			u32 request_mask, unsigned int flags);

struct fuse_setattr_io {
	struct fuse_setattr_in fsi;
	struct fuse_attr_out fao;
};

int fuse_setattr_initialize(struct fuse_bpf_args *fa, struct fuse_setattr_io *fsi,
		struct dentry *dentry, struct iattr *attr, struct file *file);
int fuse_setattr_backing(struct fuse_bpf_args *fa,
		struct dentry *dentry, struct iattr *attr, struct file *file);
void *fuse_setattr_finalize(struct fuse_bpf_args *fa,
		struct dentry *dentry, struct iattr *attr, struct file *file);

int fuse_statfs_initialize(struct fuse_bpf_args *fa, struct fuse_statfs_out *fso,
		struct dentry *dentry, struct kstatfs *buf);
int fuse_statfs_backing(struct fuse_bpf_args *fa,
		struct dentry *dentry, struct kstatfs *buf);
void *fuse_statfs_finalize(struct fuse_bpf_args *fa,
		struct dentry *dentry, struct kstatfs *buf);

int fuse_get_link_initialize(struct fuse_bpf_args *fa, struct fuse_dummy_io *dummy,
		struct inode *inode, struct dentry *dentry,
		struct delayed_call *callback, const char **out);
int fuse_get_link_backing(struct fuse_bpf_args *fa,
		struct inode *inode, struct dentry *dentry,
		struct delayed_call *callback, const char **out);
void *fuse_get_link_finalize(struct fuse_bpf_args *fa,
		struct inode *inode, struct dentry *dentry,
		struct delayed_call *callback, const char **out);

int fuse_symlink_initialize(
		struct fuse_bpf_args *fa, struct fuse_dummy_io *unused,
		struct inode *dir, struct dentry *entry, const char *link, int len);
int fuse_symlink_backing(
		struct fuse_bpf_args *fa,
		struct inode *dir, struct dentry *entry, const char *link, int len);
void *fuse_symlink_finalize(
		struct fuse_bpf_args *fa,
		struct inode *dir, struct dentry *entry, const char *link, int len);

struct fuse_read_io {
	struct fuse_read_in fri;
	struct fuse_read_out fro;
};

int fuse_readdir_initialize(struct fuse_bpf_args *fa, struct fuse_read_io *frio,
			    struct file *file, struct dir_context *ctx,
			    bool *force_again, bool *allow_force, bool is_continued);
int fuse_readdir_backing(struct fuse_bpf_args *fa,
			 struct file *file, struct dir_context *ctx,
			 bool *force_again, bool *allow_force, bool is_continued);
void *fuse_readdir_finalize(struct fuse_bpf_args *fa,
			    struct file *file, struct dir_context *ctx,
			    bool *force_again, bool *allow_force, bool is_continued);

int fuse_access_initialize(struct fuse_bpf_args *fa, struct fuse_access_in *fai,
			   struct inode *inode, int mask);
int fuse_access_backing(struct fuse_bpf_args *fa, struct inode *inode, int mask);
void *fuse_access_finalize(struct fuse_bpf_args *fa, struct inode *inode, int mask);

int fuse_file_flock_backing(struct file *file, int cmd, struct file_lock *fl);
long fuse_backing_ioctl(struct file *file, unsigned int command,
			unsigned long arg, int flags);
#endif /* CONFIG_FUSE_BPF */

struct posix_acl *fuse_get_acl(struct inode *inode, int type);
int fuse_set_acl(struct inode *inode, struct posix_acl *acl, int type);
extern const struct xattr_handler *fuse_acl_xattr_handlers[];

#endif /* _FS_FUSE_I_H */
