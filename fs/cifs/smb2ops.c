/*
 *  SMB2 version specific operations
 *
 *  Copyright (c) 2012, Jeff Layton <jlayton@redhat.com>
 *
 *  This library is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License v2 as published
 *  by the Free Software Foundation.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See
 *  the GNU Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public License
 *  along with this library; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

#include <linux/pagemap.h>
#include <linux/vfs.h>
#include <linux/falloc.h>
#include <linux/scatterlist.h>
#include <crypto/aead.h>
#include "cifsglob.h"
#include "smb2pdu.h"
#include "smb2proto.h"
#include "cifsproto.h"
#include "cifs_debug.h"
#include "cifs_unicode.h"
#include "smb2status.h"
#include "smb2glob.h"

/* Missing share capability flags */
#ifndef SMB2_SHARE_CAP_CONTINUOUS_AVAILABILITY
#define SMB2_SHARE_CAP_CONTINUOUS_AVAILABILITY __constant_cpu_to_le32(0x00000010)
#endif
#ifndef SMB2_SHARE_CAP_SCALEOUT
#define SMB2_SHARE_CAP_SCALEOUT __constant_cpu_to_le32(0x00000020)
#endif
#ifndef SMB2_SHARE_CAP_CLUSTER
#define SMB2_SHARE_CAP_CLUSTER __constant_cpu_to_le32(0x00000040)
#endif
#ifndef SMB2_SHARE_CAP_ASYMMETRIC
#define SMB2_SHARE_CAP_ASYMMETRIC __constant_cpu_to_le32(0x00000080)
#endif

/* Missing NTSTATUS codes */
#ifndef STATUS_NETWORK_SESSION_EXPIRED
#define STATUS_NETWORK_SESSION_EXPIRED __constant_cpu_to_le32(0x00010016)
#endif
#ifndef STATUS_USER_SESSION_DELETED
#define STATUS_USER_SESSION_DELETED __constant_cpu_to_le32(0x0001001E)
#endif

/* Missing FSCTL codes */
#ifndef FSCTL_DUPLICATE_EXTENTS_TO_FILE
#define FSCTL_DUPLICATE_EXTENTS_TO_FILE 0x00098344
#endif
#ifndef FSCTL_SET_INTEGRITY_INFORMATION
#define FSCTL_SET_INTEGRITY_INFORMATION 0x0009C280
#endif
#ifndef FSCTL_SRV_ENUMERATE_SNAPSHOTS
#define FSCTL_SRV_ENUMERATE_SNAPSHOTS 0x00144064
#endif
#ifndef FSCTL_SRV_REQUEST_RESUME_KEY
#define FSCTL_SRV_REQUEST_RESUME_KEY 0x00140078
#endif
#ifndef FSCTL_SRV_COPYCHUNK
#define FSCTL_SRV_COPYCHUNK 0x001440F2
#endif

/* Compression format values */
#ifndef COMPRESSION_FORMAT_NONE
#define COMPRESSION_FORMAT_NONE		cpu_to_le16(0x0000)
#endif
#ifndef COMPRESSION_FORMAT_DEFAULT
#define COMPRESSION_FORMAT_DEFAULT	cpu_to_le16(0x0001)
#endif
#ifndef COMPRESSION_FORMAT_LZNT1
#define COMPRESSION_FORMAT_LZNT1	cpu_to_le16(0x0002)
#endif

/* Missing FSCTL codes for DFS and validate negotiate */
#ifndef FSCTL_DFS_GET_REFERRALS
#define FSCTL_DFS_GET_REFERRALS 0x00060194
#endif
#ifndef FSCTL_VALIDATE_NEGOTIATE_INFO
#define FSCTL_VALIDATE_NEGOTIATE_INFO 0x00140204
#endif

struct close_cancelled_open {
	struct cifs_fid fid;
	struct cifs_tcon *tcon;
	struct work_struct work;
};

/* Forward declarations for extern functions not yet in smb2proto.h */
extern int SMB2_ioctl(const unsigned int xid, struct cifs_tcon *tcon,
		      u64 persistent_fid, u64 volatile_fid, u32 opcode,
		      bool is_fsctl, char *in_data, u32 in_len,
		      char **out_data, u32 *out_len);
extern int SMB2_set_compression(const unsigned int xid, struct cifs_tcon *tcon,
				u64 persistent_fid, u64 volatile_fid,
				__le16 compression_level);
extern int SMB2_QFS_attr(const unsigned int xid, struct cifs_tcon *tcon,
			 u64 persistent_fid, u64 volatile_fid, int level);
extern void smb2_cancelled_close_fid(struct work_struct *work);

static int
change_conf(struct TCP_Server_Info *server)
{
	server->credits += server->echo_credits + server->oplock_credits;
	server->oplock_credits = server->echo_credits = 0;
	switch (server->credits) {
	case 0:
		return -1;
	case 1:
		server->echoes = false;
		server->oplocks = false;
		cifs_dbg(VFS, "disabling echoes and oplocks\n");
		break;
	case 2:
		server->echoes = true;
		server->oplocks = false;
		server->echo_credits = 1;
		cifs_dbg(FYI, "disabling oplocks\n");
		break;
	default:
		server->echoes = true;
		if (enable_oplocks) {
			server->oplocks = true;
			server->oplock_credits = 1;
		} else
			server->oplocks = false;

		server->echo_credits = 1;
	}
	server->credits -= server->echo_credits + server->oplock_credits;
	return 0;
}

static void
smb2_add_credits(struct TCP_Server_Info *server, const unsigned int add,
		 const int optype)
{
	int *val, rc = 0;
	spin_lock(&server->req_lock);
	val = server->ops->get_credits_field(server, optype);
	*val += add;
	server->in_flight--;
	if (server->in_flight == 0 && (optype & CIFS_OP_MASK) != CIFS_NEG_OP)
		rc = change_conf(server);
	else if (server->in_flight > 0 && server->oplock_credits == 0 &&
		 server->oplocks) {
		if (server->credits > 1) {
			server->credits--;
			server->oplock_credits++;
		}
	}
	spin_unlock(&server->req_lock);
	wake_up(&server->request_q);
	if (rc)
		cifs_reconnect(server);
}

static void
smb2_set_credits(struct TCP_Server_Info *server, const int val)
{
	spin_lock(&server->req_lock);
	server->credits = val;
	spin_unlock(&server->req_lock);
}

static int *
smb2_get_credits_field(struct TCP_Server_Info *server, const int optype)
{
	switch (optype) {
	case CIFS_ECHO_OP:
		return &server->echo_credits;
	case CIFS_OBREAK_OP:
		return &server->oplock_credits;
	default:
		return &server->credits;
	}
}

static unsigned int
smb2_get_credits(struct mid_q_entry *mid)
{
	return le16_to_cpu(((struct smb2_hdr *)mid->resp_buf)->CreditRequest);
}

static __u64
smb2_get_next_mid(struct TCP_Server_Info *server)
{
	__u64 mid;
	spin_lock(&GlobalMid_Lock);
	mid = server->CurrentMid++;
	spin_unlock(&GlobalMid_Lock);
	return mid;
}

static struct mid_q_entry *
smb2_find_mid(struct TCP_Server_Info *server, char *buf)
{
	struct mid_q_entry *mid;
	struct smb2_hdr *hdr = (struct smb2_hdr *)buf;

	spin_lock(&GlobalMid_Lock);
	list_for_each_entry(mid, &server->pending_mid_q, qhead) {
		if ((mid->mid == hdr->MessageId) &&
		    (mid->mid_state == MID_REQUEST_SUBMITTED) &&
		    (mid->command == hdr->Command)) {
			spin_unlock(&GlobalMid_Lock);
			return mid;
		}
	}
	spin_unlock(&GlobalMid_Lock);
	return NULL;
}

static void
smb2_dump_detail(void *buf)
{
#ifdef CONFIG_CIFS_DEBUG2
	struct smb2_hdr *smb = (struct smb2_hdr *)buf;

	cifs_dbg(VFS, "Cmd: %d Err: 0x%x Flags: 0x%x Mid: %llu Pid: %d\n",
		 smb->Command, smb->Status, smb->Flags, smb->MessageId,
		 smb->ProcessId);
	cifs_dbg(VFS, "smb buf %p len %u\n", smb, smb2_calc_size(smb));
#endif
}

static bool
smb2_need_neg(struct TCP_Server_Info *server)
{
	return server->max_read == 0;
}

static int
smb2_negotiate(const unsigned int xid, struct cifs_ses *ses)
{
	int rc;
	ses->server->CurrentMid = 0;
	rc = SMB2_negotiate(xid, ses);
	if (rc == -EAGAIN)
		rc = -EHOSTDOWN;
	return rc;
}

static unsigned int
smb2_negotiate_wsize(struct cifs_tcon *tcon, struct smb_vol *volume_info)
{
	struct TCP_Server_Info *server = tcon->ses->server;
	unsigned int wsize;

	wsize = volume_info->wsize ? volume_info->wsize : CIFS_DEFAULT_IOSIZE;
	wsize = min_t(unsigned int, wsize, server->max_write);
	wsize = min_t(unsigned int, wsize, SMB2_MAX_BUFFER_SIZE);

	return wsize;
}

static unsigned int
smb2_negotiate_rsize(struct cifs_tcon *tcon, struct smb_vol *volume_info)
{
	struct TCP_Server_Info *server = tcon->ses->server;
	unsigned int rsize;

	rsize = volume_info->rsize ? volume_info->rsize : CIFS_DEFAULT_IOSIZE;
	rsize = min_t(unsigned int, rsize, server->max_read);
	rsize = min_t(unsigned int, rsize, SMB2_MAX_BUFFER_SIZE);

	return rsize;
}

static int
smb2_is_path_accessible(const unsigned int xid, struct cifs_tcon *tcon,
			struct cifs_sb_info *cifs_sb, const char *full_path)
{
	int rc;
	__le16 *utf16_path;
	__u8 oplock = SMB2_OPLOCK_LEVEL_NONE;
	struct cifs_open_parms oparms;
	struct cifs_fid fid;

	utf16_path = cifs_convert_path_to_utf16(full_path, cifs_sb);
	if (!utf16_path)
		return -ENOMEM;

	oparms.tcon = tcon;
	oparms.desired_access = FILE_READ_ATTRIBUTES;
	oparms.disposition = FILE_OPEN;
	oparms.create_options = 0;
	oparms.fid = &fid;
	oparms.reconnect = false;

	rc = SMB2_open(xid, &oparms, utf16_path, &oplock, NULL);
	if (rc) {
		kfree(utf16_path);
		return rc;
	}

	rc = SMB2_close(xid, tcon, fid.persistent_fid, fid.volatile_fid);
	kfree(utf16_path);
	return rc;
}

static int
smb2_get_srv_inum(const unsigned int xid, struct cifs_tcon *tcon,
		  struct cifs_sb_info *cifs_sb, const char *full_path,
		  u64 *uniqueid, FILE_ALL_INFO *data)
{
	*uniqueid = le64_to_cpu(data->IndexNumber);
	return 0;
}

static int
smb2_query_file_info(const unsigned int xid, struct cifs_tcon *tcon,
		     struct cifs_fid *fid, FILE_ALL_INFO *data)
{
	int rc;
	struct smb2_file_all_info *smb2_data;

	smb2_data = kzalloc(sizeof(struct smb2_file_all_info) + PATH_MAX * 2,
			    GFP_KERNEL);
	if (smb2_data == NULL)
		return -ENOMEM;

	rc = SMB2_query_info(xid, tcon, fid->persistent_fid, fid->volatile_fid,
			     smb2_data);
	if (!rc)
		move_smb2_info_to_cifs(data, smb2_data);
	kfree(smb2_data);
	return rc;
}

static bool
smb2_can_echo(struct TCP_Server_Info *server)
{
	return server->echoes;
}

static void
smb2_clear_stats(struct cifs_tcon *tcon)
{
#ifdef CONFIG_CIFS_STATS
	int i;
	for (i = 0; i < NUMBER_OF_SMB2_COMMANDS; i++) {
		atomic_set(&tcon->stats.smb2_stats.smb2_com_sent[i], 0);
		atomic_set(&tcon->stats.smb2_stats.smb2_com_failed[i], 0);
	}
#endif
}

static void
smb2_print_stats(struct seq_file *m, struct cifs_tcon *tcon)
{
#ifdef CONFIG_CIFS_STATS
	atomic_t *sent = tcon->stats.smb2_stats.smb2_com_sent;
	atomic_t *failed = tcon->stats.smb2_stats.smb2_com_failed;
	seq_printf(m, "\nNegotiates: %d sent %d failed",
		   atomic_read(&sent[SMB2_NEGOTIATE_HE]),
		   atomic_read(&failed[SMB2_NEGOTIATE_HE]));
	seq_printf(m, "\nSessionSetups: %d sent %d failed",
		   atomic_read(&sent[SMB2_SESSION_SETUP_HE]),
		   atomic_read(&failed[SMB2_SESSION_SETUP_HE]));
#define SMB2LOGOFF		0x0002 /* trivial request/resp */
	seq_printf(m, "\nLogoffs: %d sent %d failed",
		   atomic_read(&sent[SMB2_LOGOFF_HE]),
		   atomic_read(&failed[SMB2_LOGOFF_HE]));
	seq_printf(m, "\nTreeConnects: %d sent %d failed",
		   atomic_read(&sent[SMB2_TREE_CONNECT_HE]),
		   atomic_read(&failed[SMB2_TREE_CONNECT_HE]));
	seq_printf(m, "\nTreeDisconnects: %d sent %d failed",
		   atomic_read(&sent[SMB2_TREE_DISCONNECT_HE]),
		   atomic_read(&failed[SMB2_TREE_DISCONNECT_HE]));
	seq_printf(m, "\nCreates: %d sent %d failed",
		   atomic_read(&sent[SMB2_CREATE_HE]),
		   atomic_read(&failed[SMB2_CREATE_HE]));
	seq_printf(m, "\nCloses: %d sent %d failed",
		   atomic_read(&sent[SMB2_CLOSE_HE]),
		   atomic_read(&failed[SMB2_CLOSE_HE]));
	seq_printf(m, "\nFlushes: %d sent %d failed",
		   atomic_read(&sent[SMB2_FLUSH_HE]),
		   atomic_read(&failed[SMB2_FLUSH_HE]));
	seq_printf(m, "\nReads: %d sent %d failed",
		   atomic_read(&sent[SMB2_READ_HE]),
		   atomic_read(&failed[SMB2_READ_HE]));
	seq_printf(m, "\nWrites: %d sent %d failed",
		   atomic_read(&sent[SMB2_WRITE_HE]),
		   atomic_read(&failed[SMB2_WRITE_HE]));
	seq_printf(m, "\nLocks: %d sent %d failed",
		   atomic_read(&sent[SMB2_LOCK_HE]),
		   atomic_read(&failed[SMB2_LOCK_HE]));
	seq_printf(m, "\nIOCTLs: %d sent %d failed",
		   atomic_read(&sent[SMB2_IOCTL_HE]),
		   atomic_read(&failed[SMB2_IOCTL_HE]));
	seq_printf(m, "\nCancels: %d sent %d failed",
		   atomic_read(&sent[SMB2_CANCEL_HE]),
		   atomic_read(&failed[SMB2_CANCEL_HE]));
	seq_printf(m, "\nEchos: %d sent %d failed",
		   atomic_read(&sent[SMB2_ECHO_HE]),
		   atomic_read(&failed[SMB2_ECHO_HE]));
	seq_printf(m, "\nQueryDirectories: %d sent %d failed",
		   atomic_read(&sent[SMB2_QUERY_DIRECTORY_HE]),
		   atomic_read(&failed[SMB2_QUERY_DIRECTORY_HE]));
	seq_printf(m, "\nChangeNotifies: %d sent %d failed",
		   atomic_read(&sent[SMB2_CHANGE_NOTIFY_HE]),
		   atomic_read(&failed[SMB2_CHANGE_NOTIFY_HE]));
	seq_printf(m, "\nQueryInfos: %d sent %d failed",
		   atomic_read(&sent[SMB2_QUERY_INFO_HE]),
		   atomic_read(&failed[SMB2_QUERY_INFO_HE]));
	seq_printf(m, "\nSetInfos: %d sent %d failed",
		   atomic_read(&sent[SMB2_SET_INFO_HE]),
		   atomic_read(&failed[SMB2_SET_INFO_HE]));
	seq_printf(m, "\nOplockBreaks: %d sent %d failed",
		   atomic_read(&sent[SMB2_OPLOCK_BREAK_HE]),
		   atomic_read(&failed[SMB2_OPLOCK_BREAK_HE]));
#endif
}

static void
smb2_set_fid(struct cifsFileInfo *cfile, struct cifs_fid *fid, __u32 oplock)
{
	struct cifsInodeInfo *cinode = CIFS_I(cfile->dentry->d_inode);
	cfile->fid.persistent_fid = fid->persistent_fid;
	cfile->fid.volatile_fid = fid->volatile_fid;
	smb2_set_oplock_level(cinode, oplock);
	cinode->can_cache_brlcks = cinode->clientCanCacheAll;
}

static void
smb2_close_file(const unsigned int xid, struct cifs_tcon *tcon,
		struct cifs_fid *fid)
{
	SMB2_close(xid, tcon, fid->persistent_fid, fid->volatile_fid);
}

static int
smb2_flush_file(const unsigned int xid, struct cifs_tcon *tcon,
		struct cifs_fid *fid)
{
	return SMB2_flush(xid, tcon, fid->persistent_fid, fid->volatile_fid);
}

static unsigned int
smb2_read_data_offset(char *buf)
{
	struct smb2_read_rsp *rsp = (struct smb2_read_rsp *)buf;
	return rsp->DataOffset;
}

static unsigned int
smb2_read_data_length(char *buf)
{
	struct smb2_read_rsp *rsp = (struct smb2_read_rsp *)buf;
	return le32_to_cpu(rsp->DataLength);
}


static int
smb2_sync_read(const unsigned int xid, struct cifsFileInfo *cfile,
	       struct cifs_io_parms *parms, unsigned int *bytes_read,
	       char **buf, int *buf_type)
{
	parms->persistent_fid = cfile->fid.persistent_fid;
	parms->volatile_fid = cfile->fid.volatile_fid;
	return SMB2_read(xid, parms, bytes_read, buf, buf_type);
}

static int
smb2_sync_write(const unsigned int xid, struct cifsFileInfo *cfile,
		struct cifs_io_parms *parms, unsigned int *written,
		struct kvec *iov, unsigned long nr_segs)
{

	parms->persistent_fid = cfile->fid.persistent_fid;
	parms->volatile_fid = cfile->fid.volatile_fid;
	return SMB2_write(xid, parms, written, iov, nr_segs);
}

static int
smb2_set_file_size(const unsigned int xid, struct cifs_tcon *tcon,
		   struct cifsFileInfo *cfile, __u64 size, bool set_alloc)
{
	__le64 eof = cpu_to_le64(size);
	return SMB2_set_eof(xid, tcon, cfile->fid.persistent_fid,
			    cfile->fid.volatile_fid, cfile->pid, &eof);
}

static int
smb2_query_dir_first(const unsigned int xid, struct cifs_tcon *tcon,
		     const char *path, struct cifs_sb_info *cifs_sb,
		     struct cifs_fid *fid, __u16 search_flags,
		     struct cifs_search_info *srch_inf)
{
	__le16 *utf16_path;
	int rc;
	__u8 oplock = SMB2_OPLOCK_LEVEL_NONE;
	struct cifs_open_parms oparms;

	utf16_path = cifs_convert_path_to_utf16(path, cifs_sb);
	if (!utf16_path)
		return -ENOMEM;

	oparms.tcon = tcon;
	oparms.desired_access = FILE_READ_ATTRIBUTES | FILE_READ_DATA;
	oparms.disposition = FILE_OPEN;
	oparms.create_options = 0;
	oparms.fid = fid;
	oparms.reconnect = false;

	rc = SMB2_open(xid, &oparms, utf16_path, &oplock, NULL);
	kfree(utf16_path);
	if (rc) {
		cifs_dbg(VFS, "open dir failed\n");
		return rc;
	}

	srch_inf->entries_in_buffer = 0;
	srch_inf->index_of_last_entry = 0;

	rc = SMB2_query_directory(xid, tcon, fid->persistent_fid,
				  fid->volatile_fid, 0, srch_inf);
	if (rc) {
		cifs_dbg(VFS, "query directory failed\n");
		SMB2_close(xid, tcon, fid->persistent_fid, fid->volatile_fid);
	}
	return rc;
}

static int
smb2_query_dir_next(const unsigned int xid, struct cifs_tcon *tcon,
		    struct cifs_fid *fid, __u16 search_flags,
		    struct cifs_search_info *srch_inf)
{
	return SMB2_query_directory(xid, tcon, fid->persistent_fid,
				    fid->volatile_fid, 0, srch_inf);
}

static int
smb2_close_dir(const unsigned int xid, struct cifs_tcon *tcon,
	       struct cifs_fid *fid)
{
	return SMB2_close(xid, tcon, fid->persistent_fid, fid->volatile_fid);
}

/*
* If we negotiate SMB2 protocol and get STATUS_PENDING - update
* the number of credits and return true. Otherwise - return false.
*/
static bool
smb2_is_status_pending(char *buf, struct TCP_Server_Info *server, int length)
{
	struct smb2_hdr *hdr = (struct smb2_hdr *)buf;

	if (hdr->Status != STATUS_PENDING)
		return false;

	if (!length) {
		spin_lock(&server->req_lock);
		server->credits += le16_to_cpu(hdr->CreditRequest);
		spin_unlock(&server->req_lock);
		wake_up(&server->request_q);
	}

	return true;
}

static int
smb2_oplock_response(struct cifs_tcon *tcon, struct cifs_fid *fid,
		     struct cifsInodeInfo *cinode)
{
	if (tcon->ses->server->capabilities & SMB2_GLOBAL_CAP_LEASING)
		return SMB2_lease_break(0, tcon, cinode->lease_key,
					smb2_get_lease_state(cinode));

	return SMB2_oplock_break(0, tcon, fid->persistent_fid,
				 fid->volatile_fid,
				 cinode->clientCanCacheRead ? 1 : 0);
}

static int
smb2_queryfs(const unsigned int xid, struct cifs_tcon *tcon,
	     struct kstatfs *buf)
{
	int rc;
	__le16 srch_path = 0;
	u8 oplock = SMB2_OPLOCK_LEVEL_NONE;
	struct cifs_open_parms oparms;
	struct cifs_fid fid;

	oparms.tcon = tcon;
	oparms.desired_access = FILE_READ_ATTRIBUTES;
	oparms.disposition = FILE_OPEN;
	oparms.create_options = 0;
	oparms.fid = &fid;
	oparms.reconnect = false;

	rc = SMB2_open(xid, &oparms, &srch_path, &oplock, NULL);
	if (rc)
		return rc;
	buf->f_type = SMB2_MAGIC_NUMBER;
	rc = SMB2_QFS_info(xid, tcon, fid.persistent_fid, fid.volatile_fid,
			   buf);
	SMB2_close(xid, tcon, fid.persistent_fid, fid.volatile_fid);
	return rc;
}

static bool
smb2_compare_fids(struct cifsFileInfo *ob1, struct cifsFileInfo *ob2)
{
	return ob1->fid.persistent_fid == ob2->fid.persistent_fid &&
	       ob1->fid.volatile_fid == ob2->fid.volatile_fid;
}

static int
smb2_mand_lock(const unsigned int xid, struct cifsFileInfo *cfile, __u64 offset,
	       __u64 length, __u32 type, int lock, int unlock, bool wait)
{
	if (unlock && !lock)
		type = SMB2_LOCKFLAG_UNLOCK;
	return SMB2_lock(xid, tlink_tcon(cfile->tlink),
			 cfile->fid.persistent_fid, cfile->fid.volatile_fid,
			 current->tgid, length, offset, type, wait);
}

static void
smb2_get_lease_key(struct inode *inode, struct cifs_fid *fid)
{
	memcpy(fid->lease_key, CIFS_I(inode)->lease_key, SMB2_LEASE_KEY_SIZE);
}

static void
smb2_set_lease_key(struct inode *inode, struct cifs_fid *fid)
{
	memcpy(CIFS_I(inode)->lease_key, fid->lease_key, SMB2_LEASE_KEY_SIZE);
}

static void
smb2_new_lease_key(struct cifs_fid *fid)
{
	get_random_bytes(fid->lease_key, SMB2_LEASE_KEY_SIZE);
}

static bool
smb2_dir_needs_close(struct cifsFileInfo *cfile)
{
	return !cfile->invalidHandle;
}

/* wait for mtu credits */
static int
smb2_wait_mtu_credits(struct TCP_Server_Info *server, unsigned int size,
		      unsigned int *num, unsigned int *credits)
{
	int rc = 0;
	unsigned int scredits;
	spin_lock(&server->req_lock);
	while (1) {
		if (server->credits <= 0) {
			spin_unlock(&server->req_lock);
			cifs_num_waiters_inc(server);
			rc = wait_event_killable(server->request_q,
					has_credits(server, &server->credits));
			cifs_num_waiters_dec(server);
			if (rc)
				return rc;
			spin_lock(&server->req_lock);
		} else {
			if (server->tcpStatus == CifsExiting) {
				spin_unlock(&server->req_lock);
				return -ENOENT;
			}
			scredits = server->credits;
			if (scredits <= 8) {
				*num = SMB2_MAX_BUFFER_SIZE;
				*credits = 0;
				break;
			}
			scredits -= 8;
			*num = min_t(unsigned int, size,
				     scredits * SMB2_MAX_BUFFER_SIZE);
			*credits = DIV_ROUND_UP(*num, SMB2_MAX_BUFFER_SIZE);
			server->credits -= *credits;
			server->in_flight++;
			break;
		}
	}
	spin_unlock(&server->req_lock);
	return rc;
}

static void
smb2_dump_share_caps(struct seq_file *m, struct cifs_tcon *tcon)
{
	seq_puts(m, "\n\tShare Capabilities:");
	if (tcon->capabilities & SMB2_SHARE_CAP_DFS)
		seq_puts(m, " DFS,");
	if (tcon->capabilities & SMB2_SHARE_CAP_CONTINUOUS_AVAILABILITY)
		seq_puts(m, " CONTINUOUS AVAILABILITY,");
	if (tcon->capabilities & SMB2_SHARE_CAP_SCALEOUT)
		seq_puts(m, " SCALEOUT,");
	if (tcon->capabilities & SMB2_SHARE_CAP_CLUSTER)
		seq_puts(m, " CLUSTER,");
	if (tcon->capabilities & SMB2_SHARE_CAP_ASYMMETRIC)
		seq_puts(m, " ASYMMETRIC,");
	if (tcon->capabilities == 0)
		seq_puts(m, " None");
	seq_printf(m, "\tShare Flags: 0x%x", tcon->share_flags);
}

static bool
smb2_is_session_expired(char *buf)
{
	struct smb2_hdr *hdr = (struct smb2_hdr *)buf;
	if (hdr->Status != STATUS_NETWORK_SESSION_EXPIRED &&
	    hdr->Status != STATUS_USER_SESSION_DELETED)
		return false;
	cifs_dbg(FYI, "Session expired or deleted\n");
	return true;
}

static int
smb2_handle_cancelled_mid(char *buffer, struct TCP_Server_Info *server)
{
	struct smb2_hdr *hdr = (struct smb2_hdr *)buffer;
	struct smb2_create_rsp *rsp = (struct smb2_create_rsp *)buffer;
	struct cifs_tcon *tcon;
	struct close_cancelled_open *cancelled;

	if (hdr->Command != SMB2_CREATE ||
	    hdr->Status != STATUS_SUCCESS)
		return 0;

	cancelled = kzalloc(sizeof(*cancelled), GFP_KERNEL);
	if (!cancelled)
		return -ENOMEM;

	tcon = smb2_find_smb_tcon(server, hdr->SessionId, hdr->TreeId);
	if (!tcon) {
		kfree(cancelled);
		return -ENOENT;
	}
	cancelled->fid.persistent_fid = rsp->PersistentFileId;
	cancelled->fid.volatile_fid = rsp->VolatileFileId;
	cancelled->tcon = tcon;
	INIT_WORK(&cancelled->work, smb2_cancelled_close_fid);
	queue_work(cifsiod_wq, &cancelled->work);
	return 0;
}

static int
smb2_set_compression(const unsigned int xid, struct cifs_tcon *tcon,
		     struct cifsFileInfo *cfile)
{
	return SMB2_set_compression(xid, tcon, cfile->fid.persistent_fid,
				    cfile->fid.volatile_fid,
				    COMPRESSION_FORMAT_DEFAULT);
}

static int
smb2_duplicate_extents(const unsigned int xid, struct cifs_tcon *tcon,
		       struct cifsFileInfo *src_file,
		       struct cifsFileInfo *target_file,
		       __u64 src_off, __u64 dest_off, __u64 len)
{
	struct duplicate_extents_to_file dup_ext_buf;
	char *retbuf = NULL;
	int rc;

	dup_ext_buf.PersistentFileHandle = src_file->fid.persistent_fid;
	dup_ext_buf.VolatileFileHandle = src_file->fid.volatile_fid;
	dup_ext_buf.SourceFileOffset = cpu_to_le64(src_off);
	dup_ext_buf.TargetFileOffset = cpu_to_le64(dest_off);
	dup_ext_buf.ByteCount = cpu_to_le64(len);

	rc = SMB2_ioctl(xid, tcon, target_file->fid.persistent_fid,
			target_file->fid.volatile_fid,
			FSCTL_DUPLICATE_EXTENTS_TO_FILE,
			true /* is_fsctl */, (char *)&dup_ext_buf,
			sizeof(struct duplicate_extents_to_file),
			&retbuf, NULL);
	kfree(retbuf);
	return rc;
}

static int
smb3_set_integrity(const unsigned int xid, struct cifs_tcon *tcon,
		   struct cifsFileInfo *src_file)
{
	struct fsctl_set_integrity_information_req integ_req;
	char *retbuf = NULL;
	int rc;

	integ_req.ChecksumAlgorithm = CHECKSUM_TYPE_UNCHANGED;
	integ_req.Reserved = 0;
	integ_req.Flags = 0;

	rc = SMB2_ioctl(xid, tcon, src_file->fid.persistent_fid,
			src_file->fid.volatile_fid,
			FSCTL_SET_INTEGRITY_INFORMATION,
			true /* is_fsctl */, (char *)&integ_req,
			sizeof(struct fsctl_set_integrity_information_req),
			&retbuf, NULL);
	kfree(retbuf);
	return rc;
}

static int
smb3_enum_snapshots(const unsigned int xid, struct cifs_tcon *tcon,
		    struct cifsFileInfo *src_file, void __user *data)
{
	char *retbuf = NULL;
	int rc;

	rc = SMB2_ioctl(xid, tcon, src_file->fid.persistent_fid,
			src_file->fid.volatile_fid,
			FSCTL_SRV_ENUMERATE_SNAPSHOTS,
			true /* is_fsctl */, NULL, 0, &retbuf, NULL);
	if (rc)
		return rc;

	if (retbuf) {
		struct smb_snapshot_array *snap_array =
			(struct smb_snapshot_array *)retbuf;

		if (copy_to_user(data, &snap_array->number_of_snapshots,
				 sizeof(snap_array->number_of_snapshots))) {
			kfree(retbuf);
			return -EFAULT;
		}
		kfree(retbuf);
	}

	return 0;
}

static void
smb3_qfs_tcon(const unsigned int xid, struct cifs_tcon *tcon)
{
	int rc;
	__le16 srch_path = 0;
	u8 oplock = SMB2_OPLOCK_LEVEL_NONE;
	struct cifs_open_parms oparms;
	struct cifs_fid fid;

	oparms.tcon = tcon;
	oparms.desired_access = FILE_READ_ATTRIBUTES;
	oparms.disposition = FILE_OPEN;
	oparms.create_options = 0;
	oparms.fid = &fid;
	oparms.reconnect = false;

	rc = SMB2_open(xid, &oparms, &srch_path, &oplock, NULL);
	if (rc)
		return;

	SMB2_QFS_attr(xid, tcon, fid.persistent_fid, fid.volatile_fid,
		      FS_ATTRIBUTE_INFORMATION);
	SMB2_QFS_attr(xid, tcon, fid.persistent_fid, fid.volatile_fid,
		      FS_DEVICE_INFORMATION);
	SMB2_QFS_attr(xid, tcon, fid.persistent_fid, fid.volatile_fid,
		      FS_FULL_SIZE_INFORMATION);

	SMB2_close(xid, tcon, fid.persistent_fid, fid.volatile_fid);
}

static void
smb2_qfs_tcon(const unsigned int xid, struct cifs_tcon *tcon)
{
	int rc;
	__le16 srch_path = 0;
	u8 oplock = SMB2_OPLOCK_LEVEL_NONE;
	struct cifs_open_parms oparms;
	struct cifs_fid fid;

	oparms.tcon = tcon;
	oparms.desired_access = FILE_READ_ATTRIBUTES;
	oparms.disposition = FILE_OPEN;
	oparms.create_options = 0;
	oparms.fid = &fid;
	oparms.reconnect = false;

	rc = SMB2_open(xid, &oparms, &srch_path, &oplock, NULL);
	if (rc)
		return;

	SMB2_QFS_attr(xid, tcon, fid.persistent_fid, fid.volatile_fid,
		      FS_ATTRIBUTE_INFORMATION);
	SMB2_QFS_attr(xid, tcon, fid.persistent_fid, fid.volatile_fid,
		      FS_DEVICE_INFORMATION);

	SMB2_close(xid, tcon, fid.persistent_fid, fid.volatile_fid);
}

static int
SMB2_request_res_key(const unsigned int xid, struct cifs_tcon *tcon,
		     u64 persistent_fid, u64 volatile_fid,
		     struct copychunk_ioctl *chunk)
{
	int rc;
	char *retbuf = NULL;
	struct resume_key_req *res_key;

	rc = SMB2_ioctl(xid, tcon, persistent_fid, volatile_fid,
			FSCTL_SRV_REQUEST_RESUME_KEY,
			true /* is_fsctl */, NULL, 0, &retbuf, NULL);
	if (rc) {
		cifs_dbg(FYI, "Failed to get resume key: %d\n", rc);
		return rc;
	}

	res_key = (struct resume_key_req *)retbuf;
	memcpy(chunk->SourceKey, res_key->ResumeKey, COPY_CHUNK_RES_KEY_SIZE);
	kfree(retbuf);
	return 0;
}

static int
smb2_copychunk_range(const unsigned int xid, struct cifsFileInfo *src_file,
		     struct cifsFileInfo *target_file, __u64 src_off,
		     __u64 dst_off, __u64 len)
{
	struct copychunk_ioctl chunk;
	struct copychunk_ioctl_rsp *chunk_rsp;
	char *retbuf = NULL;
	int rc;

	rc = SMB2_request_res_key(xid, tlink_tcon(src_file->tlink),
				  src_file->fid.persistent_fid,
				  src_file->fid.volatile_fid, &chunk);
	if (rc)
		return rc;

	chunk.ChunkCount = cpu_to_le32(1);
	chunk.Reserved = 0;
	chunk.SourceOffset = cpu_to_le64(src_off);
	chunk.TargetOffset = cpu_to_le64(dst_off);
	chunk.Length = cpu_to_le32(len);
	chunk.Reserved2 = 0;

	rc = SMB2_ioctl(xid, tlink_tcon(target_file->tlink),
			target_file->fid.persistent_fid,
			target_file->fid.volatile_fid,
			FSCTL_SRV_COPYCHUNK,
			true /* is_fsctl */, (char *)&chunk,
			sizeof(struct copychunk_ioctl),
			&retbuf, NULL);
	if (rc == 0 && retbuf) {
		chunk_rsp = (struct copychunk_ioctl_rsp *)retbuf;
		cifs_dbg(FYI, "Chunks written: %u, bytes written: %u\n",
			 le32_to_cpu(chunk_rsp->ChunksWritten),
			 le32_to_cpu(chunk_rsp->ChunkBytesWritten));
	}

	kfree(retbuf);
	return rc;
}

static __le32
map_oplock_to_lease(__u8 oplock)
{
	if (oplock == SMB2_OPLOCK_LEVEL_EXCLUSIVE)
		return SMB2_LEASE_WRITE_CACHING | SMB2_LEASE_READ_CACHING;
	else if (oplock == SMB2_OPLOCK_LEVEL_II)
		return SMB2_LEASE_READ_CACHING;
	else if (oplock == SMB2_OPLOCK_LEVEL_BATCH)
		return SMB2_LEASE_HANDLE_CACHING | SMB2_LEASE_READ_CACHING |
		       SMB2_LEASE_WRITE_CACHING;
	return 0;
}

static void
smb21_set_oplock_level(struct cifsInodeInfo *cinode, __u32 oplock,
		       __u32 epoch, bool *purge_cache)
{
	unsigned int lease_state;

	oplock &= 0xFF;
	if (oplock == SMB2_OPLOCK_LEVEL_NOCHANGE)
		return;

	if (oplock != SMB2_OPLOCK_LEVEL_LEASE) {
		smb2_set_oplock_level(cinode, oplock);
		return;
	}

	lease_state = cinode->lease_state;
	if (lease_state & SMB2_LEASE_WRITE_CACHING) {
		cinode->clientCanCacheAll = true;
		cinode->clientCanCacheRead = true;
	} else if (lease_state & SMB2_LEASE_READ_CACHING) {
		cinode->clientCanCacheAll = false;
		cinode->clientCanCacheRead = true;
	} else {
		cinode->clientCanCacheAll = false;
		cinode->clientCanCacheRead = false;
	}
}

static void
smb3_set_oplock_level(struct cifsInodeInfo *cinode, __u32 oplock,
		      __u32 epoch, bool *purge_cache)
{
	unsigned int lease_state;

	oplock &= 0xFF;
	if (oplock == SMB2_OPLOCK_LEVEL_NOCHANGE)
		return;

	if (oplock != SMB2_OPLOCK_LEVEL_LEASE) {
		smb2_set_oplock_level(cinode, oplock);
		return;
	}

	lease_state = cinode->lease_state;
	if (lease_state & SMB2_LEASE_WRITE_CACHING) {
		cinode->clientCanCacheAll = true;
		cinode->clientCanCacheRead = true;
		if (epoch > cinode->epoch)
			cinode->epoch = epoch;
		if (purge_cache && *purge_cache)
			cinode->invalid_mapping = true;
	} else if (lease_state & SMB2_LEASE_READ_CACHING) {
		cinode->clientCanCacheAll = false;
		cinode->clientCanCacheRead = true;
	} else {
		cinode->clientCanCacheAll = false;
		cinode->clientCanCacheRead = false;
	}
}

static void
smb2_downgrade_oplock(struct TCP_Server_Info *server,
		      struct cifsInodeInfo *cinode, bool cacheable)
{
	if (cacheable)
		cinode->clientCanCacheRead = true;
	else
		cinode->clientCanCacheRead = false;
	cinode->clientCanCacheAll = false;
}

static void
smb3_downgrade_oplock(struct TCP_Server_Info *server,
		      struct cifsInodeInfo *cinode, bool cacheable)
{
	if (cacheable)
		cinode->clientCanCacheRead = true;
	else
		cinode->clientCanCacheRead = false;
	cinode->clientCanCacheAll = false;
	cinode->epoch++;
}

static bool
smb21_is_read_op(__u32 oplock)
{
	if ((oplock & 0xFF) == SMB2_OPLOCK_LEVEL_LEASE)
		return (oplock & (SMB2_LEASE_READ_CACHING_HE |
				  SMB2_LEASE_WRITE_CACHING_HE)) ==
			SMB2_LEASE_READ_CACHING_HE;
	return false;
}

static bool
smb2_is_read_op(__u32 oplock)
{
	return (oplock & 0xFF) == SMB2_OPLOCK_LEVEL_II;
}

static unsigned int
smb2_wp_retry_size(struct inode *inode)
{
	return SMB2_MAX_BUFFER_SIZE;
}

static char *
smb2_create_lease_buf(__u8 *lease_key, __u8 oplock)
{
	struct create_lease *buf;

	buf = kzalloc(sizeof(struct create_lease), GFP_KERNEL);
	if (!buf)
		return NULL;

	buf->ccontext.NameOffset = cpu_to_le16(offsetof
					(struct create_lease, Name));
	buf->ccontext.NameLength = cpu_to_le16(8);
	buf->ccontext.DataOffset = cpu_to_le16(offsetof
					(struct create_lease, lcontext));
	buf->ccontext.DataLength = cpu_to_le16(sizeof(struct lease_context));
	memcpy(buf->Name, SMB2_CREATE_REQUEST_LEASE, 8);
	buf->lcontext.LeaseKeyLow = cpu_to_le64(*((u64 *)lease_key));
	buf->lcontext.LeaseKeyHigh = cpu_to_le64(*((u64 *)(lease_key + 8)));
	buf->lcontext.LeaseState = map_oplock_to_lease(oplock);
	buf->lcontext.LeaseFlags = 0;
	buf->lcontext.LeaseDuration = 0;

	return (char *)buf;
}

static char *
smb3_create_lease_buf(__u8 *lease_key, __u8 oplock)
{
	struct create_lease_v2 *buf;

	buf = kzalloc(sizeof(struct create_lease_v2), GFP_KERNEL);
	if (!buf)
		return NULL;

	buf->ccontext.NameOffset = cpu_to_le16(offsetof
					(struct create_lease_v2, Name));
	buf->ccontext.NameLength = cpu_to_le16(8);
	buf->ccontext.DataOffset = cpu_to_le16(offsetof
					(struct create_lease_v2, lcontext));
	buf->ccontext.DataLength = cpu_to_le16(sizeof(struct lease_context_v2));
	memcpy(buf->Name, SMB2_CREATE_REQUEST_LEASE, 8);
	buf->lcontext.LeaseKeyLow = cpu_to_le64(*((u64 *)lease_key));
	buf->lcontext.LeaseKeyHigh = cpu_to_le64(*((u64 *)(lease_key + 8)));
	buf->lcontext.LeaseState = map_oplock_to_lease(oplock);
	buf->lcontext.LeaseFlags = 0;
	buf->lcontext.LeaseDuration = 0;
	buf->lcontext.ParentLeaseKeyLow = 0;
	buf->lcontext.ParentLeaseKeyHigh = 0;
	buf->lcontext.Epoch = 0;
	buf->lcontext.Reserved = 0;

	return (char *)buf;
}

static __u32
smb2_parse_lease_buf(void *buf, unsigned int *epoch)
{
	struct create_lease *lc = (struct create_lease *)buf;

	*epoch = 0;
	return le32_to_cpu(lc->lcontext.LeaseState);
}

static __u32
smb3_parse_lease_buf(void *buf, unsigned int *epoch)
{
	struct create_lease_v2 *lc = (struct create_lease_v2 *)buf;

	*epoch = le16_to_cpu(lc->lcontext.Epoch);
	return le32_to_cpu(lc->lcontext.LeaseState);
}

static int
smb2_set_sparse(const unsigned int xid, struct cifs_tcon *tcon,
		struct cifsFileInfo *cfile)
{
	char *retbuf = NULL;
	int rc;

	rc = SMB2_ioctl(xid, tcon, cfile->fid.persistent_fid,
			cfile->fid.volatile_fid, FSCTL_SET_SPARSE,
			true /* is_fsctl */, NULL, 0, &retbuf, NULL);
	kfree(retbuf);
	return rc;
}

static long smb3_zero_range(struct file *file, struct cifs_tcon *tcon,
			    loff_t offset, loff_t len, bool keep_size);

static long
smb3_simple_falloc(struct file *file, struct cifs_tcon *tcon, loff_t off,
		   loff_t len, bool keep_size)
{
	struct cifsFileInfo *cfile = file->private_data;
	__u64 size;
	int rc;
	unsigned int xid = get_xid();

	if (keep_size && off + len < i_size_read(file->f_mapping->host)) {
		free_xid(xid);
		goto zero_range;
	}

	size = off + len;
	rc = inode_newsize_ok(file->f_mapping->host, size);
	if (rc) {
		free_xid(xid);
		return rc;
	}

	rc = SMB2_set_eof(xid, tcon, cfile->fid.persistent_fid,
			  cfile->fid.volatile_fid, cfile->pid,
			  &(__le64){cpu_to_le64(size)});
	if (rc) {
		free_xid(xid);
		return rc;
	}

	if (!keep_size)
		i_size_write(file->f_mapping->host, size);

	free_xid(xid);

zero_range:
	return smb3_zero_range(file, tcon, off, len, true);
}

static long
smb3_zero_range(struct file *file, struct cifs_tcon *tcon, loff_t offset,
		loff_t len, bool keep_size)
{
	struct cifsFileInfo *cfile = file->private_data;
	struct file_zero_data_information fsctl_buf;
	char *retbuf = NULL;
	int rc;
	unsigned int xid = get_xid();

	fsctl_buf.FileOffset = cpu_to_le64(offset);
	fsctl_buf.BeyondFinalZero = cpu_to_le64(offset + len);

	rc = SMB2_ioctl(xid, tcon, cfile->fid.persistent_fid,
			cfile->fid.volatile_fid, FSCTL_SET_ZERO_DATA,
			true /* is_fsctl */, (char *)&fsctl_buf,
			sizeof(struct file_zero_data_information),
			&retbuf, NULL);
	kfree(retbuf);

	free_xid(xid);
	return rc;
}

static long
smb3_punch_hole(struct file *file, struct cifs_tcon *tcon, loff_t offset,
		loff_t len)
{
	struct cifsFileInfo *cfile = file->private_data;
	struct file_zero_data_information fsctl_buf;
	struct inode *inode = file->f_mapping->host;
	char *retbuf = NULL;
	int rc;
	unsigned int xid = get_xid();

	fsctl_buf.FileOffset = cpu_to_le64(offset);
	fsctl_buf.BeyondFinalZero = cpu_to_le64(offset + len);

	rc = SMB2_ioctl(xid, tcon, cfile->fid.persistent_fid,
			cfile->fid.volatile_fid, FSCTL_SET_ZERO_DATA,
			true /* is_fsctl */, (char *)&fsctl_buf,
			sizeof(struct file_zero_data_information),
			&retbuf, NULL);
	kfree(retbuf);
	if (rc) {
		free_xid(xid);
		return rc;
	}

	truncate_pagecache_range(inode, offset, offset + len - 1);
	free_xid(xid);
	return 0;
}

static long
smb3_fallocate(struct file *file, struct cifs_tcon *tcon, int mode,
	       loff_t off, loff_t len)
{
	if (mode & FALLOC_FL_PUNCH_HOLE)
		return smb3_punch_hole(file, tcon, off, len);
	else if (mode & FALLOC_FL_ZERO_RANGE)
		return smb3_zero_range(file, tcon, off, len, false);
	else if (mode & FALLOC_FL_KEEP_SIZE)
		return smb3_simple_falloc(file, tcon, off, len, true);
	else
		return smb3_simple_falloc(file, tcon, off, len, false);
}

static int
smb2_get_dfs_refer(const unsigned int xid, struct cifs_ses *ses,
		   const char *search_name, struct dfs_info3_param **targets,
		   unsigned int *num_of_ret,
		   const struct nls_table *nls_codepage, int remap)
{
	return -EOPNOTSUPP;
}

static int
smb2_query_symlink(const unsigned int xid, struct cifs_tcon *tcon,
		   const char *full_path, char **target_path,
		   struct cifs_sb_info *cifs_sb)
{
	int rc;
	__le16 *utf16_path;
	__u8 oplock = SMB2_OPLOCK_LEVEL_NONE;
	struct cifs_open_parms oparms;
	struct cifs_fid fid;
	char *retbuf = NULL;
	struct smb2_symlink_err_rsp *symlink;

	utf16_path = cifs_convert_path_to_utf16(full_path, cifs_sb);
	if (!utf16_path)
		return -ENOMEM;

	oparms.tcon = tcon;
	oparms.desired_access = FILE_READ_ATTRIBUTES;
	oparms.disposition = FILE_OPEN;
	oparms.create_options = FILE_OPEN_REPARSE_POINT_LE;
	oparms.fid = &fid;
	oparms.reconnect = false;

	rc = SMB2_open(xid, &oparms, utf16_path, &oplock, NULL);
	if (rc) {
		kfree(utf16_path);
		return rc;
	}

	rc = SMB2_ioctl(xid, tcon, fid.persistent_fid, fid.volatile_fid,
			FSCTL_GET_REPARSE_POINT, true /* is_fsctl */,
			NULL, 0, &retbuf, NULL);
	if (rc) {
		SMB2_close(xid, tcon, fid.persistent_fid, fid.volatile_fid);
		kfree(utf16_path);
		return rc;
	}

	SMB2_close(xid, tcon, fid.persistent_fid, fid.volatile_fid);
	kfree(utf16_path);

	symlink = (struct smb2_symlink_err_rsp *)retbuf;
	if (le32_to_cpu(symlink->SymLinkErrorTag) != 0) {
		kfree(retbuf);
		return -EINVAL;
	}

	*target_path = kzalloc(symlink->SubstituteNameLength + 1, GFP_KERNEL);
	if (!*target_path) {
		kfree(retbuf);
		return -ENOMEM;
	}

	cifs_from_utf16(*target_path,
			(__le16 *)(symlink->PathBuffer +
				 le16_to_cpu(symlink->SubstituteNameOffset)),
			symlink->SubstituteNameLength,
			symlink->SubstituteNameLength,
			cifs_sb->local_nls,
			cifs_sb->mnt_cifs_flags & CIFS_MOUNT_MAP_SPECIAL_CHR);

	kfree(retbuf);
	return 0;
}

static int
smb3_validate_negotiate(const unsigned int xid, struct cifs_tcon *tcon)
{
	int rc;
	struct validate_negotiate_info_req *vneg_in;
	struct validate_negotiate_info_rsp *vneg_out;
	char *retbuf = NULL;
	struct TCP_Server_Info *server = tcon->ses->server;

	vneg_in = kzalloc(sizeof(struct validate_negotiate_info_req),
			  GFP_KERNEL);
	if (!vneg_in)
		return -ENOMEM;

	vneg_in->Capabilities = cpu_to_le32(server->capabilities);
	memcpy(vneg_in->Guid, server->client_guid, SMB2_CLIENT_GUID_SIZE);

	if (server->vals->protocol_id == SMB302_PROT_ID)
		vneg_in->SecurityMode = cpu_to_le16(SMB2_NEGOTIATE_SIGNING_ENABLED |
						    SMB2_NEGOTIATE_SIGNING_REQUIRED);

	vneg_in->DialectCount = cpu_to_le16(1);
	vneg_in->Dialects[0] = cpu_to_le16(server->vals->protocol_id);

	rc = SMB2_ioctl(xid, tcon, NO_FILE_ID, NO_FILE_ID,
			FSCTL_VALIDATE_NEGOTIATE_INFO, true /* is_fsctl */,
			(char *)vneg_in,
			sizeof(struct validate_negotiate_info_req),
			&retbuf, NULL);
	if (rc < 0) {
		cifs_dbg(FYI, "validate negotiate rc=%d\n", rc);
		goto out_free;
	}

	vneg_out = (struct validate_negotiate_info_rsp *)retbuf;
	if (memcmp(vneg_in->Guid, vneg_out->Guid, SMB2_CLIENT_GUID_SIZE) ||
	    vneg_in->Capabilities != vneg_out->Capabilities ||
	    vneg_in->SecurityMode != vneg_out->SecurityMode ||
	    vneg_in->Dialects[0] != vneg_out->Dialect)
		rc = -EIO;

	kfree(retbuf);
out_free:
	kfree(vneg_in);
	return rc;
}

static enum securityEnum
smb2_select_sectype(struct TCP_Server_Info *server, enum securityEnum requested)
{
	switch (requested) {
	case Kerberos:
	case RawNTLMSSP:
		return requested;
	case NTLMv2:
		return RawNTLMSSP;
	default:
		return Unspecified;
	}
}

static int
smb2_get_enc_key(struct TCP_Server_Info *server, __u64 ses_id, int enc, u8 *key)
{
	struct cifs_ses *ses;

	ses = smb2_find_smb_ses(server, ses_id);
	if (!ses) {
		cifs_dbg(FYI, "%s: Could not find session\n", __func__);
		return -ENOENT;
	}

	if (enc)
		memcpy(key, ses->smb3encryptionkey, SMB3_SIGN_KEY_SIZE);
	else
		memcpy(key, ses->smb3decryptionkey, SMB3_SIGN_KEY_SIZE);

	return 0;
}

static void
cifs_crypt_complete(struct crypto_async_request *req, int err)
{
	struct completion *done = req->data;

	if (err != -EINPROGRESS)
		complete(done);
}

static int
init_sg(struct kvec *iov, unsigned int nvec, struct scatterlist *sg)
{
	unsigned int i;
	int j;

	sg_init_table(sg, nvec);
	for (i = 0, j = 0; i < nvec; i++) {
		sg_set_buf(&sg[j], iov[i].iov_base, iov[i].iov_len);
		j++;
	}
	return j;
}

static int
crypt_message(struct TCP_Server_Info *server, struct smb_rqst *rqst, int enc)
{
	struct smb2_transform_hdr *tr_hdr =
		(struct smb2_transform_hdr *)rqst->rq_iov[0].iov_base;
	int rc = 0;
	struct scatterlist *sg, *sg_assoc;
	u8 sign[SMB2_SIGNATURE_SIZE] = {};
	u8 key[SMB3_SIGN_KEY_SIZE];
	struct aead_request *aead_req;
	u8 *iv;
	unsigned int iv_len;
	unsigned int rc4;
	struct crypto_aead *tfm;

	if (enc)
		tfm = server->secmech.ccmaesencrypt;
	else
		tfm = server->secmech.ccmaesdecrypt;

	if (!tfm) {
		rc = smb3_crypto_aead_allocate(server);
		if (rc)
			return rc;
		if (enc)
			tfm = server->secmech.ccmaesencrypt;
		else
			tfm = server->secmech.ccmaesdecrypt;
	}

	rc = smb2_get_enc_key(server, tr_hdr->SessionId, enc, key);
	if (rc)
		return rc;

	rc = crypto_aead_setkey(tfm, key, SMB3_SIGN_KEY_SIZE);
	if (rc) {
		cifs_dbg(VFS, "%s: Failed to set aead key\n", __func__);
		return rc;
	}

	rc = crypto_aead_setauthsize(tfm, SMB2_SIGNATURE_SIZE);
	if (rc) {
		cifs_dbg(VFS, "%s: Failed to set authsize\n", __func__);
		return rc;
	}

	aead_req = aead_request_alloc(tfm, GFP_KERNEL);
	if (!aead_req)
		return -ENOMEM;

	if (!(server->capabilities & SMB2_GLOBAL_CAP_ENCRYPTION))
		iv_len = SMB3_AES128CMM_NONCE;
	else
		iv_len = SMB3_AES128GCM_NONCE;

	iv = kzalloc(iv_len, GFP_KERNEL);
	if (!iv) {
		aead_request_free(aead_req);
		return -ENOMEM;
	}

	memcpy(iv, tr_hdr->Nonce, iv_len);

	sg_assoc = kmalloc(sizeof(struct scatterlist), GFP_KERNEL);
	if (!sg_assoc) {
		kfree(iv);
		aead_request_free(aead_req);
		return -ENOMEM;
	}
	sg_init_one(sg_assoc, rqst->rq_iov[0].iov_base,
		    rqst->rq_iov[0].iov_len);

	sg = kmalloc(sizeof(struct scatterlist) * (rqst->rq_nvec - 1), GFP_KERNEL);
	if (!sg) {
		kfree(sg_assoc);
		kfree(iv);
		aead_request_free(aead_req);
		return -ENOMEM;
	}
	init_sg(rqst->rq_iov + 1, rqst->rq_nvec - 1, sg);

	aead_request_set_assoc(aead_req, sg_assoc, rqst->rq_iov[0].iov_len);
	aead_request_set_crypt(aead_req, sg, sg, rqst->rq_iov[1].iov_len, iv);

	if (enc)
		rc = crypto_aead_encrypt(aead_req);
	else
		rc = crypto_aead_decrypt(aead_req);

	if (rc) {
		kfree(sg_assoc);
		kfree(sg);
		kfree(iv);
		aead_request_free(aead_req);
		return rc;
	}

	kfree(sg_assoc);
	kfree(sg);
	kfree(iv);
	aead_request_free(aead_req);
	return 0;
}

static void
fill_transform_hdr(struct smb2_transform_hdr *tr_hdr,
		   unsigned int orig_len, struct smb_rqst *old_rqst,
		   __le16 cipher_type)
{
	struct smb2_hdr *old_hdr =
		(struct smb2_hdr *)old_rqst->rq_iov[0].iov_base;

	memset(tr_hdr, 0, sizeof(struct smb2_transform_hdr));
	tr_hdr->ProtocolId = SMB2_TRANSFORM_PROTO_NUM;
	get_random_bytes(tr_hdr->Nonce, SMB3_AES128CMM_NONCE);
	tr_hdr->OriginalMessageSize = cpu_to_le32(orig_len);
	tr_hdr->Flags = cpu_to_le16(0x01);
	tr_hdr->SessionId = old_hdr->SessionId;
}

static int
smb3_init_transform_rq(struct TCP_Server_Info *server, struct smb_rqst *new_rqst,
		       struct smb_rqst *old_rqst)
{
	int i, rc;
	struct smb2_transform_hdr *tr_hdr;
	struct page *page;
	unsigned int orig_len;

	tr_hdr = kmalloc(sizeof(struct smb2_transform_hdr), GFP_KERNEL);
	if (!tr_hdr)
		return -ENOMEM;

	orig_len = 0;
	for (i = 0; i < old_rqst->rq_nvec; i++)
		orig_len += old_rqst->rq_iov[i].iov_len;
	for (i = 0; i < old_rqst->rq_npages; i++)
		orig_len += (old_rqst->rq_pagesz > 0) ? old_rqst->rq_pagesz :
			    PAGE_SIZE;

	fill_transform_hdr(tr_hdr, orig_len, old_rqst,
			   cpu_to_le16(SMB2_ENCRYPTION_AES128_CCM));

	new_rqst->rq_iov[0].iov_base = tr_hdr;
	new_rqst->rq_iov[0].iov_len = sizeof(struct smb2_transform_hdr);

	new_rqst->rq_nvec = old_rqst->rq_nvec + 1;
	for (i = 0; i < old_rqst->rq_nvec; i++)
		new_rqst->rq_iov[i + 1] = old_rqst->rq_iov[i];

	new_rqst->rq_npages = old_rqst->rq_npages;
	new_rqst->rq_pagesz = old_rqst->rq_pagesz;
	new_rqst->rq_tailsz = old_rqst->rq_tailsz;
	for (i = 0; i < old_rqst->rq_npages; i++)
		new_rqst->rq_pages[i] = old_rqst->rq_pages[i];

	rc = crypt_message(server, new_rqst, 1);
	if (rc) {
		kfree(tr_hdr);
		return rc;
	}

	return 0;
}

static void
smb3_free_transform_rq(struct smb_rqst *rqst)
{
	int i;

	for (i = 0; i < rqst->rq_npages; i++)
		put_page(rqst->rq_pages[i]);
	kfree(rqst->rq_iov[0].iov_base);
}

static int
smb3_is_transform_hdr(void *buf)
{
	struct smb2_transform_hdr *tr_hdr = (struct smb2_transform_hdr *)buf;

	return (tr_hdr->ProtocolId == SMB2_TRANSFORM_PROTO_NUM);
}

static int
receive_encrypted_standard(struct TCP_Server_Info *server,
			   struct mid_q_entry **mid)
{
	int rc;
	struct smb_rqst rqst;
	struct kvec iov;
	struct mid_q_entry *mid_entry;
	char *buf;
	unsigned int pdu_length;
	unsigned int buf_size;
	struct smb2_transform_hdr *tr_hdr;
	struct smb2_hdr *hdr;

	if (server->large_buf)
		pdu_length = get_rfc1002_length(server->bigbuf);
	else
		pdu_length = get_rfc1002_length(server->smallbuf);

	buf_size = sizeof(struct smb2_transform_hdr) + pdu_length;

	buf = kmalloc(buf_size, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	tr_hdr = (struct smb2_transform_hdr *)buf;
	if (server->large_buf)
		memcpy(buf, server->bigbuf, buf_size);
	else
		memcpy(buf, server->smallbuf, buf_size);

	iov.iov_base = buf + sizeof(struct smb2_transform_hdr);
	iov.iov_len = pdu_length;

	memset(&rqst, 0, sizeof(struct smb_rqst));
	rqst.rq_iov = &iov;
	rqst.rq_nvec = 1;

	rc = crypt_message(server, &rqst, 0);
	if (rc) {
		kfree(buf);
		return rc;
	}

	memmove(buf, iov.iov_base, iov.iov_len);

	hdr = (struct smb2_hdr *)buf;
	mid_entry = server->ops->find_mid(server, buf);
	if (!mid_entry) {
		kfree(buf);
		return -ENOENT;
	}

	if (mid_entry->resp_buf) {
		memcpy(mid_entry->resp_buf, buf, iov.iov_len);
		kfree(buf);
	} else {
		mid_entry->resp_buf = buf;
	}

	*mid = mid_entry;
	return 0;
}

static int
receive_encrypted_read(struct TCP_Server_Info *server,
		       struct mid_q_entry **mid)
{
	int rc;
	struct smb_rqst rqst;
	struct kvec iov;
	struct mid_q_entry *mid_entry;
	char *buf;
	unsigned int pdu_length;
	unsigned int buf_size;
	struct smb2_transform_hdr *tr_hdr;
	struct smb2_hdr *hdr;

	if (server->large_buf)
		pdu_length = get_rfc1002_length(server->bigbuf);
	else
		pdu_length = get_rfc1002_length(server->smallbuf);

	buf_size = sizeof(struct smb2_transform_hdr) + pdu_length;

	buf = kmalloc(buf_size, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	tr_hdr = (struct smb2_transform_hdr *)buf;
	if (server->large_buf)
		memcpy(buf, server->bigbuf, buf_size);
	else
		memcpy(buf, server->smallbuf, buf_size);

	iov.iov_base = buf + sizeof(struct smb2_transform_hdr);
	iov.iov_len = pdu_length;

	memset(&rqst, 0, sizeof(struct smb_rqst));
	rqst.rq_iov = &iov;
	rqst.rq_nvec = 1;

	rc = crypt_message(server, &rqst, 0);
	if (rc) {
		kfree(buf);
		return rc;
	}

	memmove(buf, iov.iov_base, iov.iov_len);

	hdr = (struct smb2_hdr *)buf;
	mid_entry = server->ops->find_mid(server, buf);
	if (!mid_entry) {
		kfree(buf);
		return -ENOENT;
	}

	if (mid_entry->resp_buf) {
		memcpy(mid_entry->resp_buf, buf, iov.iov_len);
		kfree(buf);
	} else {
		mid_entry->resp_buf = buf;
	}

	*mid = mid_entry;
	return 0;
}

static int
smb3_receive_transform(struct TCP_Server_Info *server,
		       struct mid_q_entry **mid)
{
	int rc;

	if (server->ops->read_data_offset)
		rc = receive_encrypted_read(server, mid);
	else
		rc = receive_encrypted_standard(server, mid);

	return rc;
}

struct smb_version_operations smb21_operations = {
	.compare_fids = smb2_compare_fids,
	.setup_request = smb2_setup_request,
	.setup_async_request = smb2_setup_async_request,
	.check_receive = smb2_check_receive,
	.add_credits = smb2_add_credits,
	.set_credits = smb2_set_credits,
	.get_credits_field = smb2_get_credits_field,
	.get_credits = smb2_get_credits,
	.get_next_mid = smb2_get_next_mid,
	.read_data_offset = smb2_read_data_offset,
	.read_data_length = smb2_read_data_length,
	.map_error = map_smb2_to_linux_error,
	.find_mid = smb2_find_mid,
	.check_message = smb2_check_message,
	.dump_detail = smb2_dump_detail,
	.clear_stats = smb2_clear_stats,
	.print_stats = smb2_print_stats,
	.is_oplock_break = smb2_is_valid_oplock_break,
	.need_neg = smb2_need_neg,
	.negotiate = smb2_negotiate,
	.negotiate_wsize = smb2_negotiate_wsize,
	.negotiate_rsize = smb2_negotiate_rsize,
	.sess_setup = SMB2_sess_setup,
	.logoff = SMB2_logoff,
	.tree_connect = SMB2_tcon,
	.tree_disconnect = SMB2_tdis,
	.get_dfs_refer = smb2_get_dfs_refer,
	.qfs_tcon = smb2_qfs_tcon,
	.is_path_accessible = smb2_is_path_accessible,
	.can_echo = smb2_can_echo,
	.echo = SMB2_echo,
	.query_path_info = smb2_query_path_info,
	.get_srv_inum = smb2_get_srv_inum,
	.query_file_info = smb2_query_file_info,
	.set_path_size = smb2_set_path_size,
	.set_file_size = smb2_set_file_size,
	.set_file_info = smb2_set_file_info,
	.mkdir = smb2_mkdir,
	.mkdir_setinfo = smb2_mkdir_setinfo,
	.rmdir = smb2_rmdir,
	.unlink = smb2_unlink,
	.rename = smb2_rename_path,
	.create_hardlink = smb2_create_hardlink,
	.open = smb2_open_file,
	.set_fid = smb2_set_fid,
	.close = smb2_close_file,
	.flush = smb2_flush_file,
	.async_readv = smb2_async_readv,
	.async_writev = smb2_async_writev,
	.sync_read = smb2_sync_read,
	.sync_write = smb2_sync_write,
	.query_dir_first = smb2_query_dir_first,
	.query_dir_next = smb2_query_dir_next,
	.close_dir = smb2_close_dir,
	.calc_smb_size = smb2_calc_size,
	.is_status_pending = smb2_is_status_pending,
	.oplock_response = smb2_oplock_response,
	.queryfs = smb2_queryfs,
	.mand_lock = smb2_mand_lock,
	.mand_unlock_range = smb2_unlock_range,
	.push_mand_locks = smb2_push_mandatory_locks,
	.get_lease_key = smb2_get_lease_key,
	.set_lease_key = smb2_set_lease_key,
	.new_lease_key = smb2_new_lease_key,
	.calc_signature = smb2_calc_signature,
	.dir_needs_close = smb2_dir_needs_close,
	.wait_mtu_credits = smb2_wait_mtu_credits,
	.dump_share_caps = smb2_dump_share_caps,
	.is_session_expired = smb2_is_session_expired,
	.handle_cancelled_mid = smb2_handle_cancelled_mid,
	.set_oplock_level = smb21_set_oplock_level,
	.create_lease_buf = smb2_create_lease_buf,
	.parse_lease_buf = smb2_parse_lease_buf,
	.copychunk_range = smb2_copychunk_range,
	.wp_retry_size = smb2_wp_retry_size,
	.select_sectype = smb2_select_sectype,
};

struct smb_version_operations smb30_operations = {
	.compare_fids = smb2_compare_fids,
	.setup_request = smb2_setup_request,
	.setup_async_request = smb2_setup_async_request,
	.check_receive = smb2_check_receive,
	.add_credits = smb2_add_credits,
	.set_credits = smb2_set_credits,
	.get_credits_field = smb2_get_credits_field,
	.get_credits = smb2_get_credits,
	.get_next_mid = smb2_get_next_mid,
	.read_data_offset = smb2_read_data_offset,
	.read_data_length = smb2_read_data_length,
	.map_error = map_smb2_to_linux_error,
	.find_mid = smb2_find_mid,
	.check_message = smb2_check_message,
	.dump_detail = smb2_dump_detail,
	.clear_stats = smb2_clear_stats,
	.print_stats = smb2_print_stats,
	.is_oplock_break = smb2_is_valid_oplock_break,
	.need_neg = smb2_need_neg,
	.negotiate = smb2_negotiate,
	.negotiate_wsize = smb2_negotiate_wsize,
	.negotiate_rsize = smb2_negotiate_rsize,
	.sess_setup = SMB2_sess_setup,
	.logoff = SMB2_logoff,
	.tree_connect = SMB2_tcon,
	.tree_disconnect = SMB2_tdis,
	.get_dfs_refer = smb2_get_dfs_refer,
	.qfs_tcon = smb3_qfs_tcon,
	.is_path_accessible = smb2_is_path_accessible,
	.can_echo = smb2_can_echo,
	.echo = SMB2_echo,
	.query_path_info = smb2_query_path_info,
	.get_srv_inum = smb2_get_srv_inum,
	.query_file_info = smb2_query_file_info,
	.set_path_size = smb2_set_path_size,
	.set_file_size = smb2_set_file_size,
	.set_file_info = smb2_set_file_info,
	.mkdir = smb2_mkdir,
	.mkdir_setinfo = smb2_mkdir_setinfo,
	.rmdir = smb2_rmdir,
	.unlink = smb2_unlink,
	.rename = smb2_rename_path,
	.create_hardlink = smb2_create_hardlink,
	.open = smb2_open_file,
	.set_fid = smb2_set_fid,
	.close = smb2_close_file,
	.flush = smb2_flush_file,
	.async_readv = smb2_async_readv,
	.async_writev = smb2_async_writev,
	.sync_read = smb2_sync_read,
	.sync_write = smb2_sync_write,
	.query_dir_first = smb2_query_dir_first,
	.query_dir_next = smb2_query_dir_next,
	.close_dir = smb2_close_dir,
	.calc_smb_size = smb2_calc_size,
	.is_status_pending = smb2_is_status_pending,
	.oplock_response = smb2_oplock_response,
	.queryfs = smb2_queryfs,
	.mand_lock = smb2_mand_lock,
	.mand_unlock_range = smb2_unlock_range,
	.push_mand_locks = smb2_push_mandatory_locks,
	.get_lease_key = smb2_get_lease_key,
	.set_lease_key = smb2_set_lease_key,
	.new_lease_key = smb2_new_lease_key,
	.generate_signingkey = generate_smb30signingkey,
	.calc_signature = smb3_calc_signature,
	.set_integrity = smb3_set_integrity,
	.enum_snapshots = smb3_enum_snapshots,
	.wp_retry_size = smb2_wp_retry_size,
	.wait_mtu_credits = smb2_wait_mtu_credits,
	.dir_needs_close = smb2_dir_needs_close,
	.fallocate = smb3_fallocate,
	.init_transform_rq = smb3_init_transform_rq,
	.free_transform_rq = smb3_free_transform_rq,
	.is_transform_hdr = smb3_is_transform_hdr,
	.receive_transform = smb3_receive_transform,
	.select_sectype = smb2_select_sectype,
	.dump_share_caps = smb2_dump_share_caps,
	.is_session_expired = smb2_is_session_expired,
	.handle_cancelled_mid = smb2_handle_cancelled_mid,
	.set_oplock_level = smb3_set_oplock_level,
	.create_lease_buf = smb3_create_lease_buf,
	.parse_lease_buf = smb3_parse_lease_buf,
	.copychunk_range = smb2_copychunk_range,
	.duplicate_extents = smb2_duplicate_extents,
	.validate_negotiate = smb3_validate_negotiate,
};

#ifdef CONFIG_CIFS_SMB311
struct smb_version_operations smb311_operations = {
	.compare_fids = smb2_compare_fids,
	.setup_request = smb2_setup_request,
	.setup_async_request = smb2_setup_async_request,
	.check_receive = smb2_check_receive,
	.add_credits = smb2_add_credits,
	.set_credits = smb2_set_credits,
	.get_credits_field = smb2_get_credits_field,
	.get_credits = smb2_get_credits,
	.get_next_mid = smb2_get_next_mid,
	.read_data_offset = smb2_read_data_offset,
	.read_data_length = smb2_read_data_length,
	.map_error = map_smb2_to_linux_error,
	.find_mid = smb2_find_mid,
	.check_message = smb2_check_message,
	.dump_detail = smb2_dump_detail,
	.clear_stats = smb2_clear_stats,
	.print_stats = smb2_print_stats,
	.is_oplock_break = smb2_is_valid_oplock_break,
	.need_neg = smb2_need_neg,
	.negotiate = smb2_negotiate,
	.negotiate_wsize = smb2_negotiate_wsize,
	.negotiate_rsize = smb2_negotiate_rsize,
	.sess_setup = SMB2_sess_setup,
	.logoff = SMB2_logoff,
	.tree_connect = SMB2_tcon,
	.tree_disconnect = SMB2_tdis,
	.get_dfs_refer = smb2_get_dfs_refer,
	.qfs_tcon = smb3_qfs_tcon,
	.is_path_accessible = smb2_is_path_accessible,
	.can_echo = smb2_can_echo,
	.echo = SMB2_echo,
	.query_path_info = smb2_query_path_info,
	.get_srv_inum = smb2_get_srv_inum,
	.query_file_info = smb2_query_file_info,
	.set_path_size = smb2_set_path_size,
	.set_file_size = smb2_set_file_size,
	.set_file_info = smb2_set_file_info,
	.mkdir = smb2_mkdir,
	.mkdir_setinfo = smb2_mkdir_setinfo,
	.rmdir = smb2_rmdir,
	.unlink = smb2_unlink,
	.rename = smb2_rename_path,
	.create_hardlink = smb2_create_hardlink,
	.open = smb2_open_file,
	.set_fid = smb2_set_fid,
	.close = smb2_close_file,
	.flush = smb2_flush_file,
	.async_readv = smb2_async_readv,
	.async_writev = smb2_async_writev,
	.sync_read = smb2_sync_read,
	.sync_write = smb2_sync_write,
	.query_dir_first = smb2_query_dir_first,
	.query_dir_next = smb2_query_dir_next,
	.close_dir = smb2_close_dir,
	.calc_smb_size = smb2_calc_size,
	.is_status_pending = smb2_is_status_pending,
	.oplock_response = smb2_oplock_response,
	.queryfs = smb2_queryfs,
	.mand_lock = smb2_mand_lock,
	.mand_unlock_range = smb2_unlock_range,
	.push_mand_locks = smb2_push_mandatory_locks,
	.get_lease_key = smb2_get_lease_key,
	.set_lease_key = smb2_set_lease_key,
	.new_lease_key = smb2_new_lease_key,
	.generate_signingkey = generate_smb311signingkey,
	.calc_signature = smb3_calc_signature,
	.set_integrity = smb3_set_integrity,
	.enum_snapshots = smb3_enum_snapshots,
	.wp_retry_size = smb2_wp_retry_size,
	.wait_mtu_credits = smb2_wait_mtu_credits,
	.dir_needs_close = smb2_dir_needs_close,
	.fallocate = smb3_fallocate,
	.init_transform_rq = smb3_init_transform_rq,
	.free_transform_rq = smb3_free_transform_rq,
	.is_transform_hdr = smb3_is_transform_hdr,
	.receive_transform = smb3_receive_transform,
	.select_sectype = smb2_select_sectype,
	.dump_share_caps = smb2_dump_share_caps,
	.is_session_expired = smb2_is_session_expired,
	.handle_cancelled_mid = smb2_handle_cancelled_mid,
	.set_oplock_level = smb3_set_oplock_level,
	.create_lease_buf = smb3_create_lease_buf,
	.parse_lease_buf = smb3_parse_lease_buf,
	.copychunk_range = smb2_copychunk_range,
	.duplicate_extents = smb2_duplicate_extents,
};
#endif

struct smb_version_values smb20_values = {
	.version_string = SMB20_VERSION_STRING,
	.protocol_id = SMB20_PROT_ID,
	.req_capabilities = 0, /* MBZ */
	.large_lock_type = 0,
	.exclusive_lock_type = SMB2_LOCKFLAG_EXCLUSIVE_LOCK,
	.shared_lock_type = SMB2_LOCKFLAG_SHARED_LOCK,
	.unlock_lock_type = SMB2_LOCKFLAG_UNLOCK,
	.header_size = sizeof(struct smb2_hdr),
	.max_header_size = MAX_SMB2_HDR_SIZE,
	.read_rsp_size = sizeof(struct smb2_read_rsp) - 1,
	.lock_cmd = SMB2_LOCK,
	.cap_unix = 0,
	.cap_nt_find = SMB2_NT_FIND,
	.cap_large_files = SMB2_LARGE_FILES,
	.oplock_read = SMB2_OPLOCK_LEVEL_II,
};

struct smb_version_values smb21_values = {
	.version_string = SMB21_VERSION_STRING,
	.protocol_id = SMB21_PROT_ID,
	.req_capabilities = 0, /* MBZ on negotiate req until SMB3 dialect */
	.large_lock_type = 0,
	.exclusive_lock_type = SMB2_LOCKFLAG_EXCLUSIVE_LOCK,
	.shared_lock_type = SMB2_LOCKFLAG_SHARED_LOCK,
	.unlock_lock_type = SMB2_LOCKFLAG_UNLOCK,
	.header_size = sizeof(struct smb2_hdr),
	.max_header_size = MAX_SMB2_HDR_SIZE,
	.read_rsp_size = sizeof(struct smb2_read_rsp) - 1,
	.lock_cmd = SMB2_LOCK,
	.cap_unix = 0,
	.cap_nt_find = SMB2_NT_FIND,
	.cap_large_files = SMB2_LARGE_FILES,
	.oplock_read = SMB2_OPLOCK_LEVEL_II,
};

struct smb_version_values smb30_values = {
	.version_string = SMB30_VERSION_STRING,
	.protocol_id = SMB30_PROT_ID,
	.req_capabilities = SMB2_GLOBAL_CAP_DFS | SMB2_GLOBAL_CAP_LEASING | SMB2_GLOBAL_CAP_LARGE_MTU,
	.large_lock_type = 0,
	.exclusive_lock_type = SMB2_LOCKFLAG_EXCLUSIVE_LOCK,
	.shared_lock_type = SMB2_LOCKFLAG_SHARED_LOCK,
	.unlock_lock_type = SMB2_LOCKFLAG_UNLOCK,
	.header_size = sizeof(struct smb2_hdr),
	.max_header_size = MAX_SMB2_HDR_SIZE,
	.read_rsp_size = sizeof(struct smb2_read_rsp) - 1,
	.lock_cmd = SMB2_LOCK,
	.cap_unix = 0,
	.cap_nt_find = SMB2_NT_FIND,
	.cap_large_files = SMB2_LARGE_FILES,
	.oplock_read = SMB2_OPLOCK_LEVEL_II,
};

#ifdef CONFIG_CIFS_SMB311
struct smb_version_values smb311_values = {
	.version_string = SMB311_VERSION_STRING,
	.protocol_id = SMB311_PROT_ID,
	.req_capabilities = SMB2_GLOBAL_CAP_DFS | SMB2_GLOBAL_CAP_LEASING | SMB2_GLOBAL_CAP_LARGE_MTU,
	.large_lock_type = 0,
	.exclusive_lock_type = SMB2_LOCKFLAG_EXCLUSIVE_LOCK,
	.shared_lock_type = SMB2_LOCKFLAG_SHARED_LOCK,
	.unlock_lock_type = SMB2_LOCKFLAG_UNLOCK,
	.header_size = sizeof(struct smb2_hdr),
	.max_header_size = MAX_SMB2_HDR_SIZE,
	.read_rsp_size = sizeof(struct smb2_read_rsp) - 1,
	.lock_cmd = SMB2_LOCK,
	.cap_unix = 0,
	.cap_nt_find = SMB2_NT_FIND,
	.cap_large_files = SMB2_LARGE_FILES,
	.oplock_read = SMB2_OPLOCK_LEVEL_II,
};
#endif
