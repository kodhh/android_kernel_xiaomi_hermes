// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2021 Samsung Electronics Co., Ltd.
 *   Author(s): Namjae Jeon <linkinjeon@kernel.org>
 */

#include <linux/fs.h>

#include "glob.h"
#include "ndr.h"

#define PAYLOAD_HEAD(d) ((d)->data + (d)->offset)

#define KSMBD_ALIGN_MASK(x, mask) (((x) + (mask)) & ~(mask))

#define KSMBD_ALIGN(x, a)							\
	({									\
		typeof(x) ret = (x);						\
		if (((x) & ((typeof(x))(a) - 1)) != 0)				\
			ret = KSMBD_ALIGN_MASK(x, (typeof(x))(a) - 1);		\
		ret;								\
	})

static void align_offset(struct ndr *ndr, int n)
{
	ndr->offset = KSMBD_ALIGN(ndr->offset, n);
}

static int try_to_realloc_ndr_blob(struct ndr *n, size_t sz)
{
	char *data;

	data = krealloc(n->data, n->offset + sz + 1024, GFP_KERNEL);
	if (!data)
		return -ENOMEM;

	n->data = data;
	n->length += 1024;
	memset(n->data + n->offset, 0, 1024);
	return 0;
}

static void ndr_write_int16(struct ndr *n, __u16 value)
{
	if (n->length <= n->offset + sizeof(value))
		try_to_realloc_ndr_blob(n, sizeof(value));

	*(__le16 *)PAYLOAD_HEAD(n) = cpu_to_le16(value);
	n->offset += sizeof(value);
}

static void ndr_write_int32(struct ndr *n, __u32 value)
{
	if (n->length <= n->offset + sizeof(value))
		try_to_realloc_ndr_blob(n, sizeof(value));

	*(__le32 *)PAYLOAD_HEAD(n) = cpu_to_le32(value);
	n->offset += sizeof(value);
}

static void ndr_write_int64(struct ndr *n, __u64 value)
{
	if (n->length <= n->offset + sizeof(value))
		try_to_realloc_ndr_blob(n, sizeof(value));

	*(__le64 *)PAYLOAD_HEAD(n) = cpu_to_le64(value);
	n->offset += sizeof(value);
}

static int ndr_write_bytes(struct ndr *n, void *value, size_t sz)
{
	if (n->length <= n->offset + sz)
		try_to_realloc_ndr_blob(n, sz);

	memcpy(PAYLOAD_HEAD(n), value, sz);
	n->offset += sz;
	return 0;
}

static int ndr_write_string(struct ndr *n, void *value, size_t sz)
{
	if (n->length <= n->offset + sz)
		try_to_realloc_ndr_blob(n, sz);

	strncpy(PAYLOAD_HEAD(n), value, sz);
	sz++;
	n->offset += sz;
	align_offset(n, 2);
	return 0;
}

static int ndr_read_string(struct ndr *n, void *value, size_t sz)
{
	int len;

	if (n->offset >= n->length)
		return -EINVAL;

	len = strnlen(PAYLOAD_HEAD(n), min_t(size_t, sz, n->length - n->offset));

	memcpy(value, PAYLOAD_HEAD(n), len);
	len++;
	n->offset += len;
	align_offset(n, 2);
	return 0;
}

static int ndr_read_bytes(struct ndr *n, void *value, size_t sz)
{
	if (n->offset + sz > n->length)
		return -EINVAL;

	memcpy(value, PAYLOAD_HEAD(n), sz);
	n->offset += sz;
	return 0;
}

static int ndr_read_int16(struct ndr *n, __u16 *result)
{
	if (n->offset + sizeof(__u16) > n->length)
		return -EINVAL;

	*result = le16_to_cpu(*(__le16 *)PAYLOAD_HEAD(n));
	n->offset += sizeof(__u16);
	return 0;
}

static int ndr_read_int32(struct ndr *n, __u32 *result)
{
	if (n->offset + sizeof(__u32) > n->length)
		return -EINVAL;

	*result = le32_to_cpu(*(__le32 *)PAYLOAD_HEAD(n));
	n->offset += sizeof(__u32);
	return 0;
}

static int ndr_read_int64(struct ndr *n, __u64 *result)
{
	if (n->offset + sizeof(__u64) > n->length)
		return -EINVAL;

	*result = le64_to_cpu(*(__le64 *)PAYLOAD_HEAD(n));
	n->offset += sizeof(__u64);
	return 0;
}

int ndr_encode_dos_attr(struct ndr *n, struct xattr_dos_attrib *da)
{
	char hex_attr[12] = {0};

	n->offset = 0;
	n->length = 1024;
	n->data = kzalloc(n->length, GFP_KERNEL);
	if (!n->data)
		return -ENOMEM;

	if (da->version == 3) {
		snprintf(hex_attr, 10, "0x%x", da->attr);
		ndr_write_string(n, hex_attr, strlen(hex_attr));
	} else {
		ndr_write_string(n, "", strlen(""));
	}
	ndr_write_int16(n, da->version);
	ndr_write_int32(n, da->version);

	ndr_write_int32(n, da->flags);
	ndr_write_int32(n, da->attr);
	if (da->version == 3) {
		ndr_write_int32(n, da->ea_size);
		ndr_write_int64(n, da->size);
		ndr_write_int64(n, da->alloc_size);
	} else {
		ndr_write_int64(n, da->itime);
	}
	ndr_write_int64(n, da->create_time);
	if (da->version == 3)
		ndr_write_int64(n, da->change_time);
	return 0;
}

int ndr_decode_dos_attr(struct ndr *n, struct xattr_dos_attrib *da)
{
	char hex_attr[12] = {0};
	int ret;
	__u16 version;
	__u32 tmp32;
	__u64 tmp64;

	n->offset = 0;
	ret = ndr_read_string(n, hex_attr, n->length - n->offset);
	if (ret)
		return ret;

	ret = ndr_read_int16(n, &version);
	if (ret)
		return ret;
	da->version = version;

	if (da->version != 3 && da->version != 4) {
		ksmbd_err("v%d version is not supported\n", da->version);
		return -EINVAL;
	}

	ret = ndr_read_int32(n, &tmp32);
	if (ret)
		return ret;
	if (da->version != tmp32) {
		ksmbd_err("ndr version mismatched(version: %d, version2: %d)\n",
				da->version, tmp32);
		return -EINVAL;
	}

	ret = ndr_read_int32(n, &tmp32);
	if (ret)
		return ret;
	ret = ndr_read_int32(n, &tmp32);
	if (ret)
		return ret;
	da->attr = tmp32;

	if (da->version == 4) {
		ret = ndr_read_int64(n, &da->itime);
		if (ret)
			return ret;
		ret = ndr_read_int64(n, &da->create_time);
		if (ret)
			return ret;
	} else {
		ret = ndr_read_int32(n, &tmp32);
		if (ret)
			return ret;
		ret = ndr_read_int64(n, &tmp64);
		if (ret)
			return ret;
		ret = ndr_read_int64(n, &tmp64);
		if (ret)
			return ret;
		ret = ndr_read_int64(n, &da->create_time);
		if (ret)
			return ret;
		ret = ndr_read_int64(n, &tmp64);
		if (ret)
			return ret;
	}

	return 0;
}

static int ndr_encode_posix_acl_entry(struct ndr *n, struct xattr_smb_acl *acl)
{
	int i;

	ndr_write_int32(n, acl->count);
	align_offset(n, 8);
	ndr_write_int32(n, acl->count);
	ndr_write_int32(n, 0);

	for (i = 0; i < acl->count; i++) {
		align_offset(n, 8);
		ndr_write_int16(n, acl->entries[i].type);
		ndr_write_int16(n, acl->entries[i].type);

		if (acl->entries[i].type == SMB_ACL_USER) {
			align_offset(n, 8);
			ndr_write_int64(n, acl->entries[i].uid);
		} else if (acl->entries[i].type == SMB_ACL_GROUP) {
			align_offset(n, 8);
			ndr_write_int64(n, acl->entries[i].gid);
		}

		/* push permission */
		ndr_write_int32(n, acl->entries[i].perm);
	}

	return 0;
}

int ndr_encode_posix_acl(struct ndr *n, struct inode *inode,
		struct xattr_smb_acl *acl, struct xattr_smb_acl *def_acl)
{
	int ref_id = 0x00020000;

	n->offset = 0;
	n->length = 1024;
	n->data = kzalloc(n->length, GFP_KERNEL);
	if (!n->data)
		return -ENOMEM;

	if (acl) {
		/* ACL ACCESS */
		ndr_write_int32(n, ref_id);
		ref_id += 4;
	} else {
		ndr_write_int32(n, 0);
	}

	if (def_acl) {
		/* DEFAULT ACL ACCESS */
		ndr_write_int32(n, ref_id);
		ref_id += 4;
	} else {
		ndr_write_int32(n, 0);
	}

	ndr_write_int64(n, from_kuid(&init_user_ns, inode->i_uid));
	ndr_write_int64(n, from_kgid(&init_user_ns, inode->i_gid));
	ndr_write_int32(n, inode->i_mode);

	if (acl) {
		ndr_encode_posix_acl_entry(n, acl);
		if (def_acl)
			ndr_encode_posix_acl_entry(n, def_acl);
	}
	return 0;
}

int ndr_encode_v4_ntacl(struct ndr *n, struct xattr_ntacl *acl)
{
	int ref_id = 0x00020004;

	n->offset = 0;
	n->length = 2048;
	n->data = kzalloc(n->length, GFP_KERNEL);
	if (!n->data)
		return -ENOMEM;

	ndr_write_int16(n, acl->version);
	ndr_write_int32(n, acl->version);
	ndr_write_int16(n, 2);
	ndr_write_int32(n, ref_id);

	/* push hash type and hash 64bytes */
	ndr_write_int16(n, acl->hash_type);
	ndr_write_bytes(n, acl->hash, XATTR_SD_HASH_SIZE);
	ndr_write_bytes(n, acl->desc, acl->desc_len);
	ndr_write_int64(n, acl->current_time);
	ndr_write_bytes(n, acl->posix_acl_hash, XATTR_SD_HASH_SIZE);

	/* push ndr for security descriptor */
	ndr_write_bytes(n, acl->sd_buf, acl->sd_size);

	return 0;
}

int ndr_decode_v4_ntacl(struct ndr *n, struct xattr_ntacl *acl)
{
	int ret;
	__u16 version;
	__u32 tmp32;
	__u64 tmp64;

	n->offset = 0;
	ret = ndr_read_int16(n, &version);
	if (ret)
		return ret;
	acl->version = version;

	if (acl->version != 4) {
		ksmbd_err("v%d version is not supported\n", acl->version);
		return -EINVAL;
	}

	ret = ndr_read_int32(n, &tmp32);
	if (ret)
		return ret;
	if (acl->version != tmp32) {
		ksmbd_err("ndr version mismatched(version: %d, version2: %d)\n",
				acl->version, tmp32);
		return -EINVAL;
	}

	/* Read Level */
	ret = ndr_read_int16(n, &version);
	if (ret)
		return ret;
	/* Read Ref Id */
	ret = ndr_read_int32(n, &tmp32);
	if (ret)
		return ret;
	ret = ndr_read_int16(n, &version);
	if (ret)
		return ret;
	acl->hash_type = version;
	ret = ndr_read_bytes(n, acl->hash, XATTR_SD_HASH_SIZE);
	if (ret)
		return ret;

	ret = ndr_read_bytes(n, acl->desc, 10);
	if (ret)
		return ret;
	if (strncmp(acl->desc, "posix_acl", 9)) {
		ksmbd_err("Invalid acl description : %s\n", acl->desc);
		return -EINVAL;
	}

	/* Read Time */
	ret = ndr_read_int64(n, &tmp64);
	if (ret)
		return ret;
	/* Read Posix ACL hash */
	ret = ndr_read_bytes(n, acl->posix_acl_hash, XATTR_SD_HASH_SIZE);
	if (ret)
		return ret;
	acl->sd_size = n->length - n->offset;
	acl->sd_buf = kzalloc(acl->sd_size, GFP_KERNEL);
	if (!acl->sd_buf)
		return -ENOMEM;

	ret = ndr_read_bytes(n, acl->sd_buf, acl->sd_size);
	if (ret) {
		kfree(acl->sd_buf);
		acl->sd_buf = NULL;
		return ret;
	}

	return 0;
}
