/* Copyright (c) 2011-2014 PLUMgrid, http://plumgrid.com
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#ifndef _UAPI__LINUX_BPF_H__
#define _UAPI__LINUX_BPF_H__

#include <linux/types.h>
#include <linux/bpf_common.h>

/* Extended instruction set based on top of classic BPF */

/* instruction classes */
#define BPF_JMP32	0x06	/* jmp mode in word width */
#define BPF_ALU64	0x07	/* alu mode in double word width */

/* ld/ldx fields */
#define BPF_DW		0x18	/* double word */
#define BPF_XADD	0xc0	/* exclusive add */

/* alu/jmp fields */
#define BPF_MOV		0xb0	/* mov reg to reg */
#define BPF_ARSH	0xc0	/* sign extending arithmetic shift right */

/* change endianness of a register */
#define BPF_END		0xd0	/* flags for endianness conversion: */
#define BPF_TO_LE	0x00	/* convert to little-endian */
#define BPF_TO_BE	0x08	/* convert to big-endian */
#define BPF_FROM_LE	BPF_TO_LE
#define BPF_FROM_BE	BPF_TO_BE

/* jmp encodings */
#define BPF_JNE		0x50	/* jump != */
#define BPF_JLT		0xa0	/* LT is unsigned, '<' */
#define BPF_JLE		0xb0	/* LE is unsigned, '<=' */
#define BPF_JSGT	0x60	/* SGT is signed '>', GT in x86 */
#define BPF_JSGE	0x70	/* SGE is signed '>=', GE in x86 */
#define BPF_JSLT	0xc0	/* SLT is signed, '<' */
#define BPF_JSLE	0xd0	/* SLE is signed, '<=' */
#define BPF_CALL	0x80	/* function call */
#define BPF_EXIT	0x90	/* function return */

/* Register numbers */
enum {
	BPF_REG_0 = 0,
	BPF_REG_1,
	BPF_REG_2,
	BPF_REG_3,
	BPF_REG_4,
	BPF_REG_5,
	BPF_REG_6,
	BPF_REG_7,
	BPF_REG_8,
	BPF_REG_9,
	BPF_REG_10,
	__MAX_BPF_REG,
};

/* BPF has 10 general purpose 64-bit registers and stack frame. */
#define MAX_BPF_REG	__MAX_BPF_REG

struct bpf_insn {
	__u8	code;		/* opcode */
	__u8	dst_reg:4;	/* dest register */
	__u8	src_reg:4;	/* source register */
	__s16	off;		/* signed offset */
	__s32	imm;		/* signed immediate constant */
};

struct bpf_cgroup_storage_key {
	__u64	cgroup_inode_id;	/* cgroup inode id */
	__u32	attach_type;		/* program attach type */
};

/* Key of an a BPF_MAP_TYPE_LPM_TRIE entry */
struct bpf_lpm_trie_key {
	__u32	prefixlen;	/* up to 32 for AF_INET, 128 for AF_INET6 */
	__u8	data[0];	/* Arbitrary size */
};

/* BPF syscall commands, see bpf(2) man-page for details. */
enum bpf_cmd {
	BPF_MAP_CREATE,
	BPF_MAP_LOOKUP_ELEM,
	BPF_MAP_UPDATE_ELEM,
	BPF_MAP_DELETE_ELEM,
	BPF_MAP_GET_NEXT_KEY,
	BPF_PROG_LOAD,
	BPF_OBJ_PIN,
	BPF_OBJ_GET,
	BPF_PROG_ATTACH,
	BPF_PROG_DETACH,
	BPF_PROG_TEST_RUN, // stub
	BPF_PROG_GET_NEXT_ID,
	BPF_MAP_GET_NEXT_ID,
	BPF_PROG_GET_FD_BY_ID,
	BPF_MAP_GET_FD_BY_ID,
	BPF_OBJ_GET_INFO_BY_FD,
	BPF_PROG_QUERY,
	BPF_BTF_LOAD = 18,
	BPF_BTF_GET_FD_BY_ID,
};

enum bpf_map_type {
	BPF_MAP_TYPE_UNSPEC,
	BPF_MAP_TYPE_HASH,
	BPF_MAP_TYPE_ARRAY,
	BPF_MAP_TYPE_PROG_ARRAY,
	BPF_MAP_TYPE_PERF_EVENT_ARRAY,
	BPF_MAP_TYPE_PERCPU_HASH,
	BPF_MAP_TYPE_PERCPU_ARRAY,
	BPF_MAP_TYPE_STACK_TRACE,
	BPF_MAP_TYPE_CGROUP_ARRAY,
	BPF_MAP_TYPE_LRU_HASH,
	BPF_MAP_TYPE_LRU_PERCPU_HASH,
	BPF_MAP_TYPE_LPM_TRIE,
	BPF_MAP_TYPE_ARRAY_OF_MAPS,
	BPF_MAP_TYPE_HASH_OF_MAPS,
	BPF_MAP_TYPE_DEVMAP,
	BPF_MAP_TYPE_SOCKMAP,
	BPF_MAP_TYPE_CPUMAP,
	BPF_MAP_TYPE_SOCKHASH = 18,
	BPF_MAP_TYPE_CGROUP_STORAGE = 19,
	BPF_MAP_TYPE_REUSEPORT_SOCKARRAY = 20,
	BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE = 21,
	BPF_MAP_TYPE_QUEUE = 22,
	BPF_MAP_TYPE_STACK = 23,
	BPF_MAP_TYPE_SK_STORAGE = 24,
	BPF_MAP_TYPE_DEVMAP_HASH = BPF_MAP_TYPE_DEVMAP + 11,
	BPF_MAP_TYPE_RINGBUF = 27,
};

enum bpf_prog_type {
	BPF_PROG_TYPE_UNSPEC,
	BPF_PROG_TYPE_SOCKET_FILTER,
	BPF_PROG_TYPE_KPROBE,
	BPF_PROG_TYPE_SCHED_CLS,
	BPF_PROG_TYPE_SCHED_ACT,
	BPF_PROG_TYPE_TRACEPOINT,
	BPF_PROG_TYPE_XDP,
	BPF_PROG_TYPE_PERF_EVENT,
	BPF_PROG_TYPE_CGROUP_SKB,
	BPF_PROG_TYPE_CGROUP_SOCK,
	BPF_PROG_TYPE_CGROUP_SOCK_ADDR = BPF_PROG_TYPE_CGROUP_SOCK + 9,
	BPF_PROG_TYPE_SK_REUSEPORT = 21,
	BPF_PROG_TYPE_CGROUP_SOCKOPT = 25,
	BPF_PROG_TYPE_FUSE = 31,
};

enum bpf_attach_type {
	BPF_CGROUP_INET_INGRESS,
	BPF_CGROUP_INET_EGRESS,
	BPF_CGROUP_INET_SOCK_CREATE,
	BPF_CGROUP_INET4_BIND = BPF_CGROUP_INET_SOCK_CREATE + 6,
	BPF_CGROUP_INET6_BIND,
	BPF_CGROUP_INET4_CONNECT,
	BPF_CGROUP_INET6_CONNECT,
	BPF_CGROUP_UDP4_SENDMSG = BPF_CGROUP_INET6_CONNECT + 3,
	BPF_CGROUP_UDP6_SENDMSG,
	BPF_CGROUP_UDP4_RECVMSG = 19,
	BPF_CGROUP_UDP6_RECVMSG,
	BPF_CGROUP_GETSOCKOPT = 21,
	BPF_CGROUP_SETSOCKOPT,
	__MAX_BPF_ATTACH_TYPE,
};

#define MAX_BPF_ATTACH_TYPE __MAX_BPF_ATTACH_TYPE

/* cgroup-bpf attach flags used in BPF_PROG_ATTACH command
 *
 * NONE(default): No further bpf programs allowed in the subtree.
 *
 * BPF_F_ALLOW_OVERRIDE: If a sub-cgroup installs some bpf program,
 * the program in this cgroup yields to sub-cgroup program.
 *
 * BPF_F_ALLOW_MULTI: If a sub-cgroup installs some bpf program,
 * that cgroup program gets run in addition to the program in this cgroup.
 *
 * Only one program is allowed to be attached to a cgroup with
 * NONE or BPF_F_ALLOW_OVERRIDE flag.
 * Attaching another program on top of NONE or BPF_F_ALLOW_OVERRIDE will
 * release old program and attach the new one. Attach flags has to match.
 *
 * Multiple programs are allowed to be attached to a cgroup with
 * BPF_F_ALLOW_MULTI flag. They are executed in FIFO order
 * (those that were attached first, run first)
 * The programs of sub-cgroup are executed first, then programs of
 * this cgroup and then programs of parent cgroup.
 * When children program makes decision (like picking TCP CA or sock bind)
 * parent program has a chance to override it.
 *
 * A cgroup with MULTI or OVERRIDE flag allows any attach flags in sub-cgroups.
 * A cgroup with NONE doesn't allow any programs in sub-cgroups.
 * Ex1:
 * cgrp1 (MULTI progs A, B) ->
 *    cgrp2 (OVERRIDE prog C) ->
 *      cgrp3 (MULTI prog D) ->
 *        cgrp4 (OVERRIDE prog E) ->
 *          cgrp5 (NONE prog F)
 * the event in cgrp5 triggers execution of F,D,A,B in that order.
 * if prog F is detached, the execution is E,D,A,B
 * if prog F and D are detached, the execution is E,A,B
 * if prog F, E and D are detached, the execution is C,A,B
 *
 * All eligible programs are executed regardless of return code from
 * earlier programs.
 */
#define BPF_F_ALLOW_OVERRIDE	(1U << 0)
#define BPF_F_ALLOW_MULTI	(1U << 1)
#define BPF_F_REPLACE		(1U << 2)

/* If BPF_F_STRICT_ALIGNMENT is used in BPF_PROG_LOAD command, the
 * verifier will perform strict alignment checking as if the kernel
 * has been built with CONFIG_EFFICIENT_UNALIGNED_ACCESS not set,
 * and NET_IP_ALIGN defined to 2.
 */
#define BPF_F_STRICT_ALIGNMENT	(1U << 0)

#define BPF_PSEUDO_MAP_FD	1
#define BPF_PSEUDO_MAP_VALUE	2
#define BPF_PSEUDO_CALL		1

/* flags for BPF_MAP_UPDATE_ELEM command */
#define BPF_ANY		0 /* create new element or update existing */
#define BPF_NOEXIST	1 /* create new element if it didn't exist */
#define BPF_EXIST	2 /* update existing element */

#define BPF_F_NO_PREALLOC	(1U << 0)
/* Instead of having one common LRU list in the
 * BPF_MAP_TYPE_LRU_[PERCPU_]HASH map, use a percpu LRU list
 * which can scale and perform better.
 * Note, the LRU nodes (including free nodes) cannot be moved
 * across different LRU lists.
 */
#define BPF_F_NO_COMMON_LRU	(1U << 1)

/* Flags for accessing BPF object */
#define BPF_F_RDONLY		(1U << 3)
#define BPF_F_WRONLY		(1U << 4)

/* flags for BPF_PROG_QUERY */
#define BPF_F_QUERY_EFFECTIVE	(1U << 0)

/* Enable memory-mapping BPF map */
#define BPF_F_MMAPABLE		(1U << 10)

/* If BPF_F_NUMA_NODE is used in BPF_MAP_CREATE
 * command, the numa_node attribute will be used to
 * select the numa node for the map.
 */
#define BPF_F_NUMA_NODE		(1U << 2)

#define BPF_OBJ_NAME_LEN 16U

union bpf_attr {
	struct { /* anonymous struct used by BPF_MAP_CREATE command */
		__u32	map_type;	/* one of enum bpf_map_type */
		__u32	key_size;	/* size of key in bytes */
		__u32	value_size;	/* size of value in bytes */
		__u32	max_entries;	/* max number of entries in a map */
		__u32	map_flags;	/* prealloc or not */
		__u32	inner_map_fd;	/* fd pointing to the inner map */
		__u32	numa_node;	/* numa node (effective only if
 					 * BPF_F_NUMA_NODE is set).
 					 */
		char	map_name[BPF_OBJ_NAME_LEN];
		__u32	map_ifindex;	/* ifindex of netdev to create on */
		__u32	btf_fd;		/* fd pointing to a BTF type data */
		__u32	btf_key_type_id;	/* BTF type_id of the key */
		__u32	btf_value_type_id;	/* BTF type_id of the value */
	};

	struct { /* anonymous struct used by BPF_MAP_*_ELEM commands */
		__u32		map_fd;
		__aligned_u64	key;
		union {
			__aligned_u64 value;
			__aligned_u64 next_key;
		};
		__u64		flags;
	};

	struct { /* anonymous struct used by BPF_PROG_LOAD command */
		__u32		prog_type;	/* one of enum bpf_prog_type */
		__u32		insn_cnt;
		__aligned_u64	insns;
		__aligned_u64	license;
		__u32		log_level;	/* verbosity level of verifier */
		__u32		log_size;	/* size of user buffer */
		__aligned_u64	log_buf;	/* user supplied buffer */
		__u32		kern_version;	/* checked when prog_type=kprobe */
		__u32		prog_flags;
		char		prog_name[BPF_OBJ_NAME_LEN];
/* FIXME: backport if needed */		__u32		prog_ifindex;	/* ifindex of netdev to prep for */
		/* For some prog types expected attach type must be known at
		 * load time to verify attach type specific parts of prog
		 * (context accesses, allowed helpers, etc).
		 */
		__u32		expected_attach_type;

		__u32		prog_btf_fd;	/* fd pointing to BTF type data */
		__u32		func_info_rec_size;	/* userspace bpf_func_info size */
		__aligned_u64	func_info;	/* func info */
		__u32		func_info_cnt;	/* number of bpf_func_info records */
		__u32		line_info_rec_size;	/* userspace bpf_line_info size */
		__aligned_u64	line_info;	/* line info */
		__u32		line_info_cnt;	/* number of bpf_line_info records */
	};

	struct { /* anonymous struct used by BPF_OBJ_* commands */
		__aligned_u64	pathname;
		__u32		bpf_fd;
		__u32		file_flags;
	};

	struct { /* anonymous struct used by BPF_PROG_ATTACH/DETACH commands */
		__u32		target_fd;	/* container object to attach to */
		__u32		attach_bpf_fd;	/* eBPF program to attach */
		__u32		attach_type;
		__u32		attach_flags;
	};

	struct { /* anonymous struct used by BPF_PROG_TEST_RUN command */
		__u32           prog_fd;
		__u32           retval;
		__u32           data_size_in;
		__u32           data_size_out;
		__aligned_u64   data_in;
		__aligned_u64   data_out;
		__u32           repeat;
		__u32           duration;
	} test;

	struct { /* anonymous struct used by BPF_*_GET_*_ID */
		union {
			__u32		start_id;
			__u32		prog_id;
			__u32		map_id;
			__u32		btf_id;
		};
		__u32		next_id;
		__u32		open_flags;
	};

	struct { /* anonymous struct used by BPF_OBJ_GET_INFO_BY_FD */
		__u32		bpf_fd;
		__u32		info_len;
		__aligned_u64	info;
	} info;

	struct { /* anonymous struct used by BPF_PROG_QUERY command */
		__u32		target_fd;	/* container object to query */
		__u32		attach_type;
		__u32		query_flags;
		__u32		attach_flags;
		__aligned_u64	prog_ids;
		__u32		prog_cnt;
	} query;

	struct { /* anonymous struct used by BPF_RAW_TRACEPOINT_OPEN command */
		__u64 name;
		__u32 prog_fd;
	} raw_tracepoint;

	struct { /* anonymous struct for BPF_BTF_LOAD */
		__aligned_u64	btf;
		__aligned_u64	btf_log_buf;
		__u32		btf_size;
		__u32		btf_log_size;
		__u32		btf_log_level;
	};
} __attribute__((aligned(8)));

/* integer value in 'imm' field of BPF_CALL instruction selects which helper
 * function eBPF program intends to call
 */
#define __BPF_FUNC_MAPPER(FN)		\
	FN(unspec),			\
	FN(map_lookup_elem),		\
	FN(map_update_elem),		\
	FN(map_delete_elem),		\
	FN(probe_read),			\
	FN(ktime_get_ns),		\
	FN(trace_printk),		\
	FN(get_prandom_u32),		\
	FN(get_smp_processor_id),	\
	FN(skb_store_bytes),		\
	FN(l3_csum_replace),		\
	FN(l4_csum_replace),		\
	FN(tail_call),			\
	FN(clone_redirect),		\
	FN(get_current_pid_tgid),	\
	FN(get_current_uid_gid),	\
	FN(get_current_comm),		\
	FN(get_cgroup_classid),		\
	FN(skb_vlan_push),		\
	FN(skb_vlan_pop),		\
	FN(skb_get_tunnel_key),		\
	FN(skb_set_tunnel_key),		\
	FN(perf_event_read),		\
	FN(redirect),			\
	FN(get_route_realm),		\
	FN(perf_event_output),		\
	FN(skb_load_bytes),		\
	FN(get_stackid),		\
	FN(csum_diff),			\
	FN(skb_get_tunnel_opt),		\
	FN(skb_set_tunnel_opt),		\
	FN(skb_change_proto),		\
	FN(skb_change_type),		\
	FN(skb_under_cgroup),		\
	FN(get_hash_recalc),		\
	FN(get_current_task),		\
	FN(probe_write_user),		\
	FN(current_task_under_cgroup),	\
	FN(skb_change_tail),		\
	FN(skb_pull_data),		\
	FN(csum_update),		\
	FN(set_hash_invalid),		\
	FN(get_numa_node_id),		\
	FN(skb_change_head),		\
	FN(xdp_adjust_head),		\
	FN(probe_read_str),		\
	FN(get_socket_cookie),		\
	FN(get_socket_uid),		\
	FN(set_hash),			\
	FN(setsockopt),			\
	FN(skb_adjust_room),		\
	FN(redirect_map),		\
	FN(sk_redirect_map),		\
	FN(sock_map_update),		\
	FN(xdp_adjust_meta),		\
	FN(perf_event_read_value),	\
	FN(perf_prog_read_value),	\
	FN(getsockopt),			\
	FN(override_return),		\
	FN(sock_ops_cb_flags_set),	\
	FN(msg_redirect_map),		\
	FN(msg_apply_bytes),		\
	FN(msg_cork_bytes),		\
	FN(msg_pull_data),		\
	FN(bind),			\
	FN(xdp_adjust_tail),		\
	FN(skb_get_xfrm_state),		\
	FN(get_stack),			\
	FN(skb_load_bytes_relative),	\
	FN(fib_lookup),			\
	FN(sock_hash_update),		\
	FN(msg_redirect_hash),		\
	FN(sk_redirect_hash),		\
	FN(lwt_push_encap),		\
	FN(lwt_seg6_store_bytes),	\
	FN(lwt_seg6_adjust_srh),	\
	FN(lwt_seg6_action),		\
	FN(rc_repeat),			\
	FN(rc_keydown),			\
	FN(skb_cgroup_id),		\
	FN(get_current_cgroup_id),	\
	FN(get_local_storage),		\
	FN(sk_select_reuseport),	\
	FN(skb_ancestor_cgroup_id),	\
	FN(sk_lookup_tcp),		\
	FN(sk_lookup_udp),		\
	FN(sk_release),			\
	FN(map_push_elem),		\
	FN(map_pop_elem),		\
	FN(map_peek_elem),		\
	FN(msg_push_data),		\
	FN(msg_pop_data),		\
	FN(rc_pointer_rel),		\
	FN(spin_lock),			\
	FN(spin_unlock),		\
	FN(sk_fullsock),		\
	FN(tcp_sock),			\
	FN(skb_ecn_set_ce),		\
	FN(get_listener_sock),		\
	FN(skc_lookup_tcp),		\
	FN(tcp_check_syncookie),	\
	FN(sysctl_get_name),		\
	FN(sysctl_get_current_value),	\
	FN(sysctl_get_new_value),	\
	FN(sysctl_set_new_value),	\
	FN(strtol),			\
	FN(strtoul),			\
	FN(sk_storage_get),		\
	FN(sk_storage_delete),		\
	FN(send_signal),		\
	FN(tcp_gen_syncookie),		\
	FN(skb_output),			\
	FN(probe_read_user),		\
	FN(probe_read_kernel),		\
	FN(probe_read_user_str),	\
	FN(probe_read_kernel_str),	\
	FN(tcp_send_ack),		\
	FN(send_signal_thread),		\
	FN(jiffies64),			\
	FN(read_branch_records),	\
	FN(get_ns_current_pid_tgid),	\
	FN(xdp_output),			\
	FN(get_netns_cookie),		\
	FN(get_current_ancestor_cgroup_id),	\
	FN(sk_assign),			\
	FN(ktime_get_boot_ns),		\
	FN(seq_printf),			\
	FN(seq_write),			\
	FN(sk_cgroup_id),		\
	FN(sk_ancestor_cgroup_id),	\
	FN(ringbuf_output),		\
	FN(ringbuf_reserve),		\
	FN(ringbuf_submit),		\
	FN(ringbuf_discard),		\
	FN(ringbuf_query),

#define __BPF_ENUM_FN(x) BPF_FUNC_ ## x
enum bpf_func_id {
	__BPF_FUNC_MAPPER(__BPF_ENUM_FN)
	__BPF_FUNC_MAX_ID,
};
#undef __BPF_ENUM_FN

/* All flags used by eBPF helper functions, placed here. */

/* BPF_FUNC_skb_store_bytes flags. */
#define BPF_F_RECOMPUTE_CSUM		(1ULL << 0)
#define BPF_F_INVALIDATE_HASH		(1ULL << 1)

/* BPF_FUNC_l3_csum_replace and BPF_FUNC_l4_csum_replace flags.
 * First 4 bits are for passing the header field size.
 */
#define BPF_F_HDR_FIELD_MASK		0xfULL

/* BPF_FUNC_l4_csum_replace flags. */
#define BPF_F_PSEUDO_HDR		(1ULL << 4)
#define BPF_F_MARK_MANGLED_0		(1ULL << 5)

/* BPF_FUNC_clone_redirect and BPF_FUNC_redirect flags. */
#define BPF_F_INGRESS			(1ULL << 0)

/* BPF_FUNC_skb_set_tunnel_key and BPF_FUNC_skb_get_tunnel_key flags. */
#define BPF_F_TUNINFO_IPV6		(1ULL << 0)

/* BPF_FUNC_skb_set_tunnel_key flags. */
#define BPF_F_ZERO_CSUM_TX              (1ULL << 1)
#define BPF_F_DONT_FRAGMENT             (1ULL << 2)

/* BPF_FUNC_get_stackid flags. */
#define BPF_F_SKIP_FIELD_MASK		0xffULL
#define BPF_F_USER_STACK		(1ULL << 8)
#define BPF_F_FAST_STACK_CMP		(1ULL << 9)
#define BPF_F_REUSE_STACKID		(1ULL << 10)

/* BPF_FUNC_perf_event_output flags and BPF_FUNC_perf_event_read. */
#define BPF_F_INDEX_MASK		0xffffffffULL
#define BPF_F_CURRENT_CPU		BPF_F_INDEX_MASK
/* BPF_FUNC_perf_event_output for sk_buff input context. */
#define BPF_F_CTXLEN_MASK		(0xfffffULL << 32)

/* BPF_FUNC_sk_storage_get flags */
#define BPF_SK_STORAGE_GET_F_CREATE	(1ULL << 0)

/* BPF_FUNC_bpf_ringbuf_commit, BPF_FUNC_bpf_ringbuf_discard, and
 * BPF_FUNC_bpf_ringbuf_output flags.
 */
enum {
	BPF_RB_NO_WAKEUP		= (1ULL << 0),
	BPF_RB_FORCE_WAKEUP		= (1ULL << 1),
};

/* BPF_FUNC_bpf_ringbuf_query flags */
enum {
	BPF_RB_AVAIL_DATA = 0,
	BPF_RB_RING_SIZE = 1,
	BPF_RB_CONS_POS = 2,
	BPF_RB_PROD_POS = 3,
};

/* BPF ring buffer constants */
enum {
	BPF_RINGBUF_BUSY_BIT		= (1U << 31),
	BPF_RINGBUF_DISCARD_BIT		= (1U << 30),
	BPF_RINGBUF_HDR_SZ		= 8,
};

/* Mode for BPF_FUNC_skb_adjust_room helper. */
enum bpf_adj_room_mode {
	BPF_ADJ_ROOM_NET,
};

/* Mode for BPF_FUNC_skb_load_bytes_relative helper. */
enum bpf_hdr_start_off {
	BPF_HDR_START_MAC,
	BPF_HDR_START_NET,
};

#define __bpf_md_ptr(type, name)	\
union {					\
	type name;			\
	__u64 :64;			\
} __attribute__((aligned(8)))

struct bpf_flow_keys {
	__u16	nhoff;
	__u16	thoff;
	__u16	addr_proto;			/* ETH_P_* of valid addrs */
	__u8	is_frag;
	__u8	is_first_frag;
	__u8	is_encap;
	__u8	ip_proto;
	__be16	n_proto;
	__be16	sport;
	__be16	dport;
	union {
		struct {
			__be32	ipv4_src;
			__be32	ipv4_dst;
		};
		struct {
			__u32	ipv6_src[4];	/* in6_addr; network order */
			__u32	ipv6_dst[4];	/* in6_addr; network order */
		};
	};
	__u32	flags;
	__be32	flow_label;
};

struct bpf_sock {
	__u32 bound_dev_if;
	__u32 family;
	__u32 type;
	__u32 protocol;
	__u32 mark;
	__u32 priority;
};

/* user accessible mirror of in-kernel sk_buff.
 * new fields can only be added to the end of this structure
 */
struct __sk_buff {
	__u32 len;
	__u32 pkt_type;
	__u32 mark;
	__u32 queue_mapping;
	__u32 protocol;
	__u32 vlan_present;
	__u32 vlan_tci;
	__u32 vlan_proto;
	__u32 priority;
	__u32 ingress_ifindex;
	__u32 ifindex;
	__u32 tc_index;
	__u32 cb[5];
	__u32 hash;
	__u32 tc_classid;
	__u32 data;
	__u32 data_end;

	__u32 napi_id;

	/* Accessed by BPF_PROG_TYPE_sk_skb types from here to ... */
	__u32 family;
	__u32 remote_ip4;	/* Stored in network byte order */
	__u32 local_ip4;	/* Stored in network byte order */
	__u32 remote_ip6[4];	/* Stored in network byte order */
	__u32 local_ip6[4];	/* Stored in network byte order */
	__u32 remote_port;	/* Stored in network byte order */
	__u32 local_port;	/* stored in host byte order */
	/* ... here. */

	__u32 data_meta;
	__bpf_md_ptr(struct bpf_flow_keys *, flow_keys);
	__u64 tstamp;
	__u32 wire_len;
	__u32 gso_segs;
	__bpf_md_ptr(struct bpf_sock *, sk);
	__u32 gso_size;
};

struct bpf_tunnel_key {
	__u32 tunnel_id;
	union {
		__u32 remote_ipv4;
		__u32 remote_ipv6[4];
	};
	__u8 tunnel_tos;
	__u8 tunnel_ttl;
	__u16 tunnel_ext;
	__u32 tunnel_label;
};

/* User return codes for XDP prog type.
 * A valid XDP program must return one of these defined values. All other
 * return codes are reserved for future use. Unknown return codes will result
 * in packet drop.
 */
enum xdp_action {
	XDP_ABORTED = 0,
	XDP_DROP,
	XDP_PASS,
};

/* user accessible metadata for XDP packet hook
 * new fields must be added to the end of this structure
 */
struct xdp_md {
	__u32 data;
	__u32 data_end;
};

#define BPF_TAG_SIZE	8

struct bpf_prog_info {
	__u32 type;
	__u32 id;
	__u8  tag[BPF_TAG_SIZE];
	__u32 jited_prog_len;
	__u32 xlated_prog_len;
	__aligned_u64 jited_prog_insns;
	__aligned_u64 xlated_prog_insns;
	__u64 load_time;	/* ns since boottime */
	__u32 created_by_uid;
	__u32 nr_map_ids;
	__aligned_u64 map_ids;
	char name[BPF_OBJ_NAME_LEN];
} __attribute__((aligned(8)));

struct bpf_map_info {
	__u32 type;
	__u32 id;
	__u32 key_size;
	__u32 value_size;
	__u32 max_entries;
	__u32 map_flags;
	char  name[BPF_OBJ_NAME_LEN];
	__u32 ifindex;
	__u64 netns_dev;
	__u64 netns_ino;
	__u32 btf_id;
	__u32 btf_key_type_id;
	__u32 btf_value_type_id;
} __attribute__((aligned(8)));

struct bpf_btf_info {
	__aligned_u64 btf;
	__u32 btf_size;
	__u32 id;
} __attribute__((aligned(8)));

/* User bpf_sock_addr struct to access socket fields and sockaddr struct passed
 * by user and intended to be used by socket (e.g. to bind to, depends on
 * attach attach type).
 */
struct bpf_sock_addr {
	__u32 user_family;	/* Allows 4-byte read, but no write. */
	__u32 user_ip4;		/* Allows 1,2,4-byte read and 4-byte write.
				 * Stored in network byte order.
				 */
	__u32 user_ip6[4];	/* Allows 1,2,4-byte read an 4-byte write.
				 * Stored in network byte order.
				 */
	__u32 user_port;	/* Allows 4-byte read and write.
				 * Stored in network byte order
				 */
	__u32 family;		/* Allows 4-byte read, but no write */
	__u32 type;		/* Allows 4-byte read, but no write */
	__u32 protocol;		/* Allows 4-byte read, but no write */
	__u32 msg_src_ip4;	/* Allows 1,2,4-byte read an 4-byte write.
				 * Stored in network byte order.
				 */
	__u32 msg_src_ip6[4];	/* Allows 1,2,4-byte read an 4-byte write.
				 * Stored in network byte order.
				 */
	__bpf_md_ptr(struct bpf_sock *, sk);
};

struct bpf_sockopt {
	__bpf_md_ptr(struct bpf_sock *, sk);
	__bpf_md_ptr(void *, optval);
	__bpf_md_ptr(void *, optval_end);
	__s32	level;
	__s32	optname;
	__s32	optlen;
	__s32	retval;
};

struct bpf_tcp_sock {
	__u32 snd_cwnd;		/* Sending congestion window		*/
	__u32 srtt_us;		/* smoothed round trip time << 3 in usecs */
	__u32 rtt_min;
	__u32 snd_ssthresh;	/* Slow start size threshold		*/
	__u32 rcv_nxt;		/* What we want to receive next		*/
	__u32 snd_nxt;		/* Next sequence we send		*/
	__u32 snd_una;		/* First byte we want an ack for	*/
	__u32 mss_cache;	/* Cached effective mss, not including SACKS */
	__u32 ecn_flags;	/* ECN status bits.			*/
	__u32 rate_delivered;	/* saved rate sample: packets delivered */
	__u32 rate_interval_us;	/* saved rate sample: time elapsed */
	__u32 packets_out;	/* Packets which are "in flight"	*/
	__u32 retrans_out;	/* Retransmitted packets out		*/
	__u32 total_retrans;	/* Total retransmits for entire connection */
	__u32 segs_in;		/* RFC4898 tcpEStatsPerfSegsIn
				 * total number of segments in.
				 */
	__u32 data_segs_in;	/* RFC4898 tcpEStatsPerfDataSegsIn
				 * total number of data segments in.
				 */
	__u32 segs_out;		/* RFC4898 tcpEStatsPerfSegsOut
				 * The total number of segments sent.
				 */
	__u32 data_segs_out;	/* RFC4898 tcpEStatsPerfDataSegsOut
				 * total number of data segments sent.
				 */
	__u32 lost_out;		/* Lost packets			*/
	__u32 sacked_out;	/* SACK'd packets			*/
	__u64 bytes_received;	/* RFC4898 tcpEStatsAppHCThruOctetsReceived
				 * sum(delta(rcv_nxt)), or how many bytes
				 * were acked.
				 */
	__u64 bytes_acked;	/* RFC4898 tcpEStatsAppHCThruOctetsAcked
				 * sum(delta(snd_una)), or how many bytes
				 * were acked.
				 */
	__u32 dsack_dups;	/* RFC4898 tcpEStatsStackDSACKDups
				 * total number of DSACK blocks received
				 */
	__u32 delivered;	/* Total data packets delivered incl. rexmits */
	__u32 delivered_ce;	/* Like the above but only ECE marked packets */
	__u32 icsk_retransmits;	/* Number of unrecovered [RTO] timeouts */
};

#endif /* _UAPI__LINUX_BPF_H__ */
