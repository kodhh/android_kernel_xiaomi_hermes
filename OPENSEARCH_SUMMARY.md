## Objective
- Port BPF/net features from ExyHyperBrick exynos9810 (lineage-23.2) into hermes_bpf (MT6795 3.10) for LineageOS 23.2 compatibility.

## Important Details
- hermes_bpf spoofs `uname` to 5.10.239 (commit `aba5f91c6da`)
- exynos9810 repo at `/tmp/exynos9810` (cloned depth 200, branch lineage-23.2)
- Reference a6010 kernel at `/root/opencode/a6010` — single commit `2359fea4`
- Uncommitted hermes_bpf changes include: many modified files and untracked new files

## Work State
### Completed
- **5 helper commits**: `bpf_get_socket_cookie_sock`, `sk_lookup` in cg_skb, sock_common for sk_storage, cg_sock sk_storage proto, `BPF_CGROUP_INET_SOCK_RELEASE` hook
- **1 syscall commit**: `BPF_BTF_GET_NEXT_ID` (btf_idr export + syscall case)
- **All 11 bpf_link commits ported**:
  - Core bpf_link abstraction (`bpf_link_init`, `inc`, `put`, `release`, `bpf_link_fops`, `new_fd`, `get_from_fd`)
  - `bpf_link_new_file` + `dealloc` ops + `bpf_link_cleanup` (primer API)
  - ID allocation via IDR (`link_idr`, `link_idr_lock`), `bpf_link_prime`/`setttle`/`cleanup`
  - `BPF_LINK_GET_FD_BY_ID`, `BPF_LINK_GET_NEXT_ID` syscall handlers
  - `BPF_OBJ_GET_INFO_BY_FD` support for bpf_link (`bpf_link_get_info_by_fd`)
  - cgroup bpf_link attachment (`cgroup_bpf_link_attach`, `bpf_cgroup_link_lops`, etc.)
  - `replace_effective_prog`, `__cgroup_bpf_replace` for link program replacement
  - `BPF_LINK_CREATE` and `BPF_LINK_UPDATE` syscall handlers
  - `cgroup_bpf_link_detach`, `cgroup_bpf_replace`, `attach_type_to_prog_type`, `bpf_prog_attach_check_attach_type`
  - `cgroup_bpf_offline` call in `cgroup_destroy_locked` (kernel/cgroup.c)
  - `bpf_cgroup_storages_alloc/free/link/unlink/assign` helpers for per-cgroup storage
  - `BPF_TYPE_LINK` added to `inode.c` enum + pinning/get support
  - `enum bpf_link_type`, `struct bpf_link_info`, `link_create`/`link_update` UAPI structs
  - `struct bpf_link_primer`, `struct bpf_cgroup_link` definitions
- **Batch map operations** (all 3 batch commands: LOOKUP, UPDATE, DELETE):
  - `BPF_F_LOCK` flag defined in UAPI
  - Batch struct added to `union bpf_attr`
  - `map_value_has_spin_lock()`, `check_and_init_map_lock()` helpers in `include/linux/bpf.h`
  - `generic_map_lookup_batch()`, `generic_map_update_batch()`, `generic_map_delete_batch()` implementations in `kernel/bpf/syscall.c`
  - `bpf_map_value_size()`, `bpf_map_copy_value()`, `maybe_wait_bpf_programs()` helpers
  - `bpf_map_do_batch()` dispatcher function
  - `BPF_MAP_LOOKUP_BATCH`, `BPF_MAP_UPDATE_BATCH`, `BPF_MAP_DELETE_BATCH` syscall cases
  - `generic_map_update_batch()`, `generic_map_delete_batch()` declarations in `include/linux/bpf.h`

### Active
- (none — waiting for direction on next priority)

### Blocked
- **BPF_TASK_FD_QUERY** (1 commit, 7 files) — complex; touches trace events, kprobes, uprobes; deferred
- **Verifier/ringbuf fixes** — not started; lower priority

## Next Move
1. After batch ops, consider BPF_TASK_FD_QUERY if Android 14+ bpfloader requires it.
2. Or move to verifier/ringbuf fixes.

## Relevant Files
- `include/linux/bpf.h` — bpf_link struct, ops, link_primer; `bpf_link_init/prime/settle/cleanup/inc/put/new_fd/get_from_fd`; `check_and_init_map_lock`; `map_value_has_spin_lock`; `generic_map_*batch` declarations
- `include/uapi/linux/bpf.h` — `BPF_LINK_CREATE/UPDATE/GET_FD_BY_ID/GET_NEXT_ID`, `BPF_MAP_LOOKUP/UPDATE/DELETE_BATCH` enums; `bpf_link_type`, `bpf_link_info`, `link_create`, `link_update`, batch structs; `BPF_F_LOCK` flag
- `kernel/bpf/syscall.c` — all bpf_link functions; `link_create`, `link_update`, `bpf_link_get_fd_by_id`, `bpf_link_get_info_by_fd`, `attach_type_to_prog_type`, `bpf_prog_attach_check_attach_type`; `bpf_map_do_batch`, `generic_map_lookup_batch/update_batch/delete_batch`, `bpf_map_copy_value`, `bpf_map_value_size`, `maybe_wait_bpf_programs`
- `kernel/bpf/inode.c` — `BPF_TYPE_LINK` support
- `kernel/bpf/cgroup.c` — cgroup bpf_link operations, cgroup storage helpers
- `kernel/cgroup.c` — `cgroup_bpf_replace`, `cgroup_bpf_link_detach`, `cgroup_bpf_offline`
- `include/linux/bpf-cgroup.h` — `struct bpf_cgroup_link`, `struct bpf_prog_list` updates
- `net/ipv4/af_inet.c` — SOCK_RELEASE hook
