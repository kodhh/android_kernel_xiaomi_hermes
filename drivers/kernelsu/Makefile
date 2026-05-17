# NOTE: unity build. single unit.

obj-$(CONFIG_KSU) := kernelsu.o

CFLAGS_kernelsu.o += -I$(srctree)/security/selinux -I$(srctree)/security/selinux/include
CFLAGS_kernelsu.o += -I$(objtree)/security/selinux

CFLAGS_kernelsu.o += -DKSU_VERSION=32486

ifndef KSU_EXPECTED_SIZE
KSU_EXPECTED_SIZE := 0x033b
endif

ifndef KSU_EXPECTED_HASH
KSU_EXPECTED_HASH := c371061b19d8c7d7d6133c6a9bafe198fa944e50c1b31c9d8daa8d7f1fc2d2d6
endif

ifdef KSU_MANAGER_PACKAGE
CFLAGS_kernelsu.o += -DKSU_MANAGER_PACKAGE=\"$(KSU_MANAGER_PACKAGE)\"
$(info -- KernelSU Manager package name: $(KSU_MANAGER_PACKAGE))
endif

$(info -- KernelSU Manager signature size: $(KSU_EXPECTED_SIZE))
$(info -- KernelSU Manager signature hash: $(KSU_EXPECTED_HASH))

CFLAGS_kernelsu.o += -DEXPECTED_SIZE=$(KSU_EXPECTED_SIZE)
CFLAGS_kernelsu.o += -DEXPECTED_HASH=\"$(KSU_EXPECTED_HASH)\"

# uncommon, but wont hurt, check for 3-arg security_add_hooks
ifeq ($(shell grep -A1 "void security_add_hooks" $(srctree)/include/linux/lsm_hooks.h 2>/dev/null | grep -q lsm 2>/dev/null; echo $$?),0)
$(info -- KernelSU/compat: security_add_hooks v2 found!)
CFLAGS_kernelsu.o += -DKSU_COMPAT_SECURITY_ADD_HOOKS_V2
endif

ifeq ($(shell grep -q " current_sid(void)" $(srctree)/security/selinux/include/objsec.h; echo $$?),0)
CFLAGS_kernelsu.o += -DKSU_COMPAT_HAS_CURRENT_SID
endif

ifeq ($(shell grep -q "struct selinux_state " $(srctree)/security/selinux/include/security.h; echo $$?),0)
CFLAGS_kernelsu.o += -DKSU_COMPAT_HAS_SELINUX_STATE
endif

ifeq ($(shell grep -q "struct type_datum \*\*type_val_to_struct;" $(srctree)/security/selinux/ss/policydb.h; echo $$?),0)
CFLAGS_kernelsu.o += -DKSU_TYPE_VAL_TO_STRUCT
endif

# half-assed-backport from 5.1
ifeq ($(shell grep -q "struct type_datum \*\*type_val_to_struct_array;" $(srctree)/security/selinux/ss/policydb.h; echo $$?),0)
CFLAGS_kernelsu.o += -DKSU_TYPE_VAL_TO_STRUCT_ARRAY
endif

ifeq ($(shell grep -q "^DEFINE_RWLOCK(policy_rwlock);" $(srctree)/security/selinux/ss/services.c; echo $$?),0)
$(info -- KernelSU/compat: exported policy_rwlock found!)
CFLAGS_kernelsu.o += -DKSU_COMPAT_HAS_EXPORTED_POLICY_RWLOCK
endif

ifeq ($(shell grep -q "cpus_ptr;" $(srctree)/include/linux/sched.h; echo $$?),0)
$(info -- KernelSU/compat: backported cpus_ptr found!)
CFLAGS_kernelsu.o += -DKSU_COMPAT_HAS_BACKPORTED_CPUS_PTR
endif

ifeq ($(shell grep -q "^struct security_operations selinux_ops" $(srctree)/security/selinux/hooks.c; echo $$?),0)
$(info -- KernelSU/compat: exported selinux_ops found!)
CFLAGS_kernelsu.o += -DKSU_HAS_EXPORTED_SELINUX_OPS
endif

# UL, look for read_iter on f_op struct
ifeq ($(shell grep -q "read_iter" $(srctree)/include/linux/fs.h 2>/dev/null; echo $$?),0)
$(info -- KernelSU/compat: f_op->read_iter found!)
CFLAGS_kernelsu.o += -DKSU_HAS_FOP_READ_ITER
endif

# UL, look for iterate_dir on ‎fs/readdir.c
ifeq ($(shell grep -q "^int iterate_dir" $(srctree)/fs/readdir.c 2>/dev/null; echo $$?),0)
$(info -- KernelSU/compat: iterate_dir found!)
CFLAGS_kernelsu.o += -DKSU_HAS_ITERATE_DIR
endif

CFLAGS_kernelsu.o += -Wno-implicit-function-declaration -Wno-strict-prototypes -Wno-declaration-after-statement 
CFLAGS_kernelsu.o += -Wno-int-conversion -Wno-int-to-pointer-cast -Wno-pointer-to-int-cast
CFLAGS_kernelsu.o += -Wno-unused-variable -Wno-unused-function -Wno-format
CFLAGS_kernelsu.o += -Wno-macro-redefined

# dont be too strict
CFLAGS_REMOVE_kernelsu.o += -Werror

# so we can see stack use atleast, as we disable all stack safety here
CFLAGS_kernelsu.o += $(call cc-option, -Wframe-larger-than=1024)

# to make sure we can use builtins
CFLAGS_REMOVE_kernelsu.o += -fno-builtin

ifneq ($(CONFIG_KSU_DEBUG),y)
# strip, remove tracing / profiling
# comment out if proper backtrace is needed
CFLAGS_kernelsu.o += -g0 -fno-unwind-tables -fno-asynchronous-unwind-tables -fomit-frame-pointer
CFLAGS_REMOVE_kernelsu.o = $(CC_FLAGS_FTRACE)
CFLAGS_REMOVE_kernelsu.o += -pg

# if cflags can be macro'd, this will be called 'TRUST_ME'
CFLAGS_kernelsu.o += -fno-stack-protector -fno-stack-check
CFLAGS_REMOVE_kernelsu.o += -fsanitize=shadow-call-stack
endif # CONFIG_KSU_DEBUG

# Keep a new line here!! Because someone may append config
