#ifndef __ASM_SYSREG_H
#define __ASM_SYSREG_H

#include <linux/stringify.h>
#include <linux/types.h>

/*
 * Unlike read_cpuid, calls to read_sysreg are never expected to be
 * optimized away or replaced with synthetic values.
 */
#define read_sysreg(r) ({					\
	u64 __val;						\
	asm volatile("mrs %0, " __stringify(r) : "=r" (__val));	\
	__val;							\
})

#define write_sysreg(v, r) do {					\
	u64 __val = (u64)v;					\
	asm volatile("msr " __stringify(r) ", %0"		\
		     : : "r" (__val));				\
} while (0)

#endif	/* __ASM_SYSREG_H */