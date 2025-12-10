/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __bitmap_set
#define __bitmap_set(a, b, c)	bitmap_set(a, b, c)
#endif

#ifndef __bitmap_clear
#define __bitmap_clear(a, b, c)	bitmap_clear(a, b, c)
#endif

/*
 * Copy from include/linux/compiler_attributes.h
 */
#ifndef __has_attribute
#define __has_attribute(x) 0
#endif

#ifndef fallthrough
#if __has_attribute(__fallthrough__)
#define fallthrough __attribute__((__fallthrough__))
#else
#define fallthrough do {} while (0)  /* fallthrough */
#endif
#endif

#ifdef __GENKSYMS__
/* genksyms gets confused by _Static_assert */
#define _Static_assert(expr, ...)
#endif

/*
 * Copy from include/linux/build_bug.h
 */
#define SECTOR_SHIFT 9

#ifndef static_assert
#define static_assert(expr, ...) __static_assert(expr, ##__VA_ARGS__, #expr)
#define __static_assert(expr, msg, ...) _Static_assert(expr, msg)
#endif

/*
 * Copy from include/linux/overflow.h
 */
#ifndef struct_size
#define struct_size(p, member, n) (sizeof(*(p)) + n * sizeof(*(p)->member))
#endif

/* Account to memcg */
#ifdef CONFIG_MEMCG_KMEM
# define SLAB_ACCOUNT		((slab_flags_t __force)0x04000000U)
#else
# define SLAB_ACCOUNT		0
#endif

#ifndef mul_u32_u32
/*
 * Many a GCC version messes this up and generates a 64x64 mult :-(
 */
static inline u64 mul_u32_u32(u32 a, u32 b)
{
	return (u64)a * b;
}
#endif

#if defined(CONFIG_ARCH_SUPPORTS_INT128) && defined(__SIZEOF_INT128__)

#ifndef mul_u64_u32_shr
static inline u64 mul_u64_u32_shr(u64 a, u32 mul, unsigned int shift)
{
	return (u64)(((unsigned __int128)a * mul) >> shift);
}
#endif /* mul_u64_u32_shr */

#else

#ifndef mul_u64_u32_shr
static inline u64 mul_u64_u32_shr(u64 a, u32 mul, unsigned int shift)
{
	u32 ah, al;
	u64 ret;

	al = a;
	ah = a >> 32;

	ret = mul_u32_u32(al, mul) >> shift;
	if (ah)
		ret += mul_u32_u32(ah, mul) << (32 - shift);

	return ret;
}
#endif /* mul_u64_u32_shr */

#endif