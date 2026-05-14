#ifndef _LINUX_TIME64_H
#define _LINUX_TIME64_H

#include <linux/types.h>

#ifndef time64_t
typedef s64 time64_t;
#endif

#ifndef __kernel_time64_t
typedef s64 __kernel_time64_t;
#endif

#ifndef __kernel_old_timeval
struct __kernel_old_timeval {
	__kernel_time_t tv_sec;
	__kernel_suseconds_t tv_usec;
};
#endif

#ifndef timespec64
struct timespec64 {
	time64_t tv_sec;
	long tv_nsec;
};
#endif

#ifndef ktime_get_real_ts64
static inline void ktime_get_real_ts64(struct timespec64 *ts)
{
	struct timeval tv;

	do_gettimeofday(&tv);
	ts->tv_sec = tv.tv_sec;
	ts->tv_nsec = tv.tv_usec * NSEC_PER_USEC;
}
#endif

#ifndef timespec64_to_timespec
static inline struct timespec timespec64_to_timespec(const struct timespec64 ts64)
{
	struct timespec ts;

	ts.tv_sec = (time_t)ts64.tv_sec;
	ts.tv_nsec = ts64.tv_nsec;
	return ts;
}
#endif

#ifndef timespec_to_timespec64
static inline struct timespec64 timespec_to_timespec64(const struct timespec ts)
{
	struct timespec64 ts64;

	ts64.tv_sec = ts.tv_sec;
	ts64.tv_nsec = ts.tv_nsec;
	return ts64;
}
#endif

#endif /* _LINUX_TIME64_H */
