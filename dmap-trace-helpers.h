#ifndef __DMAP_TRACE_HELPERS_H__
#define __DMAP_TRACE_HELPERS_H__

void dmap_trace_printf(const char *fmt, ...);

void dmap_trace_error(int err, const char *fmt, ...);

#define TRACE(fmt, ...)						\
do {								\
	dmap_trace_printf("%s: " fmt,				\
				__func__, ##__VA_ARGS__);	\
} while (false)

#define TRACE_ERR(err, fmt, ...)			\
do {							\
	dmap_trace_error(err, "%s: " fmt,		\
			      __func__, ##__VA_ARGS__);	\
} while (false)

#define TRACE_VERBOSE(fmt, ...)

#endif
