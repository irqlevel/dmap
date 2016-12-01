#if !defined(_TRACE_DMAP_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_DMAP_H

#include <linux/tracepoint.h>

#undef TRACE_SYSTEM
#define TRACE_SYSTEM dmap

#define DMAP_MSG_CHARS	256

TRACE_EVENT(printf,
	TP_PROTO(const char *fmt, va_list args),
	TP_ARGS(fmt, args),

	TP_STRUCT__entry(
		__dynamic_array(char, message, DMAP_MSG_CHARS)
	),

	TP_fast_assign(
		vsnprintf((char *)__get_str(message),
			  DMAP_MSG_CHARS - 1, fmt, args);
		((char *)__get_str(message))[DMAP_MSG_CHARS - 1] = '\0';
	),

	TP_printk("%s", __get_str(message))
);

TRACE_EVENT(error,
	TP_PROTO(int err, const char *fmt, va_list args),
	TP_ARGS(err, fmt, args),

	TP_STRUCT__entry(
		__dynamic_array(char, message, DMAP_MSG_CHARS)
		__field(int, err)
	),

	TP_fast_assign(
		vsnprintf((char *)__get_str(message),
			  DMAP_MSG_CHARS - 1, fmt, args);
		((char *)__get_str(message))[DMAP_MSG_CHARS - 1] = '\0';
		__entry->err = err;
	),

	TP_printk("%d: %s", __entry->err, __get_str(message))
);

#endif /* _TRACE_DMAP_H */

#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH .
#undef TRACE_INCLUDE_FILE
#define TRACE_INCLUDE_FILE dmap-trace

/* This part must be outside protection */
#include <trace/define_trace.h>
