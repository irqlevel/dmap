#ifndef __DMAP_HELPERS_H__
#define __DMAP_HELPERS_H__

#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/module.h>

unsigned long dmap_hash_pointer(void *ptr);

const char *dmap_truncate_file_name(const char *file_name);

#define PRINTK(fmt, ...)    \
		pr_info("dmap: " fmt, ##__VA_ARGS__)

#define PRINTKE(fmt, ...)    \
		pr_err("dmap: " fmt, ##__VA_ARGS__)

int dmap_hex_to_byte(unsigned char c);

int dmap_hex_to_bytes(char *hex, int hex_len, unsigned char *dst,
		       int dst_len);

#endif
