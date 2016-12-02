#ifndef __DMAP_HELPERS_H__
#define __DMAP_HELPERS_H__

#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/module.h>

#define PRINTK(fmt, ...)    \
		pr_info("dmap: " fmt, ##__VA_ARGS__)

#define PRINTKE(fmt, ...)    \
		pr_err("dmap: " fmt, ##__VA_ARGS__)

unsigned long dmap_hash_pointer(void *ptr);

const char *dmap_truncate_file_name(const char *file_name);

char dmap_byte_to_hex(unsigned char c);

void dmap_bytes_to_hex(unsigned char *src, int slen, char *dst, int dlen);

unsigned char dmap_hex_to_byte(char c);

int dmap_hex_to_bytes(char *hex, int hex_len, unsigned char *dst,
		       int dst_len);

#endif
