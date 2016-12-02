#include "dmap-helpers.h"

unsigned long dmap_hash_pointer(void *ptr)
{
	unsigned long val = (unsigned long)ptr;
	unsigned long hash, i, c;

	hash = 5381;
	val = val >> 3;
	for (i = 0; i < sizeof(val); i++) {
		c = (unsigned char)val & 0xFF;
		hash = ((hash << 5) + hash) + c;
		val = val >> 8;
	}

	return hash;
}

const char *dmap_truncate_file_name(const char *file_name)
{
	char *base;

	base = strrchr(file_name, '/');
	if (base)
		return ++base;
	else
		return file_name;
}

char dmap_byte_to_hex(unsigned char c)
{
	if (WARN_ON(c > 15))
		return '0';

	if (c < 10)
		return '0' + c;
	else
		return 'a' + c - 10;
}

void dmap_bytes_to_hex(unsigned char *src, int slen, char *dst, int dlen)
{
	int i;

	if (WARN_ON(dlen < (2 * slen + 1)))
		return;

	for (i = 0; i < slen; i++) {
		dst[2 * i] = dmap_byte_to_hex((src[i] >> 4) & 0xF);
		dst[2 * i + 1] = dmap_byte_to_hex(src[i] & 0xF);
	}

	dst[2 * slen] = '\0';
}

unsigned char dmap_hex_to_byte(char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	else
		return -1;
}

int dmap_hex_to_bytes(char *hex, int hex_len, unsigned char *dst,
		       int dst_len)
{
	int i, pos;
	int low, high;

	if (hex_len <= 0 || dst_len <= 0)
		return -EINVAL;

	if (hex_len & 1)
		return -EINVAL;

	if (dst_len != hex_len/2)
		return -EINVAL;

	for (i = 0, pos = 0; i < hex_len; i += 2, pos += 1) {
		high = dmap_hex_to_byte(hex[i]);
		low = dmap_hex_to_byte(hex[i + 1]);
		if (high == -1 || low == -1)
			return -EINVAL;
		dst[pos] = (high << 4) + low;
	}

	return 0;
}
