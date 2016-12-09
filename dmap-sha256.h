#ifndef __DMAP_SHA256_H__
#define __DMAP_SHA256_H__

#include <linux/kernel.h>
#include <linux/module.h>

struct sha256_context {
	u32 total[2];
	u32 state[8];
	unsigned char buffer[64];

	unsigned char ipad[64];
	unsigned char opad[64];
};

void sha256_init(struct sha256_context *ctx);

void sha256_starts(struct sha256_context *ctx);

void sha256_update(struct sha256_context *ctx, void *ibuf, size_t ilen);

void sha256_finish(struct sha256_context *ctx, unsigned char output[32]);

void sha256_free(struct sha256_context *ctx);

void sha256(void *input, size_t ilen, unsigned char output[32]);

#endif
