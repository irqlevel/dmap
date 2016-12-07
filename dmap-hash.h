#ifndef __DMAP_HASH_H__
#define __DMAP_HASH_H__

#include "dmap-const.h"

#include <linux/rbtree.h>
#include <linux/rwlock.h>

#define DMAP_HASH_SIZE	32768

struct dmap_hash_node {
	struct rb_node link;
	unsigned char *key;
	size_t key_len;
	unsigned char *value;
	size_t value_len;
	atomic_t ref_count;
	bool in_tree;
};

struct dmap_hash_bucket {
	struct rb_root tree;
	rwlock_t lock;
};

struct dmap_hash {
	struct dmap_hash_bucket bucket[DMAP_HASH_SIZE];
};

void dmap_hash_init(struct dmap_hash *hash);

void dmap_hash_deinit(struct dmap_hash *hash);

int dmap_hash_insert(struct dmap_hash *hash, unsigned char *key, size_t key_len,
		unsigned char *value, size_t value_len);

int dmap_hash_get(struct dmap_hash *hash, unsigned char *key, size_t key_len,
		unsigned char *value, size_t value_len, size_t *pvalue_len);

int dmap_hash_delete(struct dmap_hash *hash, unsigned char *key,
		size_t key_len);

#endif
