#include "dmap-hash.h"
#include "dmap-malloc.h"

void dmap_hash_init(struct dmap_hash *hash)
{
	struct dmap_hash_bucket *bucket;
	int i;

	atomic64_set(&hash->nr_keys, 0);
	for (i = 0; i < ARRAY_SIZE(hash->bucket); i++) {
		bucket = &hash->bucket[i];
		rwlock_init(&bucket->lock);
		bucket->tree = RB_ROOT;
	}
}

static void dmap_hash_node_put(struct dmap_hash_node *node)
{
	if (atomic_dec_and_test(&node->ref_count)) {
		WARN_ON(node->in_tree);
		dmap_kfree(node->key);
		dmap_kfree(node->value);
		dmap_kfree(node);
	}
}

void dmap_hash_deinit(struct dmap_hash *hash)
{
	struct dmap_hash_bucket *bucket;
	struct dmap_hash_node *node, *tmp;
	int i;

	for (i = 0; i < ARRAY_SIZE(hash->bucket); i++) {
		bucket = &hash->bucket[i];
		rbtree_postorder_for_each_entry_safe(node, tmp,
						&bucket->tree, link) {
			node->in_tree = false;
			dmap_hash_node_put(node);
		}
	}
}

static void dmap_hash_node_get(struct dmap_hash_node *node)
{
	atomic_inc(&node->ref_count);
}

static struct dmap_hash_node *dmap_hash_node_create(
				unsigned char *key, size_t key_len,
				unsigned char *value, size_t value_len)
{
	struct dmap_hash_node *node;

	if (WARN_ON(key_len == 0 || key_len > DMAP_KEY_SIZE))
		return NULL;
	if (WARN_ON(value_len == 0 || value_len > DMAP_VALUE_SIZE))
		return NULL;

	node = dmap_kmalloc(sizeof(*node), GFP_KERNEL);
	if (!node)
		return NULL;

	atomic_set(&node->ref_count, 1);

	node->key = dmap_kmalloc(key_len, GFP_KERNEL);
	if (!node->key)
		goto free_node;

	node->value = dmap_kmalloc(value_len, GFP_KERNEL);
	if (!node->value)
		goto free_key;

	node->in_tree = false;
	node->key_len = key_len;
	memcpy(node->key, key, node->key_len);
	node->value_len = value_len;
	memcpy(node->value, value, node->value_len);

	return node;

free_key:
	dmap_kfree(node->key);
free_node:
	dmap_kfree(node);
	return NULL;
}

static unsigned long dmap_hash_get_hash(unsigned char *key, size_t key_len)
{
	unsigned long hash = 5381;
	size_t i;
	int c;

	for (i = 0; i < key_len; i++) {
		c = key[i];
		hash = ((hash << 5) + hash) + c;
	}

	return hash;
}

static int dmap_hash_compare_key(unsigned char *key1, size_t key1_len,
			unsigned char *key2, size_t key2_len)
{
	if (key1_len < key2_len)
		return -1;
	if (key1_len > key2_len)
		return 1;

	return memcmp(key1, key2, key1_len);
}

static int dmap_hash_insert_node(struct dmap_hash *hash,
				struct dmap_hash_node *node)
{
	struct dmap_hash_bucket *bucket;
	struct dmap_hash_node *curr;
	struct rb_node **p;
	struct rb_node *parent;
	int i, cmp;
	bool exist;

	i = dmap_hash_get_hash(node->key, node->key_len);
	bucket = &hash->bucket[i % ARRAY_SIZE(hash->bucket)];
	exist = false;
	parent = NULL;
	write_lock(&bucket->lock);
	p = &bucket->tree.rb_node;
	while (*p) {
		parent = *p;
		curr = rb_entry(parent, struct dmap_hash_node, link);
		cmp = dmap_hash_compare_key(node->key, node->key_len,
					curr->key, curr->key_len);
		if (cmp < 0)
			p = &(*p)->rb_left;
		else if (cmp > 0)
			p = &(*p)->rb_right;
		else {
			exist = true;
			break;
		}
	}
	if (!exist) {
		rb_link_node(&node->link, parent, p);
		rb_insert_color(&node->link, &bucket->tree);
		node->in_tree = true;
		dmap_hash_node_get(node);
		atomic64_inc(&hash->nr_keys);
	}
	write_unlock(&bucket->lock);

	return (exist) ? -EEXIST : 0;
}

static struct dmap_hash_node *dmap_hash_lookup_node(struct dmap_hash *hash,
					unsigned char *key, size_t key_len)
{
	struct dmap_hash_bucket *bucket;
	struct dmap_hash_node *node, *found;
	struct rb_node *n;
	int i, cmp;

	found = NULL;
	i = dmap_hash_get_hash(key, key_len);
	bucket = &hash->bucket[i % ARRAY_SIZE(hash->bucket)];

	read_lock(&bucket->lock);
	n = bucket->tree.rb_node;
	while (n) {
		node = rb_entry(n, struct dmap_hash_node, link);
		cmp = dmap_hash_compare_key(key, key_len, node->key,
					node->key_len);
		if (cmp < 0)
			n = n->rb_left;
		else if (cmp > 0)
			n = n->rb_right;
		else {
			found = node;
			dmap_hash_node_get(found);
			break;
		}
	}
	read_unlock(&bucket->lock);

	return found;
}

static int dmap_hash_delete_node(struct dmap_hash *hash,
			struct dmap_hash_node *node)
{
	struct dmap_hash_bucket *bucket;
	int i, r;

	r = -ENOTTY;
	i = dmap_hash_get_hash(node->key, node->key_len);
	bucket = &hash->bucket[i % ARRAY_SIZE(hash->bucket)];

	write_lock(&bucket->lock);
	if (node->in_tree) {
		rb_erase(&node->link, &bucket->tree);
		atomic64_dec(&hash->nr_keys);
		node->in_tree = false;
		r = 0;
	}
	write_unlock(&bucket->lock);

	if (!r)
		dmap_hash_node_put(node);

	return r;
}

int dmap_hash_insert(struct dmap_hash *hash, unsigned char *key, size_t key_len,
		unsigned char *value, size_t value_len)
{
	struct dmap_hash_node *node;
	int r;

	if (key_len == 0 || key_len > DMAP_KEY_SIZE)
		return -EINVAL;
	if (value_len == 0 || value_len > DMAP_VALUE_SIZE)
		return -EINVAL;

	node = dmap_hash_node_create(key, key_len, value, value_len);
	if (!node)
		return -ENOMEM;

	r = dmap_hash_insert_node(hash, node);

	dmap_hash_node_put(node);
	return r;
}

int dmap_hash_get(struct dmap_hash *hash, unsigned char *key, size_t key_len,
		unsigned char *value, size_t value_len, size_t *pvalue_len)
{
	struct dmap_hash_node *node;
	int r;

	if (key_len == 0 || key_len > DMAP_KEY_SIZE)
		return -EINVAL;
	if (value_len == 0 || value_len > DMAP_VALUE_SIZE)
		return -EINVAL;

	node = dmap_hash_lookup_node(hash, key, key_len);
	if (!node)
		return -ENOTTY;

	if (node->value_len > value_len) {
		r = -E2BIG;
		goto put_node;
	}

	memcpy(value, node->value, node->value_len);
	*pvalue_len = node->value_len;
	r = 0;

put_node:
	dmap_hash_node_put(node);
	return r;
}

int dmap_hash_delete(struct dmap_hash *hash, unsigned char *key,
		size_t key_len)
{
	struct dmap_hash_node *node;
	int r;

	if (key_len == 0 || key_len > DMAP_KEY_SIZE)
		return -EINVAL;

	node = dmap_hash_lookup_node(hash, key, key_len);
	if (!node)
		return -ENOTTY;

	r = dmap_hash_delete_node(hash, node);

	dmap_hash_node_put(node);
	return r;
}
