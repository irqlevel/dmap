#ifndef __DMAP_H__
#define __DMAP_H__

#include <linux/kernel.h>
#include <linux/device-mapper.h>
#include <linux/mutex.h>
#include <linux/kobject.h>
#include <linux/zlib.h>
#include <linux/net.h>
#include <linux/radix-tree.h>
#include <linux/hrtimer.h>

#include "dmap-helpers.h"

#define MEGA_BYTE			(1024ULL * 1024ULL)

struct dmap_kobject_holder {
	struct kobject kobj;
	struct completion completion;
	atomic_t deiniting;
};

struct dmap_req_header {
	__le32 magic;
	__le32 type;
	__le32 len;
	__le32 padding;
};

struct dmap_resp_header {
	__le32 magic;
	__le32 type;
	__le32 len;
	__le32 result;
};

#define DMAP_REQ_MAGIC		0xCBEECBEE
#define DMAP_RESP_MAGIC		0xCBDACBDA

#define DMAP_REQ_BODY_MAX	65536
#define DMAP_RESP_BODY_MAX	65536

#define DMAP_KEY_BYTES		32
#define DMAP_VALUE_BYTES	4096
#define DMAP_HOST_BYTES		256

struct dmap_req_set_key {
	char key[DMAP_KEY_BYTES];
	char value[DMAP_VALUE_BYTES];
};

struct dmap_resp_set_key {
	__le64 padding;
};

struct dmap_req_get_key {
	char key[DMAP_KEY_BYTES];
};

struct dmap_resp_get_key {
	char value[DMAP_VALUE_BYTES];
};

struct dmap_req_del_key {
	char key[DMAP_KEY_BYTES];
};

struct dmap_resp_del_key {
	__le64 padding;
};

struct dmap_connection {
	struct rw_semaphore rw_sem;
	struct socket *sock;
	char host[DMAP_HOST_BYTES];
	u16 port;
};

struct dmap;

struct dmap_queue {
	struct dmap *dmap;
	wait_queue_head_t waitq;
	rwlock_t lock;
	struct list_head req_list;
	struct task_struct *thread;
	int index;
};

struct dmap {
	struct rw_semaphore rw_sem;
	struct dmap_kobject_holder kobj_holder;
};

void *dmap_kzalloc(size_t size, gfp_t flags);

void *dmap_kcalloc(size_t n, size_t size, gfp_t flags);

void *dmap_kmalloc(size_t size, gfp_t flags);

void dmap_kfree(void *ptr);

#endif
