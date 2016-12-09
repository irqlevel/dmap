#ifndef __DMAP_H__
#define __DMAP_H__

#include "dmap-const.h"
#include "dmap-helpers.h"
#include "dmap-sysfs.h"
#include "dmap-connection.h"
#include "dmap-server.h"
#include "dmap-hash.h"
#include "dmap-neighbor.h"

#include <linux/hrtimer.h>

struct dmap {
	struct rw_semaphore rw_sem;
	struct dmap_kobject_holder kobj_holder;
	struct dmap_server server;
	unsigned char id[DMAP_ID_SIZE];
	char id_str[2 * DMAP_ID_SIZE + 1];
	struct list_head neighbor_list;
	struct work_struct ping_work;
	struct workqueue_struct *wq;
	struct hrtimer timer;
	struct dmap_hash hash;
	struct rb_root neighbor_tree;
};

int dmap_add_neighbor(struct dmap *map, struct dmap_address *addr, bool hello);

int dmap_remove_neighbor(struct dmap *map, char *host);

struct dmap_neighbor *dmap_lookup_neighbor(struct dmap *map,
					   struct dmap_address *addr);

int dmap_erase_neighbor(struct dmap *map, struct dmap_neighbor *victim);

void dmap_addr_init(struct dmap_address *addr, char *host, int port,
		unsigned char id[DMAP_ID_SIZE]);

void dmap_get_address(struct dmap *map, struct dmap_address *addr);

int dmap_check_address(struct dmap_address *addr);

struct dmap_neighbor *dmap_select_neighbor(struct dmap *map,
					unsigned char id[DMAP_ID_SIZE]);

bool dmap_is_self_neighbor(struct dmap *map, struct dmap_neighbor *neighbor);

#endif
