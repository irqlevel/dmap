#ifndef __DMAP_H__
#define __DMAP_H__

#include "dmap-const.h"
#include "dmap-helpers.h"
#include "dmap-sysfs.h"
#include "dmap-connection.h"
#include "dmap-server.h"

struct dmap {
	struct rw_semaphore rw_sem;
	struct dmap_kobject_holder kobj_holder;
	struct dmap_server server;
	char id[DMAP_ID_SIZE];
	struct list_head neighbor_list;
};

int dmap_add_neighbor(struct dmap *map, char *host, int port);

int dmap_remove_neighbor(struct dmap *map, char *host);

#endif
