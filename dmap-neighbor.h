#ifndef __DMAP_NEIGHBOR_H__
#define __DMAP_NEIGHBOR_H__

#include "dmap-const.h"

enum {
	DMAP_NEIGHBOR_STATE_INIT = 1,
};

struct dmap_neighbor {
	struct list_head list;
	char id[DMAP_ID_SIZE];
	char host[DMAP_HOST_SIZE];
	int port;
	int state;
	atomic_t ref_count;
};

void dmap_neighbor_put(struct dmap_neighbor *neighbor);

void dmap_neighbor_get(struct dmap_neighbor *neighbor);

struct dmap_neighbor *dmap_neighbor_create(char *host, int port);

#endif
