#ifndef __DMAP_NEIGHBOR_H__
#define __DMAP_NEIGHBOR_H__

#include "dmap-const.h"
#include "dmap-connection.h"

enum {
	DMAP_NEIGHBOR_S_INIT = 1,
	DMAP_NEIGHBOR_S_HELLO = 3,
	DMAP_NEIGHBOR_S_BROKEN = 4,
};

struct dmap;

struct dmap_neighbor {
	struct dmap *map;
	struct mutex mutex;
	struct list_head list;
	struct dmap_address addr;
	int state;
	atomic_t ref_count;
	struct dmap_connection con;
	struct dmap_packet request;
	struct dmap_packet response;
	u64 ping_us;
};

void dmap_neighbor_put(struct dmap_neighbor *neighbor);

void dmap_neighbor_get(struct dmap_neighbor *neighbor);

struct dmap_neighbor *dmap_neighbor_create(struct dmap *map,
					   char *host, int port);

int dmap_neighbor_hello(struct dmap_neighbor *neighbor);

int dmap_neighbor_bye(struct dmap_neighbor *neighbor);

int dmap_neighbor_ping(struct dmap_neighbor *neighbor);

void dmap_neighbor_set_state(struct dmap_neighbor *neighbor, int state);

#endif
