#include "dmap-neighbor.h"
#include "dmap-malloc.h"

static void dmap_neighbor_free(struct dmap_neighbor *neighbor)
{
	dmap_kfree(neighbor);
}

void dmap_neighbor_put(struct dmap_neighbor *neighbor)
{
	if (atomic_dec_and_test(&neighbor->ref_count))
		dmap_neighbor_free(neighbor);
}

void dmap_neighbor_get(struct dmap_neighbor *neighbor)
{
	atomic_inc(&neighbor->ref_count);
}

struct dmap_neighbor *dmap_neighbor_create(char *host, int port)
{
	struct dmap_neighbor *neighbor;

	neighbor = dmap_kzalloc(sizeof(*neighbor), GFP_KERNEL);
	if (!neighbor)
		return NULL;

	INIT_LIST_HEAD(&neighbor->list);
	atomic_set(&neighbor->ref_count, 1);
	snprintf(neighbor->host, ARRAY_SIZE(neighbor->host), "%s", host);
	neighbor->port = port;
	neighbor->state = DMAP_NEIGHBOR_STATE_INIT;

	return neighbor;
}
