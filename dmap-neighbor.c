#include "dmap-neighbor.h"
#include "dmap-malloc.h"
#include "dmap.h"

static void dmap_neighbor_free(struct dmap_neighbor *neighbor)
{
	destroy_workqueue(neighbor->wq);
	dmap_con_deinit(&neighbor->con);
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

static void dmap_neighbor_set_state(struct dmap_neighbor *neighbor, int state)
{
	neighbor->state = state;
}

static int dmap_neighbor_connect(struct dmap_neighbor *neighbor)
{
	int r;

	r = dmap_con_connect(&neighbor->con, neighbor->addr.host,
			     neighbor->addr.port);
	if (r) {
		if (r == -EEXIST)
			return 0;

		dmap_neighbor_set_state(neighbor, DMAP_NEIGHBOR_S_BROKEN);
		return r;
	}

	return 0;
}

int dmap_neighbor_hello(struct dmap_neighbor *neighbor)
{
	struct dmap_req_hello *req =
		(struct dmap_req_hello *)neighbor->request.body;
	struct dmap_resp_hello *resp =
		(struct dmap_resp_hello *)neighbor->response.body;
	int r;

	mutex_lock(&neighbor->mutex);
	r = dmap_neighbor_connect(neighbor);
	if (r)
		goto unlock;

	dmap_get_address(neighbor->map, &req->source);

	r = dmap_con_send(&neighbor->con, DMAP_PACKET_HELLO, sizeof(*req), 0,
			  &neighbor->request);
	if (r)
		goto unlock;

	r = dmap_con_recv_check(&neighbor->con, &neighbor->response,
				DMAP_PACKET_HELLO, sizeof(*resp));
	if (r)
		dmap_neighbor_set_state(neighbor, DMAP_NEIGHBOR_S_BROKEN);
	else {
		memcpy(neighbor->addr.id, resp->addr.id,
		       sizeof(neighbor->addr.id));
		memcpy(neighbor->addr.id_str, resp->addr.id_str,
		       sizeof(neighbor->addr.id_str));
		dmap_neighbor_set_state(neighbor, DMAP_NEIGHBOR_S_HELLO);
	}

unlock:
	mutex_unlock(&neighbor->mutex);
	return r;
}

int dmap_neighbor_bye(struct dmap_neighbor *neighbor)
{
	struct dmap_req_bye *req =
		(struct dmap_req_bye *)neighbor->request.body;
	struct dmap_resp_bye *resp =
		(struct dmap_resp_bye *)neighbor->response.body;
	int r;

	mutex_lock(&neighbor->mutex);
	r = dmap_neighbor_connect(neighbor);
	if (r)
		goto unlock;

	dmap_get_address(neighbor->map, &req->source);

	r = dmap_con_send(&neighbor->con, DMAP_PACKET_BYE, sizeof(*req), 0,
			  &neighbor->request);
	if (r)
		goto unlock;

	r = dmap_con_recv_check(&neighbor->con, &neighbor->response,
				DMAP_PACKET_BYE, sizeof(*resp));
	if (r)
		dmap_neighbor_set_state(neighbor, DMAP_NEIGHBOR_S_BROKEN);

unlock:
	mutex_unlock(&neighbor->mutex);
	return r;
}

int dmap_neighbor_ping(struct dmap_neighbor *neighbor)
{
	struct dmap_req_ping *req =
		(struct dmap_req_ping *)neighbor->request.body;
	struct dmap_resp_ping *resp =
		(struct dmap_resp_ping *)neighbor->response.body;
	int r;

	mutex_lock(&neighbor->mutex);
	r = dmap_neighbor_connect(neighbor);
	if (r)
		goto unlock;

	dmap_get_address(neighbor->map, &req->source);

	r = dmap_con_send(&neighbor->con, DMAP_PACKET_PING, sizeof(*req), 0,
			  &neighbor->request);
	if (r)
		goto unlock;

	r = dmap_con_recv_check(&neighbor->con, &neighbor->response,
				DMAP_PACKET_PING, sizeof(*resp));
	if (r)
		dmap_neighbor_set_state(neighbor, DMAP_NEIGHBOR_S_BROKEN);

unlock:
	mutex_unlock(&neighbor->mutex);
	return r;
}

struct dmap_neighbor *dmap_neighbor_create(struct dmap *map,
					   char *host, int port)
{
	struct dmap_neighbor *neighbor;
	int r;

	neighbor = dmap_kzalloc(sizeof(*neighbor), GFP_KERNEL);
	if (!neighbor)
		return NULL;

	neighbor->map = map;
	mutex_init(&neighbor->mutex);
	INIT_LIST_HEAD(&neighbor->list);
	atomic_set(&neighbor->ref_count, 1);
	snprintf(neighbor->addr.host, ARRAY_SIZE(neighbor->addr.host),
		 "%s", host);
	neighbor->addr.port = port;
	neighbor->state = DMAP_NEIGHBOR_S_INIT;

	r = dmap_con_init(&neighbor->con);
	if (r)
		goto free_neighbor;

	neighbor->wq = alloc_workqueue("dmap-neighbor-wq", WQ_MEM_RECLAIM, 0);
	if (!neighbor->wq)
		goto deinit_con;

	return neighbor;

deinit_con:
	dmap_con_deinit(&neighbor->con);
free_neighbor:
	dmap_kfree(neighbor);
	return NULL;
}
