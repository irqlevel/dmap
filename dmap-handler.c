#include "dmap-handler.h"
#include "dmap-neighbor.h"
#include "dmap-trace-helpers.h"
#include "dmap-hash.h"
#include "dmap-sha256.h"

static int dmap_handle_hello(struct dmap *map, struct dmap_req_hello *req,
			     struct dmap_resp_hello *resp)
{
	int r;

	r = dmap_check_address(&req->source);
	if (r)
		return r;

	TRACE("hello %s:%d %s",
	      req->source.host, req->source.port, req->source.id_str);

	r = dmap_add_neighbor(map, &req->source, true);
	if (r) {
		if (r == -EEXIST)
			r = 0;
		else
			return r;
	}

	dmap_get_address(map, &resp->addr);
	return 0;
}

static int dmap_handle_ping(struct dmap *map, struct dmap_req_ping *req,
			    struct dmap_resp_ping *resp)
{
	struct dmap_neighbor *neighbor;
	int r;

	r = dmap_check_address(&req->source);
	if (r)
		return r;


	TRACE("ping %s:%d %s",
	      req->source.host, req->source.port, req->source.id_str);

	neighbor = dmap_lookup_neighbor(map, &req->source);
	if (!neighbor)
		return -ENOTTY;

	dmap_neighbor_put(neighbor);
	return 0;
}

static int dmap_handle_bye(struct dmap *map, struct dmap_req_bye *req,
			   struct dmap_resp_bye *resp)
{
	struct dmap_neighbor *neighbor;
	int r;

	r = dmap_check_address(&req->source);
	if (r)
		return r;

	TRACE("bye %s:%d %s",
	      req->source.host, req->source.port, req->source.id_str);

	neighbor = dmap_lookup_neighbor(map, &req->source);
	if (!neighbor)
		return -ENOTTY;

	r = dmap_erase_neighbor(map, neighbor);

	dmap_neighbor_put(neighbor);
	return r;
}

static int dmap_handle_set_key(struct dmap *map, struct dmap_req_set_key *req,
			   struct dmap_resp_set_key *resp)
{
	unsigned char hash[32];
	struct dmap_neighbor *neighbor;
	int r;

	sha256(req->key, sizeof(req->key), hash);

	neighbor = dmap_select_neighbor(map, hash);
	if (WARN_ON(neighbor == NULL))
		return -ENOTTY;

	if (dmap_is_self_neighbor(map, neighbor))
		r = dmap_hash_insert(&map->hash, req->key, sizeof(req->key),
				req->value, sizeof(req->value));
	else
		r = dmap_neighbor_set_key(neighbor, req, resp);

	TRACE("set key: %16phN r: %d", req->key, hash, r);

	return r;
}

static int dmap_handle_get_key(struct dmap *map, struct dmap_req_get_key *req,
			   struct dmap_resp_get_key *resp)
{
	struct dmap_neighbor *neighbor;
	unsigned char hash[32];
	int r;
	size_t value_len;

	sha256(req->key, sizeof(req->key), hash);

	neighbor = dmap_select_neighbor(map, hash);
	if (WARN_ON(neighbor == NULL))
		return -ENOTTY;

	if (dmap_is_self_neighbor(map, neighbor))
		r = dmap_hash_get(&map->hash, req->key, sizeof(req->key),
			  resp->value, sizeof(resp->value), &value_len);
	else
		r = dmap_neighbor_get_key(neighbor, req, resp);

	TRACE("get key: %16phN value: %16phN r: %d", req->key, resp->value);


	return r;
}

static int dmap_handle_del_key(struct dmap *map, struct dmap_req_del_key *req,
			   struct dmap_resp_del_key *resp)
{
	struct dmap_neighbor *neighbor;
	unsigned char hash[32];
	int r;

	sha256(req->key, sizeof(req->key), hash);

	neighbor = dmap_select_neighbor(map, hash);
	if (WARN_ON(neighbor == NULL))
		return -ENOTTY;

	if (dmap_is_self_neighbor(map, neighbor))
		r = dmap_hash_delete(&map->hash, req->key, sizeof(req->key));
	else
		r = dmap_neighbor_del_key(neighbor, req, resp);

	TRACE("del key: %16phN r: %d", req->key, r);

	return r;
}

static int dmap_handle_upd_key(struct dmap *map, struct dmap_req_upd_key *req,
			   struct dmap_resp_upd_key *resp)
{
	unsigned char hash[32];
	struct dmap_neighbor *neighbor;
	int r;

	sha256(req->key, sizeof(req->key), hash);

	neighbor = dmap_select_neighbor(map, hash);
	if (WARN_ON(neighbor == NULL))
		return -ENOTTY;

	if (dmap_is_self_neighbor(map, neighbor))
		r = dmap_hash_update(&map->hash, req->key, sizeof(req->key),
				req->value, sizeof(req->value));
	else
		r = dmap_neighbor_upd_key(neighbor, req, resp);

	TRACE("update key: %16phN r: %d", req->key, hash, r);

	return r;
}

static int dmap_handle_cmpxchg_key(struct dmap *map,
				struct dmap_req_cmpxchg_key *req,
				struct dmap_resp_cmpxchg_key *resp)
{
	unsigned char hash[32];
	struct dmap_neighbor *neighbor;
	size_t value_len;
	int r;

	sha256(req->key, sizeof(req->key), hash);

	neighbor = dmap_select_neighbor(map, hash);
	if (WARN_ON(neighbor == NULL))
		return -ENOTTY;

	if (dmap_is_self_neighbor(map, neighbor))
		r = dmap_hash_cmpxchg(&map->hash, req->key, sizeof(req->key),
				req->exchange, sizeof(req->exchange),
				req->comparand, sizeof(req->comparand),
				resp->value, sizeof(resp->value), &value_len);
	else
		r = dmap_neighbor_cmpxchg_key(neighbor, req, resp);

	TRACE("cmpxchg key: %16phN r: %d", req->key, hash, r);

	return r;
}

int dmap_handle_request(struct dmap *map, u32 type, void *req_body, u32 req_len,
			void *resp_body, u32 *resp_len)
{
	int r;

	switch (type) {
	case DMAP_PACKET_HELLO: {
		struct dmap_req_hello *req = req_body;
		struct dmap_resp_hello *resp = resp_body;

		if (req_len != sizeof(*req)) {
			r = -EINVAL;
			break;
		}

		r = dmap_handle_hello(map, req, resp);

		*resp_len = sizeof(*resp);
		break;
	}
	case DMAP_PACKET_PING: {
		struct dmap_req_ping *req = req_body;
		struct dmap_resp_ping *resp = resp_body;

		if (req_len != sizeof(*req)) {
			r = -EINVAL;
			break;
		}

		r = dmap_handle_ping(map, req, resp);

		*resp_len = sizeof(*resp);
		break;
	}
	case DMAP_PACKET_BYE: {
		struct dmap_req_bye *req = req_body;
		struct dmap_resp_bye *resp = resp_body;

		if (req_len != sizeof(*req)) {
			r = -EINVAL;
			break;
		}

		r = dmap_handle_bye(map, req, resp);

		*resp_len = sizeof(*resp);
		break;
	}
	case DMAP_PACKET_SET_KEY: {
		struct dmap_req_set_key *req = req_body;
		struct dmap_resp_set_key *resp = resp_body;

		if (req_len != sizeof(*req)) {
			r = -EINVAL;
			break;
		}

		r = dmap_handle_set_key(map, req, resp);

		*resp_len = sizeof(*resp);
		break;
	}
	case DMAP_PACKET_GET_KEY: {
		struct dmap_req_get_key *req = req_body;
		struct dmap_resp_get_key *resp = resp_body;

		if (req_len != sizeof(*req)) {
			r = -EINVAL;
			break;
		}

		r = dmap_handle_get_key(map, req, resp);

		*resp_len = sizeof(*resp);
		break;
	}
	case DMAP_PACKET_DEL_KEY: {
		struct dmap_req_del_key *req = req_body;
		struct dmap_resp_del_key *resp = resp_body;

		if (req_len != sizeof(*req)) {
			r = -EINVAL;
			break;
		}

		r = dmap_handle_del_key(map, req, resp);

		*resp_len = sizeof(*resp);
		break;
	}
	case DMAP_PACKET_UPD_KEY: {
		struct dmap_req_upd_key *req = req_body;
		struct dmap_resp_upd_key *resp = resp_body;

		if (req_len != sizeof(*req)) {
			r = -EINVAL;
			break;
		}

		r = dmap_handle_upd_key(map, req, resp);

		*resp_len = sizeof(*resp);
		break;
	}
	case DMAP_PACKET_CMPXCHG_KEY: {
		struct dmap_req_cmpxchg_key *req = req_body;
		struct dmap_resp_cmpxchg_key *resp = resp_body;

		if (req_len != sizeof(*req)) {
			r = -EINVAL;
			break;
		}

		r = dmap_handle_cmpxchg_key(map, req, resp);

		*resp_len = sizeof(*resp);
		break;
	}
	default:
		r = -EINVAL;
		TRACE_ERR(r, "unsupported request type %d", type);
		break;
	}

	if (r)
		*resp_len = 0;

	return r;
}
