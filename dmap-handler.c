#include "dmap-handler.h"

static int dmap_handle_hello(struct dmap *map, struct dmap_req_hello *req,
			     struct dmap_resp_hello *resp)
{
	return -EINVAL;
}

static int dmap_handle_ping(struct dmap *map, struct dmap_req_ping *req,
			    struct dmap_resp_ping *resp)
{
	return -EINVAL;
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
	default:
		r = -EINVAL;
		break;
	}

	if (r)
		*resp_len = 0;

	return r;
}


