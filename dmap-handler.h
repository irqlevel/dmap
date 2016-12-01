#ifndef __DMAP_HANDLER_H__
#define __DMAP_HANDLER_H__

#include "dmap.h"

int dmap_handle_request(struct dmap *map, u32 type, void *req_body, u32 req_len,
			void *resp_body, u32 *resp_len);

#endif
