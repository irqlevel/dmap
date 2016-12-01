#ifndef __DMAP_CONNECTION_H__
#define __DMAP_CONNECTION_H__

#include "dmap-const.h"
#include <linux/mutex.h>

#define DMAP_REQ_MAGIC		0xCBEECBEE
#define DMAP_RESP_MAGIC		0xCBDACBDA

#define DMAP_REQ_BODY_MAX	65536
#define DMAP_RESP_BODY_MAX	65536

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

struct dmap_req_set_key {
	char key[DMAP_KEY_SIZE];
	char value[DMAP_VALUE_SIZE];
};

struct dmap_resp_set_key {
	__le64 padding;
};

struct dmap_req_get_key {
	char key[DMAP_KEY_SIZE];
};

struct dmap_resp_get_key {
	char value[DMAP_VALUE_SIZE];
};

struct dmap_req_del_key {
	char key[DMAP_KEY_SIZE];
};

struct dmap_resp_del_key {
	__le64 padding;
};

struct dmap_connection {
	struct mutex mutex;
	struct socket *sock;
	char host[DMAP_HOST_SIZE];
	int port;
};

int dmap_con_init(struct dmap_connection *con);

void dmap_con_deinit(struct dmap_connection *con);

int dmap_con_connect(struct dmap_connection *con, char *host, u16 port);

int dmap_con_close(struct dmap_connection *con);

#endif
