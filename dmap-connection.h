#ifndef __DMAP_CONNECTION_H__
#define __DMAP_CONNECTION_H__

#include "dmap-const.h"
#include <linux/mutex.h>

#define DMAP_PACKET_MAGIC	0xCBEECBEE

#define DMAP_PACKET_BODY_SIZE	65520

#define DMAP_PACKET_SET_KEY	1
#define DMAP_PACKET_GET_KEY	2
#define DMAP_PACKET_DEL_KEY	3
#define DMAP_PACKET_HELLO	4
#define DMAP_PACKET_PING	5
#define DMAP_PACKET_BYE		6

struct dmap_packet_header {
	__le32 magic;
	__le32 type;
	__le32 len;
	__le32 result;
};

struct dmap_packet {
	struct dmap_packet_header header;
	unsigned char body[DMAP_PACKET_BODY_SIZE];
};

struct dmap_req_set_key {
	unsigned char key[DMAP_KEY_SIZE];
	unsigned char value[DMAP_VALUE_SIZE];
};

struct dmap_resp_set_key {
	__le64 padding;
};

struct dmap_req_get_key {
	unsigned char key[DMAP_KEY_SIZE];
};

struct dmap_resp_get_key {
	unsigned char value[DMAP_VALUE_SIZE];
};

struct dmap_req_del_key {
	unsigned char key[DMAP_KEY_SIZE];
};

struct dmap_resp_del_key {
	__le64 padding;
};

struct dmap_req_hello {
	struct dmap_address source;
};

struct dmap_resp_hello {
	__le64 padding;
};

struct dmap_req_ping {
	struct dmap_address source;
};

struct dmap_resp_ping {
	__le64 padding;
};

struct dmap_req_bye {
	struct dmap_address source;
};

struct dmap_resp_bye {
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

int dmap_con_set_socket(struct dmap_connection *con, struct socket *sock);

int dmap_con_close(struct dmap_connection *con);

int dmap_con_send(struct dmap_connection *con, u32 type, u32 len,
		  u32 result, struct dmap_packet *packet);

int dmap_con_recv(struct dmap_connection *con, struct dmap_packet *packet,
		  u32 *type, u32 *len, u32 *result);

#endif
