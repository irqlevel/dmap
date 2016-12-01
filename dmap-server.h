#ifndef __DMAP_SERVER_H__
#define __DMAP_SERVER_H__

#include "dmap-const.h"
#include "dmap-connection.h"

#include "ksocket.h"

#include <linux/mutex.h>

struct dmap_server;

struct dmap_server_con {
	struct dmap_server *srv;
	struct mutex mutex;
	struct list_head list;
	struct task_struct *thread;
	struct dmap_connection con;
	struct dmap_packet request;
	struct dmap_packet response;
	bool stopping;
	u64 id;
};

struct dmap_server {
	struct mutex mutex;
	char host[DMAP_HOST_SIZE];
	int port;

	struct task_struct *thread;
	struct socket *sock;
	bool stopping;

	struct list_head con_list;
	atomic64_t next_con_id;
};

int dmap_server_init(struct dmap_server *srv);

int dmap_server_start(struct dmap_server *srv, char *host, int port);

int dmap_server_stop(struct dmap_server *srv);

void dmap_server_deinit(struct dmap_server *srv);

#endif
