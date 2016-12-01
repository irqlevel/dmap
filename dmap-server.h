#ifndef __DMAP_SERVER_H__
#define __DMAP_SERVER_H__

#include "dmap-const.h"
#include "ksocket.h"

#include <linux/mutex.h>

struct dmap_server {
	struct mutex mutex;
	char host[DMAP_HOST_SIZE];
	int port;

	struct task_struct *thread;
	struct socket *sock;
	bool stopping;
};

int dmap_server_init(struct dmap_server *srv);

int dmap_server_start(struct dmap_server *srv, char *host, int port);

int dmap_server_stop(struct dmap_server *srv);

void dmap_server_deinit(struct dmap_server *srv);

#endif
