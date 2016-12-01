#include "dmap-server.h"

int dmap_server_init(struct dmap_server *srv)
{
	memset(srv, 0, sizeof(*srv));
	mutex_init(&srv->mutex);
	return 0;
}

int dmap_server_start(struct dmap_server *srv, char *host, int port)
{
	int r;

	mutex_lock(&srv->mutex);
	snprintf(srv->host, ARRAY_SIZE(srv->host), "%s", host);
	srv->port = port;
	r = 0;
	mutex_unlock(&srv->mutex);
	return r;
}

int dmap_server_stop(struct dmap_server *srv)
{
	int r;

	mutex_lock(&srv->mutex);
	r = 0;
	mutex_unlock(&srv->mutex);
	return r;
}

void dmap_server_deinit(struct dmap_server *srv)
{
	dmap_server_stop(srv);
}
