#ifndef __DMAP_CONNECTION_H__
#define __DMAP_CONNECTION_H__

#include "dmap.h"

int dmap_con_init(struct dmap_connection *con);

void dmap_con_deinit(struct dmap_connection *con);

int dmap_con_connect(struct dmap_connection *con, char *host, u16 port);

int dmap_con_close(struct dmap_connection *con);

#endif
