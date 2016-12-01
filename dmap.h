#ifndef __DMAP_H__
#define __DMAP_H__

#include "dmap-const.h"
#include "dmap-helpers.h"
#include "dmap-sysfs.h"
#include "dmap-connection.h"
#include "dmap-server.h"

struct dmap {
	struct rw_semaphore rw_sem;
	struct dmap_kobject_holder kobj_holder;
	struct dmap_server server;
};

#endif
