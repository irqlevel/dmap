#ifndef __DMAP_CONST_H__
#define __DMAP_CONST_H__

#include <linux/module.h>

#define DMAP_TIMER_MS		100

#define DMAP_KEY_SIZE		16
#define DMAP_KEY_HEX_SIZE	(2 * DMAP_KEY_SIZE + 1)

#define DMAP_ID_SIZE		16
#define DMAP_VALUE_SIZE		4096
#define DMAP_HOST_SIZE		32

#define DMAP_PARAM_SIZE		64
#define DMAP_PARAM_FMT		"%63s"

struct dmap_address {
	char host[DMAP_HOST_SIZE];
	unsigned char id[DMAP_ID_SIZE];
	char id_str[2 * DMAP_ID_SIZE + 1];
	int port;
};

#endif
