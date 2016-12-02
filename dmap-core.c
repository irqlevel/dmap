#include <linux/module.h>
#include <linux/init.h>
#include <linux/bio.h>
#include <linux/mutex.h>
#include <linux/bitmap.h>
#include <net/sock.h>
#include <linux/un.h>
#include <linux/uaccess.h>
#include <linux/ioctl.h>
#include <linux/kobject.h>
#include <linux/zlib.h>
#include <linux/vmalloc.h>
#include <linux/bitmap.h>
#include <linux/rwsem.h>
#include <linux/cdrom.h>
#include <linux/kthread.h>
#include <linux/random.h>

#include "malloc-checker.h"
#include "dmap.h"
#include "dmap-sysfs.h"
#include "dmap-connection.h"
#include "dmap-trace-helpers.h"
#include "dmap-helpers.h"
#include "dmap-malloc.h"
#include "dmap-neighbor.h"

static struct dmap global_dmap;

static int dmap_init(struct dmap *map)
{
	int r;

	init_rwsem(&map->rw_sem);
	INIT_LIST_HEAD(&map->neighbor_list);

	get_random_bytes(map->id, sizeof(map->id));

	dmap_bytes_to_hex(map->id, ARRAY_SIZE(map->id),
			  map->id_str, ARRAY_SIZE(map->id_str));

	r = dmap_server_init(&map->server);
	if (r)
		return r;

	r = dmap_sysfs_init(&map->kobj_holder, fs_kobj, &dmap_ktype,
			    "%s", "dmap");
	if (r)
		goto deinit_server;

	return 0;

deinit_server:
	dmap_server_deinit(&map->server);
	return r;
}

static void dmap_deinit(struct dmap *map)
{
	struct dmap_neighbor *curr, *tmp;

	dmap_sysfs_deinit(&map->kobj_holder);
	dmap_server_deinit(&map->server);

	down_write(&map->rw_sem);
	list_for_each_entry_safe(curr, tmp, &map->neighbor_list, list) {
		list_del_init(&curr->list);
		dmap_neighbor_put(curr);
	}
	up_write(&map->rw_sem);
}

static struct dmap *get_dmap(void)
{
	return &global_dmap;
}

int dmap_add_neighbor(struct dmap *map, char *host, int port)
{
	struct dmap_neighbor *new, *curr;
	int r;

	new = dmap_neighbor_create(host, port);
	if (!new)
		return -ENOMEM;

	down_write(&map->rw_sem);
	r = 0;
	list_for_each_entry(curr, &map->neighbor_list, list) {
		if (strncmp(curr->host, host, strlen(curr->host) + 1) == 0) {
			r = -EEXIST;
			break;
		}
	}
	if (!r) {
		dmap_neighbor_get(new);
		list_add_tail(&new->list, &map->neighbor_list);
	}
	up_write(&map->rw_sem);
	dmap_neighbor_put(new);

	return r;
}

int dmap_remove_neighbor(struct dmap *map, char *host)
{
	struct dmap_neighbor *found, *curr, *tmp;

	found = NULL;
	down_write(&map->rw_sem);
	list_for_each_entry_safe(curr, tmp, &map->neighbor_list, list) {
		if (strncmp(curr->host, host, strlen(curr->host) + 1) == 0) {
			found = curr;
			list_del_init(&found->list);
			break;
		}
	}
	up_write(&map->rw_sem);

	if (found)
		dmap_neighbor_put(found);

	return (found) ? 0 : -ENOTTY;
}

void dmap_get_address(struct dmap *map, struct dmap_address *addr)
{
	snprintf(addr->host, ARRAY_SIZE(addr->host), "%s", map->server.host);
	addr->port = map->server.port;

	memcpy(addr->id, map->id, sizeof(addr->id));
	snprintf(addr->id_str, ARRAY_SIZE(addr->id_str), "%s", map->id_str);
}

void *dmap_kzalloc(size_t size, gfp_t flags)
{
#ifdef __MALLOC_CHECKER__
	void *ptr;

	ptr = dmap_kmalloc(size, flags);
	if (ptr)
		memset(ptr, 0, size);

	return ptr;
#else
	return kzalloc(size, flags);
#endif
}

void *dmap_kcalloc(size_t n, size_t size, gfp_t flags)
{
#ifdef __MALLOC_CHECKER__
	void *ptr;

	ptr = dmap_kmalloc(n * size, flags);
	if (ptr)
		memset(ptr, 0, n * size);

	return ptr;
#else
	return kcalloc(n, size, flags);
#endif
}

void *dmap_kmalloc(size_t size, gfp_t flags)
{
#ifdef __MALLOC_CHECKER__
	return malloc_checker_kmalloc(size, flags);
#else
	return kmalloc(size, flags);
#endif
}

void dmap_kfree(void *ptr)
{
#ifdef __MALLOC_CHECKER__
	malloc_checker_kfree(ptr);
#else
	kfree(ptr);
#endif
}

static int __init dmap_module_init(void)
{
	struct dmap *map = get_dmap();
	int r;

#ifdef __MALLOC_CHECKER__
	r = malloc_checker_init();
	if (r) {
		PRINTK("malloc checker init r %d", r);
		return r;
	}
#endif

	r = dmap_init(map);
	if (r) {
#ifdef __MALLOC_CHECKER__
		malloc_checker_deinit();
#endif
		PRINTKE("cant init global, r %d", r);
		return r;
	}

	PRINTK("inited, dmap_module_init=0x%p global=0x%p",
		dmap_module_init, map);
	return 0;
}

static void __exit dmap_module_exit(void)
{
	struct dmap *map = get_dmap();

	dmap_deinit(map);

#ifdef __MALLOC_CHECKER__
	malloc_checker_deinit();
#endif

	PRINTK("exited");
}

module_init(dmap_module_init)
module_exit(dmap_module_exit)

MODULE_AUTHOR("Andrey Smetanin <irqlevel@gmail.com>");
MODULE_DESCRIPTION("Virtual disk");
MODULE_LICENSE("GPL");
