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

#include "dmap.h"
#include "dmap-sysfs.h"
#include "dmap-connection.h"
#include "dmap-trace-helpers.h"
#include "dmap-malloc-checker.h"
#include "dmap-helpers.h"

static struct dmap global_dmap;

static int dmap_init(struct dmap *map)
{
	int r;

	r = dmap_sysfs_init(&map->kobj_holder, fs_kobj, &dmap_ktype,
			    "%s", "dmap");
	if (r)
		return r;

	return 0;
}

static void dmap_deinit(struct dmap *map)
{
	dmap_sysfs_deinit(&map->kobj_holder);
}

static struct dmap *get_dmap(void)
{
	return &global_dmap;
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
