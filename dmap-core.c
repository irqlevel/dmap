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

static void dmap_ping_worker(struct work_struct *work)
{
	struct dmap_neighbor *curr;
	struct dmap *map;

	map = container_of(work, struct dmap, ping_work);

	down_read(&map->rw_sem);
	list_for_each_entry(curr, &map->neighbor_list, list) {
		dmap_neighbor_ping(curr);
	}
	up_read(&map->rw_sem);
}

static enum hrtimer_restart dmap_timer_callback(struct hrtimer *timer)
{
	struct dmap *map;

	map = container_of(timer, struct dmap, timer);
	queue_work(map->wq, &map->ping_work);

	hrtimer_start(&map->timer, ktime_add_ms(ktime_get(), DMAP_TIMER_MS),
		      HRTIMER_MODE_ABS);

	return HRTIMER_NORESTART;
}

static int dmap_init(struct dmap *map)
{
	int r;

	init_rwsem(&map->rw_sem);
	INIT_LIST_HEAD(&map->neighbor_list);
	map->neighbor_tree = RB_ROOT;

	dmap_hash_init(&map->hash);

	get_random_bytes(map->id, sizeof(map->id));

	dmap_bytes_to_hex(map->id, ARRAY_SIZE(map->id),
			  map->id_str, ARRAY_SIZE(map->id_str));

	hrtimer_init(&map->timer, CLOCK_MONOTONIC, HRTIMER_MODE_ABS);
	map->timer.function = dmap_timer_callback;

	INIT_WORK(&map->ping_work, dmap_ping_worker);
	map->wq = alloc_workqueue("dmap-wq", WQ_MEM_RECLAIM, 0);
	if (!map->wq) {
		r = -ENOMEM;
		goto out;
	}

	r = dmap_server_init(&map->server);
	if (r)
		goto del_wq;

	r = dmap_sysfs_init(&map->kobj_holder, fs_kobj, &dmap_ktype,
			    "%s", "dmap");
	if (r)
		goto deinit_server;

	hrtimer_start(&map->timer, ktime_add_ms(ktime_get(), DMAP_TIMER_MS),
		      HRTIMER_MODE_ABS);

	return 0;

deinit_server:
	dmap_server_deinit(&map->server);
del_wq:
	destroy_workqueue(map->wq);
out:
	return r;
}

static void dmap_deinit(struct dmap *map)
{
	struct dmap_neighbor *curr, *tmp;

	hrtimer_cancel(&map->timer);
	destroy_workqueue(map->wq);

	dmap_sysfs_deinit(&map->kobj_holder);
	dmap_server_deinit(&map->server);

	down_write(&map->rw_sem);
	list_for_each_entry_safe(curr, tmp, &map->neighbor_list, list) {
		list_del_init(&curr->list);
		rb_erase(&curr->rb_link, &map->neighbor_tree);
		dmap_neighbor_bye(curr);
		dmap_neighbor_put(curr);
	}
	up_write(&map->rw_sem);

	dmap_hash_deinit(&map->hash);
}

static struct dmap *get_dmap(void)
{
	return &global_dmap;
}

static bool __dmap_insert_neighbor(struct dmap *map,
				   struct dmap_neighbor *neighbor)
{
	struct dmap_neighbor *curr;
	struct rb_node **p;
	struct rb_node *parent;
	int cmp;
	bool exist;

	exist = false;
	parent = NULL;
	p = &map->neighbor_tree.rb_node;
	while (*p) {
		parent = *p;
		curr = rb_entry(parent, struct dmap_neighbor, rb_link);
		cmp = memcmp(neighbor->addr.id, curr->addr.id,
			     sizeof(neighbor->addr.id));
		if (cmp < 0)
			p = &(*p)->rb_left;
		else if (cmp > 0)
			p = &(*p)->rb_right;
		else {
			exist = true;
			break;
		}
	}
	if (!exist) {
		rb_link_node(&neighbor->rb_link, parent, p);
		rb_insert_color(&neighbor->rb_link, &map->neighbor_tree);
	}

	return (exist) ? false : true;
}

int dmap_add_neighbor(struct dmap *map, struct dmap_address *addr, bool hello)
{
	struct dmap_neighbor *new, *curr;
	int r;

	new = dmap_neighbor_create(map, addr->host, addr->port);
	if (!new)
		return -ENOMEM;

	if (hello) {
		memcpy(new->addr.id, addr->id, sizeof(new->addr.id));
		memcpy(new->addr.id_str, addr->id_str,
		       sizeof(new->addr.id_str));
	}

	down_write(&map->rw_sem);
	r = 0;
	list_for_each_entry(curr, &map->neighbor_list, list) {
		if (strncmp(curr->addr.host, new->addr.host,
		    strlen(curr->addr.host) + 1) == 0) {
			r = -EEXIST;
			goto unlock;
		}
		if (hello && memcmp(curr->addr.id, new->addr.id,
		    sizeof(curr->addr.id)) == 0) {
			r = -EEXIST;
			goto unlock;
		}
	}

	if (!hello)
		r = dmap_neighbor_hello(new);
	else {
		mutex_lock(&new->mutex);
		dmap_neighbor_set_state(new, DMAP_NEIGHBOR_S_HELLO);
		mutex_unlock(&new->mutex);
	}

	if (!r) {
		if (__dmap_insert_neighbor(map, new)) {
			dmap_neighbor_get(new);
			list_add_tail(&new->list, &map->neighbor_list);
		} else
			r = -EEXIST;
	}

unlock:
	up_write(&map->rw_sem);
	dmap_neighbor_put(new);

	return r;
}

struct dmap_neighbor *dmap_lookup_neighbor(struct dmap *map,
					   struct dmap_address *addr)
{
	struct dmap_neighbor *curr;
	struct dmap_neighbor *found = NULL;
	struct rb_node *n;
	int cmp;

	down_read(&map->rw_sem);
	n = map->neighbor_tree.rb_node;
	while (n) {
		curr = rb_entry(n, struct dmap_neighbor, rb_link);
		cmp = memcmp(addr->id, curr->addr.id, sizeof(addr->id));
		if (cmp < 0)
			n = n->rb_left;
		else if (cmp > 0)
			n = n->rb_right;
		else {
			found = curr;
			dmap_neighbor_get(found);
			break;
		}
	}
	up_read(&map->rw_sem);
	return found;
}

struct dmap_neighbor *dmap_select_neighbor(struct dmap *map,
					   unsigned char id[DMAP_ID_SIZE])
{
	struct dmap_neighbor *curr;
	struct dmap_neighbor *found = NULL;
	struct rb_node *n;

	down_read(&map->rw_sem);
	for (n = rb_first(&map->neighbor_tree); n != NULL; n = rb_next(n)) {
		curr = rb_entry(n, struct dmap_neighbor, rb_link);
		if (memcmp(id, curr->addr.id, sizeof(*id)) < 0) {
			found = curr;
			break;
		}
	}

	if (found == NULL) {
		n = rb_first(&map->neighbor_tree);
		if (n)
			found = rb_entry(n, struct dmap_neighbor, rb_link);
	}

	up_read(&map->rw_sem);
	return found;
}

bool dmap_is_self_neighbor(struct dmap *map, struct dmap_neighbor *neighbor)
{
	if (memcmp(map->id, neighbor->addr.id, sizeof(map->id)) == 0)
		return true;
	return false;
}

int dmap_remove_neighbor(struct dmap *map, char *host)
{
	struct dmap_neighbor *found, *curr, *tmp;

	found = NULL;
	down_write(&map->rw_sem);
	list_for_each_entry_safe(curr, tmp, &map->neighbor_list, list) {
		if (strncmp(curr->addr.host, host,
			    strlen(curr->addr.host) + 1) == 0) {
			found = curr;
			rb_erase(&found->rb_link, &map->neighbor_tree);
			list_del_init(&found->list);
			break;
		}
	}
	up_write(&map->rw_sem);

	if (found) {
		dmap_neighbor_bye(found);
		dmap_neighbor_put(found);
	}

	return (found) ? 0 : -ENOTTY;
}

int dmap_erase_neighbor(struct dmap *map, struct dmap_neighbor *victim)
{
	struct dmap_neighbor *curr, *tmp, *found;

	found = NULL;
	down_write(&map->rw_sem);
	list_for_each_entry_safe(curr, tmp, &map->neighbor_list, list) {
		if (curr == victim) {
			rb_erase(&curr->rb_link, &map->neighbor_tree);
			list_del_init(&curr->list);
			found = curr;
			break;
		}
	}
	up_write(&map->rw_sem);

	if (found)
		dmap_neighbor_put(found);

	return (found) ? 0 : -ENOTTY;
}

void dmap_addr_init(struct dmap_address *addr, char *host, int port,
		    unsigned char id[DMAP_ID_SIZE])
{
	snprintf(addr->host, ARRAY_SIZE(addr->host), "%s", host);
	addr->port = port;

	memcpy(addr->id, id, sizeof(addr->id));

	dmap_bytes_to_hex(addr->id, ARRAY_SIZE(addr->id),
			  addr->id_str, ARRAY_SIZE(addr->id_str));
}

void dmap_get_address(struct dmap *map, struct dmap_address *addr)
{
	dmap_addr_init(addr, map->server.host, map->server.port, map->id);
}

int dmap_check_address(struct dmap_address *addr)
{
	if (addr->host[ARRAY_SIZE(addr->host) - 1] != '\0')
		return -EINVAL;
	if (addr->id_str[ARRAY_SIZE(addr->id_str) - 1] != '\0')
		return -EINVAL;

	return 0;
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
