#include "dmap-sysfs.h"
#include "dmap.h"
#include "dmap-server.h"
#include "dmap-neighbor.h"

#include <linux/sysfs.h>

#define DMAP_ATTR_RO(_name) \
struct dmap_sysfs_attr dmap_attr_##_name = \
	__ATTR(_name, S_IRUGO, dmap_attr_##_name##_show, NULL)

#define DMAP_ATTR_RW(_name) \
struct dmap_sysfs_attr dmap_attr_##_name = \
	__ATTR(_name, S_IRUGO | S_IWUSR, dmap_attr_##_name##_show, \
		dmap_attr_##_name##_store)

struct dmap_sysfs_attr {
	struct attribute attr;
	ssize_t (*show)(struct dmap *, char *);
	ssize_t (*store)(struct dmap *, const char *, size_t count);
};

static struct completion *dmap_get_completion_from_kobject(struct kobject *kobj)
{
	return &container_of(kobj,
		struct dmap_kobject_holder, kobj)->completion;
}

static void dmap_kobject_release(struct kobject *kobj)
{
	complete(dmap_get_completion_from_kobject(kobj));
}

static struct dmap *dmap_from_kobject(struct kobject *kobj)
{
	return container_of(kobj, struct dmap, kobj_holder.kobj);
}

int dmap_sysfs_init(struct dmap_kobject_holder *holder, struct kobject *root,
		     struct kobj_type *ktype, const char *fmt, ...)
{
	char name[256];
	va_list args;

	ktype->release = dmap_kobject_release;

	init_completion(&holder->completion);

	va_start(args, fmt);
	vsnprintf(name, ARRAY_SIZE(name), fmt, args);
	va_end(args);

	return kobject_init_and_add(&holder->kobj, ktype, root, "%s", name);
}

void dmap_sysfs_deinit(struct dmap_kobject_holder *holder)
{
	struct kobject *kobj = &holder->kobj;

	if (atomic_cmpxchg(&holder->deiniting, 0, 1) == 0) {
		kobject_put(kobj);
		wait_for_completion(dmap_get_completion_from_kobject(kobj));
	}
}

static ssize_t dmap_attr_start_server_store(struct dmap *map,
					const char *buf, size_t count)
{
	char host[DMAP_PARAM_SIZE];
	int r, port;

	r = sscanf(buf, DMAP_PARAM_FMT" %d", host, &port);
	if (r != 2)
		return -EINVAL;

	r = dmap_server_start(&map->server, host, port);
	if (r)
		return r;

	return count;
}

static ssize_t dmap_attr_start_server_show(struct dmap *map,
				     char *buf)
{
	snprintf(buf, PAGE_SIZE, "\n");
	return strlen(buf);
}

static ssize_t dmap_attr_stop_server_store(struct dmap *map,
					const char *buf, size_t count)
{
	int r;

	r = dmap_server_stop(&map->server);
	if (r)
		return r;

	return count;
}

static ssize_t dmap_attr_stop_server_show(struct dmap *map,
				     char *buf)
{
	snprintf(buf, PAGE_SIZE, "\n");
	return strlen(buf);
}

static ssize_t dmap_attr_server_show(struct dmap *map,
				     char *buf)
{
	snprintf(buf, PAGE_SIZE, "%s:%d\n", map->server.host, map->server.port);
	return strlen(buf);
}

static ssize_t dmap_attr_add_neighbor_store(struct dmap *map,
					  const char *buf, size_t count)
{
	char host[DMAP_PARAM_SIZE];
	int r, port;

	r = sscanf(buf, DMAP_PARAM_FMT" %d", host, &port);
	if (r != 2)
		return -EINVAL;

	r = dmap_add_neighbor(map, host, port);
	if (r)
		return r;

	return count;
}

static ssize_t dmap_attr_add_neighbor_show(struct dmap *map,
					 char *buf)
{
	snprintf(buf, PAGE_SIZE, "\n");
	return strlen(buf);
}

static ssize_t dmap_attr_remove_neighbor_store(struct dmap *map,
					  const char *buf, size_t count)
{
	char host[DMAP_PARAM_SIZE];
	int r;

	r = sscanf(buf, DMAP_PARAM_FMT, host);
	if (r != 1)
		return -EINVAL;

	r = dmap_remove_neighbor(map, host);
	if (r)
		return r;

	return count;
}

static ssize_t dmap_attr_remove_neighbor_show(struct dmap *map,
					 char *buf)
{
	snprintf(buf, PAGE_SIZE, "\n");
	return strlen(buf);
}

static ssize_t dmap_attr_neighbors_show(struct dmap *map,
					 char *buf)
{
	struct dmap_neighbor *curr;
	int n, off, r;

	r = 0;
	off = 0;
	down_read(&map->rw_sem);
	list_for_each_entry(curr, &map->neighbor_list, list) {
		if (off >= PAGE_SIZE) {
			r = -ENOMEM;
			break;
		}
		n = snprintf((char *)buf + off, PAGE_SIZE - off, "%s:%d\n",
			curr->host, curr->port);
		if (n <= 0) {
			r = -ENOMEM;
			break;
		}
		off += n;
	}
	up_read(&map->rw_sem);

	if (r)
		return r;

	return strlen(buf);
}

static ssize_t dmap_attr_id_show(struct dmap *map,
				 char *buf)
{
	snprintf(buf, PAGE_SIZE, "%s\n", map->id_str);
	return strlen(buf);
}

static ssize_t dmap_attr_show(struct kobject *kobj,
				struct attribute *attr,
				char *page)
{
	struct dmap_sysfs_attr *vattr;
	struct dmap *map;

	vattr = container_of(attr, struct dmap_sysfs_attr, attr);
	if (!vattr->show)
		return -EIO;

	map = dmap_from_kobject(kobj);
	if (!map)
		return -EIO;

	return vattr->show(map, page);
}

static ssize_t dmap_attr_store(struct kobject *kobj,
				struct attribute *attr,
				const char *page, size_t count)
{
	struct dmap_sysfs_attr *vattr;
	struct dmap *map;

	vattr = container_of(attr, struct dmap_sysfs_attr, attr);
	if (!vattr->store)
		return -EIO;

	map = dmap_from_kobject(kobj);
	if (!map)
		return -EIO;

	return vattr->store(map, page, count);
}

static DMAP_ATTR_RW(start_server);
static DMAP_ATTR_RW(stop_server);
static DMAP_ATTR_RO(server);
static DMAP_ATTR_RW(add_neighbor);
static DMAP_ATTR_RW(remove_neighbor);
static DMAP_ATTR_RO(neighbors);
static DMAP_ATTR_RO(id);

static struct attribute *dmap_attrs[] = {
	&dmap_attr_start_server.attr,
	&dmap_attr_stop_server.attr,
	&dmap_attr_server.attr,
	&dmap_attr_add_neighbor.attr,
	&dmap_attr_remove_neighbor.attr,
	&dmap_attr_neighbors.attr,
	&dmap_attr_id.attr,
	NULL,
};

static const struct sysfs_ops dmap_sysfs_ops = {
	.show	= dmap_attr_show,
	.store	= dmap_attr_store,
};

struct kobj_type dmap_ktype = {
	.sysfs_ops	= &dmap_sysfs_ops,
	.default_attrs	= dmap_attrs,
};
