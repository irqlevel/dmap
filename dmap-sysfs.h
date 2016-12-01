#ifndef __DMAP_SYSFS_H__
#define __DMAP_SYSFS_H__

#include <linux/sysfs.h>
#include <linux/kobject.h>

struct dmap_kobject_holder {
	struct kobject kobj;
	struct completion completion;
	atomic_t deiniting;
};

extern struct kobj_type dmap_ktype;

int dmap_sysfs_init(struct dmap_kobject_holder *holder, struct kobject *root,
		     struct kobj_type *ktype, const char *fmt, ...);

void dmap_sysfs_deinit(struct dmap_kobject_holder *holder);

#endif
