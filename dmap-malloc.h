#ifndef __DMAP_MALLOC_H__
#define __DMAP_MALLOC_H__

void *dmap_kzalloc(size_t size, gfp_t flags);

void *dmap_kcalloc(size_t n, size_t size, gfp_t flags);

void *dmap_kmalloc(size_t size, gfp_t flags);

void dmap_kfree(void *ptr);

#endif
