CURRDIR = $(shell pwd)
KERNEL_BUILD_PATH=/lib/modules/$(shell uname -r)/build

DMAP_MOD = dmap
DMAP_MOD_KO = $(DMAP_MOD).ko

dmap-y +=	dmap-core.o dmap-sysfs.o dmap-connection.o ksocket.o	\
		dmap-trace.o dmap-malloc-checker.o			\
		dmap-helpers.o dmap-server.o dmap-neighbor.o		\

obj-m = $(DMAP_MOD).o

KBUILD_EXTRA_SYMBOLS = $(KERNEL_BUILD_PATH)/Module.symvers

ccflags-y := -I$(src) -g3	\
		-D __MALLOC_CHECKER__				\
		-D __MALLOC_CHECKER_STACK_TRACE__		\
		-D __MALLOC_CHECKER_FILL_CC__			\

all:
	$(MAKE) -C $(KERNEL_BUILD_PATH) M=$(CURRDIR) modules
clean:
	$(MAKE) -C $(KERNEL_BUILD_PATH) M=$(CURRDIR) clean
	rm -f *.o
	rm -rf temp/
