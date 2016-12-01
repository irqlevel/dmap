#!/bin/bash -xv

WDIR=temp

#make clean
make
sync
sync
modprobe dns-resolver
insmod dmap.ko

rm -rf $WDIR
mkdir -p $WDIR

echo 0 > /sys/kernel/debug/tracing/tracing_on
echo 'nop' > /sys/kernel/debug/tracing/current_tracer
echo 100000 > /sys/kernel/debug/tracing/buffer_size_kb
echo '' > /sys/kernel/debug/tracing/trace
echo 1 > /sys/kernel/debug/tracing/events/dmap/enable
echo 1 > /sys/kernel/debug/tracing/tracing_on
