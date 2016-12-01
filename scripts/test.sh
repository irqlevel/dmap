#!/bin/bash -xv

WDIR=temp

echo 127.0.0.1 8111 > /sys/fs/dmap/start_server
cat /sys/fs/dmap/server
echo bla.com 8111 > /sys/fs/dmap/add_neighbor
echo blabla.com 8111 > /sys/fs/dmap/add_neighbor
cat /sys/fs/dmap/neighbors
