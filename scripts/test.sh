#!/bin/bash -xv

WDIR=temp

echo 127.0.0.1 8111 > /sys/fs/dmap/start_server
cat /sys/fs/dmap/server
