### dmap - distributed key-value memory cache

#### Build:
```sh
$ make
$ go build dmap_client.go
```

#### Usage:
```sh
$ sudo insmod dmap.ko #load kernel module on each node in cluster

$ echo hostname port | sudo tee /sys/fs/dmap/start_server #start server on each node in cluster

$ echo hostname port | sudo tee /sys/fs/dmap/add_neighbor #add node into cluster

$ ./dmap_client hostname:port set key value #add key-value

$ ./dmap_client hostname:port get key #query value by key

$ ./dmap_client hostname:port del key #delete key

$ rmmod dmap #unload dmap
```
