### dmap - distributed key-value memory cache

#### Client:
[go client](https://github.com/irqlevel/dmap-client-go)

#### Build:
```sh
$ make
```

#### Install:
```sh
$ sudo insmod dmap.ko #load kernel module on each node in cluster

$ echo hostname port | sudo tee /sys/fs/dmap/start_server #start server on each node in cluster

$ echo hostname port | sudo tee /sys/fs/dmap/add_neighbor #add node into cluster

$ cat /sys/fs/dmap/id #query node UID

$ cat /sys/fs/dmap/neighbors #query nodes in cluster
```

#### Usage:
```sh
$ ./dmap-client hostname:port set key value #add key-value

$ ./dmap-client hostname:port get key #query value by key

$ ./dmap-client hostname:port upd key value #update key value

$ ./dmap-client hostname:post cmpxchg key exchange comparand #compare exchange key value

$ ./dmap-client hostname:port del key #delete key
```

#### Uninstall:
```sh
$ rmmod dmap #unload dmap on each node in cluster
```
