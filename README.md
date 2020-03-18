# libbpf_map_in_map
A simple example of map_in_map usage in libbpf

# Requirements
## Linux source code
```
$ git clone https://github.com/torvalds/linux.git
```

## libbpf.so
The libbpf .so library is included in this repo. It was built agains 4.16 kerenl.
You can build it yourself by checking out the latest Linux kernel and run
```
$ git clone https://github.com/torvalds/linux.git
$ cd linux
$ cd tools/lib/bpf
$ make
```

## clang
Need clang version >= 3.7

# Build
```
$ make LINUX=<local-path-to-linux-souce-code>
```

# Run
```
$ sudo ./main
```


