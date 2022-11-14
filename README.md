# packetdrop

sudo apt-get install libelf-dev bpfcc-tools linux-headers-$(uname -r) gcc

sudo apt install clang libelf1 libelf-dev zlib1g-dev llvm pkg-config

git submodule update --init --recursive

### generate vmlinux.h

```sh
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
```
