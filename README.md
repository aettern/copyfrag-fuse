# copyfrag-fuse

a bpf-lsm module that blocks the copyfail and dirtyfrag local privilege escalation exploits on linux.

## how it works

it hooks into `socket_setsockopt` using bpf-lsm and watches for rapid bursts of specific socket option calls that these exploits rely on:

- `SOL_ALG` / `ALG_SET_KEY` (copyfail)
- `SOL_UDP` / `UDP_ENCAP` (dirtyfrag)
- `SOL_RXRPC` / `RXRPC_SECURITY_KEY` and `RXRPC_MIN_SECURITY_LEVEL` (dirtyfrag)

if a process makes 4 or more of these calls within 1 second, it gets blocked with `-EPERM`. normal usage of these socket options is unaffected.

## prerequisites

- linux kernel 5.7+ with `CONFIG_BPF_LSM=y`
- `bpf` must be listed in your kernel's lsm order (check `cat /sys/kernel/security/lsm`)
- clang
- libbpf-dev
- libelf-dev
- bpftool

on ubuntu/debian:
```
sudo apt install clang libbpf-dev libelf-dev linux-tools-common linux-tools-$(uname -r)
```

## building

```
make
```

this generates `vmlinux.h` from your running kernel, compiles the bpf object, and builds the loader.

## running

```
sudo ./loader
```

it will print a message when active. press ctrl+c to detach and exit.

blocked attempts show up in the kernel trace log:
```
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

## license

MIT