# copyfrag-fuse

bpf-lsm module that blocks CopyFail (CVE-2026-31431) and DirtyFrag (CVE-2026-43284 / CVE-2026-43500) at runtime. No kernel patch, no reboot.

Full writeup with the exploit details and design reasoning: [WRITEUP.md](./WRITEUP.md)

## how it works

Both exploits need to spam the same socket option (`ALG_SET_KEY`, `UDP_ENCAP`, `RXRPC_SECURITY_KEY`, `RXRPC_MIN_SECURITY_LEVEL`) repeatedly to build up their write, since each call only gets them a 4-byte write. Legit usage sets these once and moves on.

This hooks `security_socket_setsockopt` via `BPF_PROG_TYPE_LSM` and blocks a process with `-EPERM` if it makes 4+ of those calls within 1 second. Doesn't care which file is being targeted, doesn't need SELinux/AppArmor configured to catch it — details in the writeup.

<img width="800" height="450" alt="copyfrag-fuse demo" src="https://github.com/user-attachments/assets/56dd5b2e-4b44-4c34-b731-b66c228b5412" />

## prerequisites

- kernel 5.7+ with `CONFIG_BPF_LSM=y`
- `bpf` in your kernel's lsm order (`cat /sys/kernel/security/lsm`)
- BTF info for your kernel (`ls /sys/kernel/btf/vmlinux` should exist)

Ubuntu/Debian:
```
sudo apt install clang libbpf-dev libelf-dev linux-tools-common linux-tools-$(uname -r)
```

Fedora/RHEL:
```
sudo dnf install clang llvm libbpf-devel elfutils-libelf-devel bpftool kernel-devel
```
on RHEL, `libbpf-devel`/`bpftool` are in the CodeReady Builder repo — enable it first with `sudo subscription-manager repos --enable codeready-builder-for-rhel-9-$(arch)-rpms` (swap `rhel-9` for `rhel-8` if needed).

## build

```
make
```

generates `vmlinux.h` from your running kernel, builds the bpf object + loader.

## run

```
sudo ./loader
```

ctrl+c to detach. watch it catch stuff live:

```
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

test it against the actual [CopyFail](https://copy.fail/) or [DirtyFrag](https://github.com/V4bel/dirtyfrag) PoC in a VM before trusting it anywhere real.

## limitations

runtime mitigation, not a patch — update your kernel when you can, this just covers the gap until then. also not bulletproof: forking to spread calls across PIDs, or slowing down below the 1s window, are both real ways around the current heuristic.

## credits

detection idea is from [Miggo Security / Rafael David Tinoco's writeup](https://medium.com/@miggo-engineering/detecting-copyfail-dirtyfrag-by-thinking-outside-the-box-3cae021ca94c) — this is my own implementation of it, turned into an active block instead of just detection. mitigation-tradeoffs section also draws on [Cloudflare's CopyFail writeup](https://blog.cloudflare.com/copy-fail-linux-vulnerability-mitigation/).

## license

MIT
