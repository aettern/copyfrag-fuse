CC = clang
CFLAGS = -g -O2 -Wall
BPF_CFLAGS = -g -O2 -target bpf -D__TARGET_ARCH_x86

all: vmlinux.h loader copyfrag_fuse.bpf.o

# Generate vmlinux.h from the current running kernel
vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

# Compile the eBPF kernel program
copyfrag_fuse.bpf.o: copyfrag_fuse.bpf.c vmlinux.h
	$(CC) $(BPF_CFLAGS) -c $< -o $@

# Compile the user-space loader
loader: loader.c
	$(CC) $(CFLAGS) $< -o $@ -lbpf -lelf

clean:
	rm -f *.o loader vmlinux.h
