#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

static volatile sig_atomic_t exiting = 0;

static void sig_handler(int sig)
{
    exiting = 1;
}

int main(int argc, char **argv)
{
    struct bpf_object *obj;
    struct bpf_program *prog;
    int err;

    /* Load the compiled eBPF object */
    obj = bpf_object__open_file("copyfrag_fuse.bpf.o", NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "err: failed to open bpf object. did it compile correctly?\n");
        return 1;
    }

    /* Load the object into the kernel (requires CONFIG_BPF_LSM) */
    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "err: failed to load bpf object into kernel. Check if LSM BPF is enabled.\n");
        goto cleanup;
    }

    /* Attach the LSM hook */
    bpf_object__for_each_program(prog, obj) {
        struct bpf_link *link = bpf_program__attach(prog);
        if (libbpf_get_error(link)) {
            fprintf(stderr, "err: failed to attach bpf program.\n");
            err = 1;
            goto cleanup;
        }
    }

    /* Handle Ctrl+C gracefully */
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    printf("[+] copyfrag-fuse active. mitigating CopyFail and DirtyFrag.\n");
    printf("[+] waiting for exploit behavior... press ctrl+c to exit.\n");
    
    while (!exiting) {
        sleep(1);
    }

    printf("\n[-] detaching hook and exiting.\n");

cleanup:
    bpf_object__close(obj);
    return err != 0;
}
