#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include "../bpf/phase1.h"

static volatile bool exiting = false;

static void sig_handler(int sig)
{
    exiting = true;
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    const struct event *e = data;
    printf("Epoch %llu -> Signal %llu\n", e->epoch_id, e->signal);
    return 0;
}

int main(int argc, char **argv)
{
    struct bpf_object *obj = NULL;
    struct bpf_link *link_end = NULL;
    struct ring_buffer *rb = NULL;
    int err = 0;
    int map_fd;

    obj = bpf_object__open_file("../bpf/phase1.bpf.o", NULL);
    if (!obj || libbpf_get_error(obj)) {
        fprintf(stderr, "Failed to open BPF object\n");
        return 1;
    }

    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "Failed to load BPF object: %d\n", err);
        goto cleanup;
    }



    struct bpf_program *prog_end = bpf_object__find_program_by_name(obj, "handle_end");
    if (!prog_end) {
        fprintf(stderr, "Failed to find program handle_end\n");
        err = -1;
        goto cleanup;
    }



    link_end = bpf_program__attach(prog_end);
    err = libbpf_get_error(link_end);
    if (err) {
        fprintf(stderr, "Failed to attach end uprobe: %d\n", err);
        goto cleanup;
    }

    map_fd = bpf_object__find_map_fd_by_name(obj, "rb");
    if (map_fd < 0) {
        fprintf(stderr, "Failed to find ring buffer map: %d\n", map_fd);
        err = map_fd;
        goto cleanup;
    }

    rb = ring_buffer__new(map_fd, handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        err = -1;
        goto cleanup;
    }

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    printf("Successfully attached uprobes. Polling events...\n");

    while (!exiting) {
        err = ring_buffer__poll(rb, 100);
        if (err == -EINTR) {
            err = 0;
            break;
        }
        if (err < 0) {
            fprintf(stderr, "Error polling ring buffer: %d\n", err);
            break;
        }
    }

cleanup:
    ring_buffer__free(rb);
    bpf_link__destroy(link_end);
    bpf_object__close(obj);
    return err < 0 ? 1 : 0;
}
