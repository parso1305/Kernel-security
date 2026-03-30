#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include "../bpf/phase2.h"

static volatile bool exiting = false;

static void sig_handler(int sig)
{
    exiting = true;
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    const struct event *e = data;
    printf("Epoch %-6llu  path_id = 0x%016llx\n", e->epoch_id, e->path_id);
    return 0;
}

static struct bpf_link *attach_prog(struct bpf_object *obj, const char *name)
{
    struct bpf_program *prog = bpf_object__find_program_by_name(obj, name);
    if (!prog) {
        /* Some optional edge probes may not exist in every build — just skip */
        fprintf(stderr, "Warning: program '%s' not found, skipping\n", name);
        return NULL;
    }
    struct bpf_link *link = bpf_program__attach(prog);
    if (libbpf_get_error(link)) {
        fprintf(stderr, "Warning: failed to attach '%s': %ld\n", name, libbpf_get_error(link));
        return NULL;
    }
    fprintf(stderr, "Attached: %s\n", name);
    return link;
}

int main(int argc, char **argv)
{
    struct bpf_object *obj  = NULL;
    struct bpf_link  *links[16] = {0};
    struct ring_buffer *rb  = NULL;
    int err = 0;
    int map_fd;

    /* ---------- open & load BPF object ---------- */
    obj = bpf_object__open_file("../bpf/phase2.bpf.o", NULL);
    if (!obj || libbpf_get_error(obj)) {
        fprintf(stderr, "Failed to open BPF object\n");
        return 1;
    }

    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "Failed to load BPF object: %d\n", err);
        goto cleanup;
    }

    /* ---------- attach all probes ---------- */
    links[0] = attach_prog(obj, "handle_start");
    links[1] = attach_prog(obj, "handle_end");
    links[2] = attach_prog(obj, "handle_edge1");  /* ngx_http_core_run_phases    */
    links[3] = attach_prog(obj, "handle_edge2");  /* ngx_http_handler            */
    links[4] = attach_prog(obj, "handle_edge3");  /* ngx_http_core_generic_phase */
    links[5] = attach_prog(obj, "handle_edge4");  /* ngx_http_core_content_phase */
    links[6] = attach_prog(obj, "handle_edge5");  /* ngx_http_static_handler     */
    links[7] = attach_prog(obj, "handle_edge6");  /* ngx_http_output_filter      */

    /* handle_start and handle_end are mandatory */
    if (!links[0] || !links[1]) {
        fprintf(stderr, "Fatal: could not attach handle_start or handle_end\n");
        err = -1;
        goto cleanup;
    }

    /* ---------- ring buffer ---------- */
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

    signal(SIGINT,  sig_handler);
    signal(SIGTERM, sig_handler);

    printf("Phase 2 — CFG path accumulation. Polling events (Ctrl-C to stop)...\n");

    while (!exiting) {
        err = ring_buffer__poll(rb, 100);
        if (err == -EINTR) { err = 0; break; }
        if (err < 0) {
            fprintf(stderr, "Error polling ring buffer: %d\n", err);
            break;
        }
    }

cleanup:
    ring_buffer__free(rb);
    for (int i = 0; i < 16; i++)
        bpf_link__destroy(links[i]);
    bpf_object__close(obj);
    return err < 0 ? 1 : 0;
}
