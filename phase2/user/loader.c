#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "../bpf/phase2.h"

static volatile bool exiting = false;
static int training_mode = 1;

#define MAX_VALID_PATHS 1024
static __u64 valid_paths[MAX_VALID_PATHS];
static int num_valid_paths = 0;

static bool is_valid(__u64 path_id) {
    if (path_id == 0) return true;
    for (int i = 0; i < num_valid_paths; i++) {
        if (valid_paths[i] == path_id) return true;
    }
    return false;
}

static void add_valid_path(__u64 path_id) {
    if (path_id == 0) return;
    if (num_valid_paths < MAX_VALID_PATHS) {
        valid_paths[num_valid_paths++] = path_id;
        printf("[TRAIN] Added valid path_id = 0x%016llx\n", (unsigned long long)path_id);
    }
}

static void sig_handler(int sig)
{
    exiting = true;
}

static void sigusr1_handler(int sig)
{
    training_mode = 0;
    printf("\n--- Switched to ENFORCEMENT mode ---\n");
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    const struct event *e = data;
    printf("Epoch %-6llu  path_id = 0x%016llx\n", e->epoch_id, e->path_id);

    if (training_mode) {
        if (!is_valid(e->path_id)) {
            add_valid_path(e->path_id);
        }
    } else {
        if (!is_valid(e->path_id)) {
            printf("\033[31m[ALERT] INVALID PATH DETECTED: 0x%016llx\033[0m\n", e->path_id);
        } else {
            printf("\033[32m[OK] Valid path: 0x%016llx\033[0m\n", e->path_id);
        }
    }
    return 0;
}

// BPF Map Loading Logic
struct edge_key {
    __u32 src;
    __u32 dst;
};

static void load_edge_weights(int map_fd) {
    FILE *f = fopen("cfg_edges.json", "r");
    if (!f) {
        fprintf(stderr, "Failed to open cfg_edges.json\n");
        return;
    }
    
    char line[512];
    unsigned int src = 0, dst = 0;
    unsigned long long weight = 0;
    
    struct edge_key key;
    __u64 val;
    int loaded = 0;
    
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, "\"src\":")) {
            char *p = strchr(line, ':');
            if (p) sscanf(p + 1, " %u", &src);
        } else if (strstr(line, "\"dst\":")) {
            char *p = strchr(line, ':');
            if (p) sscanf(p + 1, " %u", &dst);
        } else if (strstr(line, "\"weight\":")) {
            char *p = strchr(line, ':');
            if (p) {
                sscanf(p + 1, " %llu", &weight);
                
                key.src = src;
                key.dst = dst;
                val = weight;
                bpf_map_update_elem(map_fd, &key, &val, BPF_ANY);
                loaded++;
                
                src = dst = weight = 0;
            }
        }
    }
    fclose(f);
    printf("Loaded %d edge weights into BPF map.\n", loaded);
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

    int edge_weights_fd;

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

    edge_weights_fd = bpf_object__find_map_fd_by_name(obj, "edge_weights_map");
    if (edge_weights_fd >= 0) {
        load_edge_weights(edge_weights_fd);
    } else {
        fprintf(stderr, "Failed to find edge_weights_map: %d\n", edge_weights_fd);
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
    links[8] = attach_prog(obj, "handle_libc_read");
    links[9] = attach_prog(obj, "handle_libc_write");
    links[10] = attach_prog(obj, "handle_libc_recv");
    links[11] = attach_prog(obj, "handle_libc_send");
    links[12] = attach_prog(obj, "handle_libc_pread");
    links[13] = attach_prog(obj, "handle_libc_pwrite");

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
    signal(SIGUSR1, sigusr1_handler);

    printf("Phase 3 — CFG-Aware Path Validation. Polling events (Ctrl-C to stop)...\n");
    printf("Send SIGUSR1 to switch from TRAIN to ENFORCEMENT mode (kill -SIGUSR1 %d).\n", getpid());

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
