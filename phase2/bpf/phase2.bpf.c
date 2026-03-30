/* SPDX-License-Identifier: Dual BSD/GPL */
#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "phase2.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/* ------------------------------------------------------------------ *
 *  Maps
 * ------------------------------------------------------------------ */

/* tid -> request_id  (which nginx r pointer is active on this thread) */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key,   __u64);
    __type(value, __u64);
} active_requests SEC(".maps");

/* request_id -> accumulated path weight */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key,   __u64);
    __type(value, __u64);
} path_map SEC(".maps");

/* request_id -> previous instruction pointer */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key,   __u64);
    __type(value, __u64);
} last_ip_map SEC(".maps");

/* ring buffer for userspace events */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

volatile __u64 epoch_ctr = 0;

/* ------------------------------------------------------------------ *
 *  Edge tracking helper
 * ------------------------------------------------------------------ */
static __always_inline void track_edge(struct pt_regs *ctx)
{
    __u64 tid = bpf_get_current_pid_tgid();

    __u64 *req_ptr = bpf_map_lookup_elem(&active_requests, &tid);
    if (!req_ptr)
        return;
    __u64 req = *req_ptr;

    __u64 ip = PT_REGS_IP(ctx);

    /* Debug: emit every edge IP so trace_pipe shows distinct sequences */
    bpf_printk("EDGE: req=%llx ip=%lx\n", req, ip);

    __u64 *prev_ptr = bpf_map_lookup_elem(&last_ip_map, &req);
    if (!prev_ptr) {
        /* First probe hit for this request — seed the last_ip and return */
        bpf_map_update_elem(&last_ip_map, &req, &ip, BPF_ANY);
        return;
    }
    __u64 prev = *prev_ptr;

    /* Fibonacci / Knuth multiplicative hash of the edge (prev XOR ip) */
    __u64 weight = (prev ^ ip) * 11400714819323198485ULL;

    __u64 *path_ptr = bpf_map_lookup_elem(&path_map, &req);
    if (!path_ptr) {
        bpf_map_update_elem(&path_map, &req, &weight, BPF_ANY);
    } else {
        __sync_fetch_and_add(path_ptr, weight);
    }

    bpf_map_update_elem(&last_ip_map, &req, &ip, BPF_ANY);
}

/* ------------------------------------------------------------------ *
 *  START — ngx_http_process_request(ngx_http_request_t *r)
 * ------------------------------------------------------------------ */
SEC("uprobe//opt/nginx/sbin/nginx:ngx_http_process_request")
int handle_start(struct pt_regs *ctx)
{
    __u64 request_id = (__u64)PT_REGS_PARM1(ctx);
    if (!request_id)
        return 0;

    __u64 tid = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&active_requests, &tid, &request_id, BPF_ANY);

    /* Seed the first IP for this request */
    track_edge(ctx);
    return 0;
}

/* ------------------------------------------------------------------ *
 *  END — ngx_http_finalize_request(ngx_http_request_t *r, ngx_int_t rc)
 * ------------------------------------------------------------------ */
SEC("uprobe//opt/nginx/sbin/nginx:ngx_http_finalize_request")
int handle_end(struct pt_regs *ctx)
{
    track_edge(ctx);

    __u64 tid = bpf_get_current_pid_tgid();
    __u64 *req_ptr = bpf_map_lookup_elem(&active_requests, &tid);
    if (!req_ptr)
        return 0;
    __u64 req = *req_ptr;

    __u64 path_id = 0;
    __u64 *path_ptr = bpf_map_lookup_elem(&path_map, &req);
    if (path_ptr)
        path_id = *path_ptr;

    bpf_printk("DONE: req=%llx path_id=%llx\n", req, path_id);

    struct event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (e) {
        e->epoch_id = __sync_fetch_and_add(&epoch_ctr, 1);
        e->path_id  = path_id;
        bpf_ringbuf_submit(e, 0);
    }

    /* Cleanup per-request state */
    bpf_map_delete_elem(&path_map,        &req);
    bpf_map_delete_elem(&last_ip_map,     &req);
    bpf_map_delete_elem(&active_requests, &tid);
    return 0;
}

/* ------------------------------------------------------------------ *
 *  Intermediate edge probes — cover both 200 and 404 hot-paths
 * ------------------------------------------------------------------ */

/* Always called for every request — phases dispatcher */
SEC("uprobe//opt/nginx/sbin/nginx:ngx_http_core_run_phases")
int handle_edge1(struct pt_regs *ctx) { track_edge(ctx); return 0; }

/* Called for every request before content phase */
SEC("uprobe//opt/nginx/sbin/nginx:ngx_http_handler")
int handle_edge2(struct pt_regs *ctx) { track_edge(ctx); return 0; }

/* Called for every request — generic phase runner */
SEC("uprobe//opt/nginx/sbin/nginx:ngx_http_core_generic_phase")
int handle_edge3(struct pt_regs *ctx) { track_edge(ctx); return 0; }

/* Content phase handler — key dispatch point for 200 vs 404 */
SEC("uprobe//opt/nginx/sbin/nginx:ngx_http_core_content_phase")
int handle_edge4(struct pt_regs *ctx) { track_edge(ctx); return 0; }

/* Called only when serving static files (200 path) */
SEC("uprobe//opt/nginx/sbin/nginx:ngx_http_static_handler")
int handle_edge5(struct pt_regs *ctx) { track_edge(ctx); return 0; }

/* Called on the 200 output path — NOT called for plain 404 */
SEC("uprobe//opt/nginx/sbin/nginx:ngx_http_output_filter")
int handle_edge6(struct pt_regs *ctx) { track_edge(ctx); return 0; }
