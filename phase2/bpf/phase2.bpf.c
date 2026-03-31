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

struct edge_key {
    __u32 src;
    __u32 dst;
};

/* (prev_probe, curr_probe) -> edge weight */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 524288);
    __type(key, struct edge_key);
    __type(value, __u64);
} edge_weights_map SEC(".maps");

/* request_id -> previous probe_id */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key,   __u64);
    __type(value, __u32);
} last_probe_id_map SEC(".maps");

/* ring buffer for userspace events */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

volatile __u64 epoch_ctr = 0;

/* ------------------------------------------------------------------ *
 *  Edge tracking helper
 * ------------------------------------------------------------------ */
static __always_inline void track_edge(struct pt_regs *ctx, __u32 current_probe_id)
{
    __u64 tid = bpf_get_current_pid_tgid();

    __u64 *req_ptr = bpf_map_lookup_elem(&active_requests, &tid);
    if (!req_ptr)
        return;
    __u64 req = *req_ptr;

    /* Debug: emit every probe id so trace_pipe shows distinct sequences */
    bpf_printk("PROBE: req=%llx id=%u\n", req, current_probe_id);

    __u32 *prev_ptr = bpf_map_lookup_elem(&last_probe_id_map, &req);
    if (!prev_ptr) {
        /* First probe hit for this request */
        bpf_printk("FIRST PROBE: req=%llx id=%u\n", req, current_probe_id);
        bpf_map_update_elem(&last_probe_id_map, &req, &current_probe_id, BPF_ANY);
        return;
    }
    __u32 prev = *prev_ptr;

    struct edge_key e_key;
    e_key.src = prev;
    e_key.dst = current_probe_id;

    __u64 *weight_ptr = bpf_map_lookup_elem(&edge_weights_map, &e_key);
    __u64 weight = weight_ptr ? *weight_ptr : 0;

    bpf_printk("prev=%u curr=%u w=%llx\n", prev, current_probe_id, weight);
    if (!weight) {
        bpf_printk("MISS: %u -> %u\n", e_key.src, e_key.dst);
    }

    if (weight > 0) {
        __u64 *path_ptr = bpf_map_lookup_elem(&path_map, &req);
        if (!path_ptr) {
            bpf_map_update_elem(&path_map, &req, &weight, BPF_ANY);
        } else {
            __sync_fetch_and_add(path_ptr, weight);
        }
    }

    bpf_map_update_elem(&last_probe_id_map, &req, &current_probe_id, BPF_ANY);
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
    track_edge(ctx, 1);
    return 0;
}

/* ------------------------------------------------------------------ *
 *  END — ngx_http_finalize_request(ngx_http_request_t *r, ngx_int_t rc)
 * ------------------------------------------------------------------ */
SEC("uprobe//opt/nginx/sbin/nginx:ngx_http_finalize_request")
int handle_end(struct pt_regs *ctx)
{
    track_edge(ctx, 14);

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
    bpf_map_delete_elem(&last_probe_id_map, &req);
    bpf_map_delete_elem(&active_requests, &tid);
    return 0;
}

/* ------------------------------------------------------------------ *
 *  Intermediate edge probes — cover both 200 and 404 hot-paths
 * ------------------------------------------------------------------ */

/* Always called for every request — phases dispatcher */
SEC("uprobe//opt/nginx/sbin/nginx:ngx_http_core_run_phases")
int handle_edge1(struct pt_regs *ctx) { track_edge(ctx, 2); return 0; }

/* Called for every request before content phase */
SEC("uprobe//opt/nginx/sbin/nginx:ngx_http_handler")
int handle_edge2(struct pt_regs *ctx) { track_edge(ctx, 3); return 0; }

/* Called for every request — generic phase runner */
SEC("uprobe//opt/nginx/sbin/nginx:ngx_http_core_generic_phase")
int handle_edge3(struct pt_regs *ctx) { track_edge(ctx, 4); return 0; }

/* Content phase handler — key dispatch point for 200 vs 404 */
SEC("uprobe//opt/nginx/sbin/nginx:ngx_http_core_content_phase")
int handle_edge4(struct pt_regs *ctx) { track_edge(ctx, 5); return 0; }

/* Called only when serving static files (200 path) */
SEC("uprobe//opt/nginx/sbin/nginx:ngx_http_static_handler")
int handle_edge5(struct pt_regs *ctx) { track_edge(ctx, 6); return 0; }

/* Called on the 200 output path — NOT called for plain 404 */
SEC("uprobe//opt/nginx/sbin/nginx:ngx_http_output_filter")
int handle_edge6(struct pt_regs *ctx) { track_edge(ctx, 7); return 0; }

/* Shared Library uprobes */
SEC("uprobe//lib/x86_64-linux-gnu/libc.so.6:read")
int handle_libc_read(struct pt_regs *ctx) { track_edge(ctx, 8); return 0; }

SEC("uprobe//lib/x86_64-linux-gnu/libc.so.6:write")
int handle_libc_write(struct pt_regs *ctx) { track_edge(ctx, 9); return 0; }

SEC("uprobe//lib/x86_64-linux-gnu/libc.so.6:recv")
int handle_libc_recv(struct pt_regs *ctx) { track_edge(ctx, 10); return 0; }

SEC("uprobe//lib/x86_64-linux-gnu/libc.so.6:send")
int handle_libc_send(struct pt_regs *ctx) { track_edge(ctx, 11); return 0; }

SEC("uprobe//lib/x86_64-linux-gnu/libc.so.6:pread")
int handle_libc_pread(struct pt_regs *ctx) { track_edge(ctx, 12); return 0; }

SEC("uprobe//lib/x86_64-linux-gnu/libc.so.6:pwrite")
int handle_libc_pwrite(struct pt_regs *ctx) { track_edge(ctx, 13); return 0; }
