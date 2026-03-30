#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "phase1.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";



struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

volatile u64 epoch_ctr = 0;



SEC("uprobe//opt/nginx/sbin/nginx:ngx_http_finalize_request")
int handle_end(struct pt_regs *ctx) {
    bpf_printk("END hit\n");

    struct event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) {
        return 0;
    }
    
    e->epoch_id = __sync_fetch_and_add(&epoch_ctr, 1);
    e->signal = 1;
    
    bpf_ringbuf_submit(e, 0);
    
    return 0;
}
