import json
import sys

# Probe IDs based on phase2.bpf.c definitions
PROBE_START = 1
PROBE_EDGE1 = 2 # run_phases
PROBE_EDGE2 = 3 # handler
PROBE_EDGE3 = 4 # generic_phase
PROBE_EDGE4 = 5 # content_phase
PROBE_EDGE5 = 6 # static_handler
PROBE_EDGE6 = 7 # output_filter
PROBE_LIBC_READ = 8
PROBE_LIBC_WRITE = 9
PROBE_LIBC_RECV = 10
PROBE_LIBC_SEND = 11
PROBE_LIBC_PREAD = 12
PROBE_LIBC_PWRITE = 13
PROBE_END = 14

def main():
    print("Generating probe-level CFG edges (Minimal Graph)...", file=sys.stderr)
    
    # We define only the valid transitions.
    # Invalid paths will result in weight 0 (missing edge).
    valid_transitions = [
        (1, 2),
        (2, 3),
        (3, 4),
        (4, 5),
        (5, 6),
        (6, 7),
        (7, 14),
        (5, 14)
    ]
    
    edges = []
    weight = 1
    for src, dst in valid_transitions:
        edges.append({"src": src, "dst": dst, "weight": weight})
        weight += 1
            
    out_dict = {"edges": edges}
    
    print(f"Generated {len(edges)} structural edges.", file=sys.stderr)
    
    with open("cfg_edges.json", "w") as f:
        json.dump(out_dict, f, indent=2)

if __name__ == "__main__":
    main()
