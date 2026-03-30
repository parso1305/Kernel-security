# Kernel-Security  
**eBPF-based Control-Flow Attestation for Long-Running Linux Processes**

---

## Abstract

Traditional control-flow attestation (CFA) techniques assume bounded program execution and are therefore unsuitable for modern server applications such as `nginx`, which operate continuously and process unbounded request streams.

This project presents a **runtime control-flow attestation framework** for long-running Linux user-space processes using **eBPF uprobes**, enabling non-intrusive, fine-grained monitoring without kernel modification. Execution is segmented into **request-level epochs**, and each epoch is summarized into a compact control-flow representation, enabling continuous verification of program behavior.

---

## Problem Statement

Existing CFA systems face practical limitations when applied to real-world services:

- Execution is assumed to terminate (not applicable to servers)
- Lack of a clear attestation unit for infinite loops
- No visibility into shared libraries (`libc`, `libssl`)
- High deployment overhead (kernel modules or hardware tracing)

As a result, attacks such as ROP/JOP within long-running services often remain undetected under traditional models.

---

## Core Approach

The system is based on three principles:

- **Epoch-based execution modeling**  
  Continuous execution is divided into request-level units.

- **Path-based control-flow representation**  
  Each epoch produces a deterministic path identifier.

- **Runtime instrumentation via eBPF**  
  Uprobes capture execution flow without modifying the target binary.

---

## System Overview

The system operates in two stages:

### Offline Stage

- Extract control-flow structure from the target binary and linked libraries
- Assign weights to control-flow edges
- Construct a database of valid execution paths

---

### Online Stage

- Attach eBPF uprobes to critical execution points
- Track control-flow transitions during execution
- Accumulate a path identifier per epoch
- Emit `(epoch_id, path_id)` to user space
- Validate execution behavior against expected paths

---

## Architecture
~~~
Offline Analysis → Edge Weights + Valid Paths
↓
eBPF Instrumentation (User-space binaries + libraries)
↓
Path Accumulation per Epoch
↓
Userspace Validation / Monitoring

~~~
---

## Implementation Overview

The implementation is structured in incremental stages:

### 1. Epoch Identification

- Attach uprobes to request handling boundaries in the target application
- Define a single request lifecycle as one epoch
- Emit one event per completed epoch

---

### 2. Control-Flow Signal Generation

- Capture instruction pointer transitions
- Form execution edges dynamically
- Compute and accumulate edge weights
- Generate a stable path identifier for each epoch

---

### 3. CFG Integration

- Replace heuristic edge tracking with CFG-derived mappings
- Incorporate shared libraries into control-flow tracking
- Maintain a set of valid execution paths collected from normal runs

---

### 4. Runtime Validation

- Compare observed path identifiers against valid paths
- Flag deviations as potential control-flow violations
- Enable continuous monitoring of execution integrity

---

## Security Perspective

The system detects deviations in execution caused by:

- Unexpected control-flow transitions  
- Missing or altered execution paths  
- Execution outside the known control-flow graph  

Detection occurs at **epoch granularity**, enabling near real-time identification of anomalies in long-running services.

---

## Notes

- Designed for research and prototype-level deployment  
- Requires a Linux system with eBPF support (BTF-enabled kernel recommended)  
- No kernel modification or binary rewriting required  
