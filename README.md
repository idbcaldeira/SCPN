# S-CPN: Sovereign Cognitive Packet Network (In-Kernel eBPF/XDP Data Plane)

![IETF RFC 8200](https://img.shields.io/badge/IETF-RFC_8200_IPv6-blue.svg)
![Linux Kernel eBPF/XDP](https://img.shields.io/badge/Linux_Kernel-eBPF_/_XDP_Native-teal.svg)
![Clang/LLVM 14.0+](https://img.shields.io/badge/Clang/LLVM-14.0+_BPF_JIT-orange.svg)

This repository contains the reference verifier-certified in-kernel eBPF/XDP data-plane implementation and RFC 8200 wire-format definitions (`scpn_xdp_complete.c`) for the **Sovereign Cognitive Packet Network (S-CPN)** architecture, accompanying our manuscript submitted to **IEEE Network Magazine**:

> **Architecting Sub-Microsecond O(1) Data Planes for Sovereign ISD-WANs**  
> *Igor D. B. Caldeira, Ricardo Choren, and Ronaldo M. Salles*  
> Department of Computer Engineering, Military Institute of Engineering (IME), Brazil & CIICESI/ESTG, Polytechnic Institute of Porto, Portugal.

---

## 1. Architectural Overview & Scope

S-CPN resolves the *Opaque Autonomy Paradox* in AI-native Intelligent Software-Defined Wide Area Networks (ISD-WANs) by decoupling stochastic control-plane routing intelligence (System 1) from deterministic, fail-closed data-plane policy enforcement (System 2).

This companion artifact provides the complete, verifier-compliant restricted-C kernel source code (`scpn_xdp_complete.c`) corresponding to **Section III**, **Section IV (Algorithm 1)**, and **Section V** of the article:

1. **RFC 8200 64-Bit Aligned IPv6 Extension Headers:**
   - `CP-SENSE` Hop-by-Hop Option (`OptType = 0x1E`, **16 octets** total): Encapsulates instantaneous queue occupancy (`Q_occ`), link propagation delay (`tau_link`), quantized packet loss (`L_pkt`), localized intrusion risk (`R_sec`), node ID, and 32-bit epoch timestamp (`T_sense`).
   - `CP-COGMAP` Destination Option (`OptType = 0x1F`, **24 octets** total): Encapsulates quantized multi-dimensional optimization weights (`lambda_delay`, `lambda_loss`, `lambda_risk`, `lambda_doc`), 32-bit sovereignty policy flags (`G_S-CPN`), and the 64-bit cryptographic explainability audit pointer (`xai_ref_id`).
2. **O(1) In-Kernel XDP Gatekeeper:**
   - Executes inside the NIC driver NAPI poll loop (`XDP_FLAGS_DRV_MODE`) prior to `sk_buff` allocation.
   - Enforces pointer domination bounds checking (`ptr + sizeof(...) <= data_end`), unrolled depth-2 extension header parsing, direct kernel FIB egress lookup (`bpf_fib_lookup`), constant-time 32-bit bitmask projection, and lockless asynchronous audit streaming via `BPF_MAP_TYPE_RINGBUF`.

---

## 2. Kernel BPF Verifier & Micro-Architectural Footprint

Compiled with `Clang/LLVM 14.0` (`-O2 -target bpf`) using BPF Type Format (BTF) relocations on a hardware-isolated Intel Xeon Gold 6230 host (2.10 GHz):

| Metric / Verification Property | Certified Value |
| :--- | :--- |
| **Attachment Mode** | Native Driver Hook (`XDP_FLAGS_DRV_MODE`) |
| **Static BPF Verifier Complexity** | `763` static BPF instructions (Zero unbounded loops) |
| **JIT-Compiled Native Code Footprint** | `1,004 bytes` (Fits entirely in 32 KB L1i cache) |
| **Maximum Kernel Stack Depth** | `88 bytes` (Strictly within the 512-byte eBPF limit) |
| **Empirical Median Latency (p50)** | `244.00 ns` (~512 CPU clock cycles) |
| **99th-Percentile Tail Latency (p99)** | `323.00 ns` (`p99/p50 = 1.32`, ~678 cycles) |
| **Sustained Line-Rate Throughput** | `10.00 Gbps` (`0.00 ms` socket bufferbloat backlog) |

---

## 3. Compilation and Kernel Verification Instructions

### Building the eBPF Bytecode
Run the provided `Makefile` to compile `scpn_xdp_complete.c` into the kernel BPF object:

    make all

### Inspecting the JIT-Compiled Footprint and Verifier Log
To load the compiled object into the kernel verifier and inspect the translated bytecode and JIT size:

    sudo bpftool prog load scpn_xdp_complete.o /sys/fs/bpf/scpn_gatekeeper type xdp
    sudo bpftool prog show pinned /sys/fs/bpf/scpn_gatekeeper
    sudo bpftool prog dump xlated pinned /sys/fs/bpf/scpn_gatekeeper

### Attaching to a Network Interface in Native Driver Mode

    sudo ip link set dev <ifname> xdpdrv pinned /sys/fs/bpf/scpn_gatekeeper

### Detaching the Gatekeeper

    sudo ip link set dev <ifname> xdpdrv off
    sudo rm /sys/fs/bpf/scpn_gatekeeper

---

## 4. Acknowledgments
This work was supported by FINEP (Cyber Semantics Project No. 0.1.22.0335.00) and CAPES (Finance Code 001).
