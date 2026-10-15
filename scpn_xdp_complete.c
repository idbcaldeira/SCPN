// SPDX-License-Identifier: GPL-2.0
/* ==============================================================================
 * scpn_xdp_complete.c - In-Kernel Deterministic O(1) Sovereign Gatekeeper
 * Target Architecture: Linux Kernel 6.8+ (Native Driver Mode XDP)
 * Target Venue: IEEE/ACM Transactions on Networking (ToN)
 * ============================================================================== */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#ifndef AF_INET6
#define AF_INET6 10
#endif

#ifndef BPF_FIB_LOOKUP_DIRECT
#define BPF_FIB_LOOKUP_DIRECT (1U << 0)
#endif

#define MAX_FLOW_BUCKETS    1024
#define MAX_EXT_HOPS        2
#define IPPROTO_HOPOPTS     0   /* RFC 8200 Hop-by-Hop Telemetry */
#define IPPROTO_DSTOPTS     60  /* RFC 8200 Destination Options */
#define OPT_TYPE_CPSENSE    0x1E
#define OPT_TYPE_CPCOGMAP   0x1F

/* Sobrecarga intrinseca de hardware RDTSC na arquitetura Intel Xeon Gold 6230 */
#define RDTSC_INSTRUMENTATION_OVERHEAD_NS 14

struct cp_sense_ext_hdr {
    __u8   nexthdr;
    __u8   hdrlen;
    __u8   opt_type;
    __u8   opt_data_len;
    __be16 queue_occupancy;
    __be16 link_delay_us;
    __u8   packet_loss_rate;
    __u8   risk_score;
    __be16 reserved_align;
    __be32 node_id;
} __attribute__((aligned(8)));

struct cp_cogmap_ext_hdr {
    __u8   nexthdr;
    __u8   hdrlen;
    __u8   opt_type;
    __u8   opt_data_len;
    __be16 goal_alpha_delay;
    __be16 goal_beta_loss;
    __be16 goal_gamma_risk;
    __be16 goal_delta_sover;
    __be32 policy_mask_flags;
    __be64 xai_ref_id;
} __attribute__((aligned(8)));

struct scpn_audit_event {
    __u64 timestamp_ns;
    __u64 latency_ns;        /* Delta real: (t_verdict - t_ingress) - RDTSC_OVERHEAD */
    __u64 xai_ref_id;
    __u32 flow_label;
    __u32 ingress_ifindex;
    __u32 candidate_egress_ifindex;
    __u8  compliance_verdict; /* 0 = DROP, 1 = PASS */
    __u8  risk_score;
    __u8  pad[6];
} __attribute__((aligned(8)));

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_FLOW_BUCKETS);
    __type(key, __u32);
    __type(value, __u32); /* Bitmask M_TC de 32 interfaces autorizadas */
} sovereignty_mask_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 16 * 1024 * 1024);
} scpn_audit_ringbuf SEC(".maps");

SEC("xdp")
int xdp_scpn_sovereign_gatekeeper(struct xdp_md *ctx) {
    __u64 t_ingress = bpf_ktime_get_ns();
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;

    /* Leitura escalar do contexto: impede mutacao de ponteiro em r6 */
    __u32 ingress_if = ctx->ingress_ifindex;

    /* 1. Validacao L2 Ethernet (Fail-Closed) */
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_DROP;

    if (eth->h_proto != bpf_htons(ETH_P_IPV6))
        return XDP_PASS; /* Nao intercepta trafego IPv4 ou controle L2 (ARP/SSH) */

    /* 2. Validacao L3 IPv6 Base Header (Fail-Closed) */
    struct ipv6hdr *ip6 = (void *)(eth + 1);
    if ((void *)(ip6 + 1) > data_end)
        return XDP_DROP;

    /* Extracao Zero-Copy de Entropia: Flow Label (RFC 6437, 20 bits invariantes) */
    __u32 vtc_flow = bpf_ntohl(*(__be32 *)ip6);
    __u32 flow_label = vtc_flow & 0x000FFFFF;

    /* 3. Travessia Desdobrada de Extensoes (DAG Aciclico Finito para o Verificador) */
    void *cursor = (void *)(ip6 + 1);
    __u8 nexthdr = ip6->nexthdr;
    __u64 extracted_xai_ref = 0;
    __u8  extracted_risk = 0;

    #pragma clang loop unroll(full)
    for (int i = 0; i < MAX_EXT_HOPS; i++) {
        if (nexthdr == IPPROTO_HOPOPTS) {
            struct cp_sense_ext_hdr *sense = cursor;
            if ((void *)(sense + 1) > data_end)
                return XDP_DROP;
            if (sense->opt_type == OPT_TYPE_CPSENSE) {
                extracted_risk = sense->risk_score;
            }
            nexthdr = sense->nexthdr;
            cursor = (void *)(sense + 1);
        } else if (nexthdr == IPPROTO_DSTOPTS) {
            struct cp_cogmap_ext_hdr *cogmap = cursor;
            if ((void *)(cogmap + 1) > data_end)
                return XDP_DROP;
            if (cogmap->opt_type == OPT_TYPE_CPCOGMAP) {
                extracted_xai_ref = bpf_be64_to_cpu(cogmap->xai_ref_id);
            }
            nexthdr = cogmap->nexthdr;
            cursor = (void *)(cogmap + 1);
        }
    }

    /* 4. Resolucao da Rota Candidata de Saida via FIB Lookup Nativa */
    struct bpf_fib_lookup fib_params = {};
    fib_params.family      = AF_INET6;
    fib_params.flowinfo    = *(__be32 *)ip6 & bpf_htonl(0x0FFFFFFF);
    fib_params.l4_protocol = nexthdr;
    fib_params.tot_len     = bpf_ntohs(ip6->payload_len);
    fib_params.ifindex     = ingress_if;
    __builtin_memcpy(fib_params.ipv6_src, &ip6->saddr, sizeof(ip6->saddr));
    __builtin_memcpy(fib_params.ipv6_dst, &ip6->daddr, sizeof(ip6->daddr));

    int rc = bpf_fib_lookup(ctx, &fib_params, sizeof(fib_params), BPF_FIB_LOOKUP_DIRECT);
    
    /* Atribuicao puramente escalar: elimina a instrucao condicional de ponteiro */
    __u32 candidate_egress_if = ingress_if;
    if (rc == BPF_FIB_LKUP_RET_SUCCESS) {
        candidate_egress_if = fib_params.ifindex;
    }

    /* 5. Avaliacao da Mascara Booleana O(1) sem Divisao de Hardware */
    __u32 map_idx = flow_label & (MAX_FLOW_BUCKETS - 1);
    __u32 *allowed_mask = bpf_map_lookup_elem(&sovereignty_mask_map, &map_idx);
    
    __u32 is_compliant = 0;
    if (allowed_mask && *allowed_mask != 0) {
        is_compliant = ((*allowed_mask) & (1U << (candidate_egress_if & 31))) ? 1 : 0;
    }

    /* 6. Calculo da Latencia Microarquitetural de Decisao */
    __u64 t_verdict = bpf_ktime_get_ns();
    __u64 raw_delta = t_verdict - t_ingress;
    __u64 net_latency = (raw_delta > RDTSC_INSTRUMENTATION_OVERHEAD_NS) ? 
                        (raw_delta - RDTSC_INSTRUMENTATION_OVERHEAD_NS) : raw_delta;

    /* 7. Bifurcacao: Encaminhamento em Linha vs. Truncamento com Auditoria */
    if (!is_compliant) {
        struct scpn_audit_event *ev = bpf_ringbuf_reserve(
            &scpn_audit_ringbuf, sizeof(struct scpn_audit_event), 0);
        if (ev) {
            ev->timestamp_ns             = t_verdict;
            ev->latency_ns               = net_latency;
            ev->xai_ref_id               = extracted_xai_ref;
            ev->flow_label               = flow_label;
            ev->ingress_ifindex          = ingress_if;
            ev->candidate_egress_ifindex = candidate_egress_if;
            ev->compliance_verdict       = 0;
            ev->risk_score               = extracted_risk;
            bpf_ringbuf_submit(ev, 0);
        }
        return XDP_DROP; /* Purga no descritor de anel DMA antes do alloc_skb() */
    }

    return XDP_PASS; /* Encaminhamento deterministico na taxa de linha fisica */
}

char _license[] SEC("license") = "GPL";
