#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <stddef.h>
#include <arpa/inet.h>

struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 128);
} XSK SEC(".maps");

volatile const __u16 TEST_PORT = 24862 /* 7777 */;

typedef struct __attribute__((__packed__)) {
    __u8 dst_addr[6];
    __u8 src_addr[6];
    __u16 ether_type;
} EthHdr;

typedef struct {
    __u8 vihl;
    __u8 tos;
    __u8 tot_len[2];
    __u8 id[2];
    __u8 frags[2];
    __u8 ttl;
    __u8 proto;
    __u8 check[2];
    __u8 src_addr[4];
    __u8 dst_addr[4];
} Ipv4Hdr;

typedef struct {
    __u8 vcf[4];
    __u8 payload_len[2];
    __u8 next_hdr;
    __u8 hop_limit;
    __u8 src_addr[16];
    __u8 dst_addr[16];
} Ipv6Hdr;

typedef struct {
    __u16 src;
    __u16 dst;
    __u16 len;
    __u8 check[2];
} UdpHdr;

inline const void* ptr_at(struct xdp_md* ctx, size_t offset, size_t len) {
    if (ctx->data + offset + len > ctx->data_end) {
        return 0;
    }

    return (const void*)(size_t)ctx->data + offset;
}

#define valid_or_pass(name, type, offset) \
    const type* name = (const type*)ptr_at(ctx, offset, sizeof(type)); \
    if (name == 0) { return XDP_PASS; }

#undef bpf_printk
#define bpf_printk(fmt, ...)                            \
({                                                      \
        static const char ____fmt[] = fmt;              \
        bpf_trace_printk(____fmt, sizeof(____fmt),      \
                         ##__VA_ARGS__);                \
})

#define ETHER_TYPE_IPV4 8
#define ETHER_TYPE_IPV6 56710
#define IP_PROTO_UDP 17

SEC("xdp")
int socket_router(struct xdp_md* ctx)
{
    size_t udp_offset = 0;

    bpf_printk("got packet! %u %u", ctx->rx_queue_index, ctx->data_end - ctx->data);

    valid_or_pass(eth, EthHdr, 0)

    bpf_printk("is ether! %u", eth->ether_type);

    if (eth->ether_type == ETHER_TYPE_IPV4) {
        valid_or_pass(ipv4, Ipv4Hdr, sizeof(EthHdr));
        bpf_printk("is ipv4!");
        if (ipv4->proto == IP_PROTO_UDP) {
            udp_offset = sizeof(EthHdr) + sizeof(Ipv4Hdr);
        }
    } else if (eth->ether_type == ETHER_TYPE_IPV6) {
        valid_or_pass(ipv6, Ipv6Hdr, sizeof(EthHdr));
        bpf_printk("is ipv6!");
        if (ipv6->next_hdr == IP_PROTO_UDP) {
            udp_offset = sizeof(EthHdr) + sizeof(Ipv6Hdr);
        }
    }

    if (udp_offset == 0) {
        bpf_printk("not udp!");
        return XDP_PASS;
    }

    valid_or_pass(udp, UdpHdr, udp_offset);
    bpf_printk("udp! %u %u", udp->dst, ntohs(udp->dst));

    if (udp->dst != TEST_PORT) {
        return XDP_PASS;
    }

    return bpf_redirect_map(&XSK, ctx->rx_queue_index, XDP_PASS);
    //return XDP_PASS;
}
