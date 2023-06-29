/* SPDX-License-Identifier: GPL-2.0 */

#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#define KV_PORT 8890

struct {
	__uint(type, BPF_MAP_TYPE_XSKMAP);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, 64);
} xsks_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, 64);
} xdp_stats_map SEC(".maps");

// Header cursor to keep track of current parsing position
struct hdr_cursor {
    void *pos;
};

// Parse the Ethernet header and return the type of the next header
static __always_inline int parse_ethhdr(struct hdr_cursor *nh,
                                        void *data_end,
                                        struct ethhdr **ethhdr)
{
    struct ethhdr *eth = nh->pos;

    // Check that ethernet header is within bounds
    if (eth + 1 > data_end) {
        return -1;
    }

    nh->pos = eth + 1;
    *ethhdr = eth;

    return eth->h_proto;
}

// Parse IPV4 header and return the type of the next header
static __always_inline int parse_iphdr(struct hdr_cursor *nh,
                                       void *data_end,
                                       struct iphdr **iphdr)
{
    struct iphdr *iph = nh->pos;
    int hdrsize;

    // First bounds check
    if (iph + 1 > data_end) {
        return -1;
    }

    hdrsize = iph->ihl * 4;
    // Sanity check
    if (hdrsize < sizeof(*iph)) {
        return -1;
    }

    // Second bounds check
    if (nh->pos + hdrsize > data_end) {
        return -1;
    }

    nh->pos += hdrsize;
    *iphdr = iph;

    return iph->protocol;
}

// Parse the IPV6 header and return the type of the next header
static __always_inline int parse_ipv6hdr(struct hdr_cursor *nh,
                                        void *data_end,
                                        struct ipv6hdr **ipv6hdr)
{
    struct ipv6hdr *ipv6h = nh->pos;

    // Check that the ipv6 header is within bounds
    if (ipv6h + 1 > data_end) {
        return -1;
    }

    nh->pos = ipv6h + 1;
    *ipv6hdr = ipv6h;

    return ipv6h->nexthdr;
}

// Parse the UDP header and return the length of the udp payload
static __always_inline int parse_udphdr(struct hdr_cursor *nh,
                                        void *data_end,
                                        struct udphdr **udphdr)
{
    int len;
    struct udphdr *udph = nh->pos;

    // Check bounds
    if (udph + 1 > data_end) {
        return -1;
    }

    nh->pos = udph + 1;
    *udphdr = udph;

    // Length of payload
    len = bpf_ntohs(udph->len) - sizeof(struct udphdr);
    if (len < 0) {
        return -1;
    }

    return len;
}


SEC("xdp")
int xdp_sock_prog(struct xdp_md *ctx)
{
    void *data_end = (void*)(long)ctx->data_end;
    void *data = (void*)(long)ctx->data;
    struct ethhdr *ethhdr;
    struct iphdr *iphdr;
    struct ipv6hdr *ipv6hdr;
    struct udphdr *udphdr;
    int dport;

    // These keep track of the next header type and iterator pointer
    struct hdr_cursor nh;
    int eth_type, ip_type;

    // Start next header cursor position at data start
    nh.pos = data;
    
    eth_type = parse_ethhdr(&nh, data_end, &ethhdr);
    
    if (eth_type < 0) {
        return XDP_ABORTED;
    }
    else if (eth_type == bpf_htons(ETH_P_IP)) {
        ip_type = parse_iphdr(&nh, data_end, &iphdr);
    }
    else if (eth_type == bpf_htons(ETH_P_IPV6)) {
        ip_type = parse_ipv6hdr(&nh, data_end, &ipv6hdr);
    }
    else {
        return XDP_PASS;
    }

    if (ip_type == IPPROTO_UDP) {
        if (parse_udphdr(&nh, data_end, &udphdr) < 0) {
            return XDP_ABORTED;
        }
    }
    else {
        return XDP_PASS;
    }

    // At this point, we can get the dport from udphdr
    dport = bpf_ntohs(udphdr->dest);
//    if (dport != KV_PORT) {
//        return XDP_PASS;
//    }

    if (dport == KV_PORT) {
    int index = ctx->rx_queue_index;
    __u32 *pkt_count;

    pkt_count = bpf_map_lookup_elem(&xdp_stats_map, &index);
    if (pkt_count) {
        (*pkt_count)++;
    }

    /* A set entry here means that the correspnding queue_id
     * has an active AF_XDP socket bound to it. */
    if (bpf_map_lookup_elem(&xsks_map, &index))
        return bpf_redirect_map(&xsks_map, index, 0);
    }
    else {
    return XDP_PASS;
    }
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
