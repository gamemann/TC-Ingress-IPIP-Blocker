#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/icmp.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/types.h>
#include <inttypes.h>

#ifndef __BPF__
#define __BPF__
#endif

// Debug
//#define DEBUG

#include "helpers.h"
#include "common.h"

#define PIN_GLOBAL_NS 2

struct bpf_elf_map 
{
    __u32 type;
    __u32 size_key;
    __u32 size_value;
    __u32 max_elem;
    __u32 flags;
    __u32 id;
    __u32 pinning;
    __u32 inner_id;
    __u32 inner_idx;
};

struct bpf_elf_map SEC("maps") blacklist_map =
{
    .type = BPF_MAP_TYPE_ARRAY,
    .size_key = sizeof(uint32_t),
    .size_value = sizeof(uint8_t),
    .max_elem = 2048,
    .pinning = PIN_GLOBAL_NS
};

SEC("ingress")
int tc_ingress(struct __sk_buff *skb)
{
    // Initialize packet data.
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;

    // Initialize Ethernet header. 
    struct ethhdr *ethhdr = data;

    // Check Ethernet header's length.
    if (ethhdr + 1 > (struct ethhdr *)data_end)
    {
        return TC_ACT_OK;
    }

    // Check Ethernet protocol and ensure it's IP.
    if (likely(ethhdr->h_proto == htons(ETH_P_IP)))
    {
        // Initialize outer IP header.
        struct iphdr *iphdr = data + sizeof(struct ethhdr);

        // Check outer IP header's length.
        if (unlikely(iphdr + 1 > (struct iphdr *)data_end))
        {
            return TC_ACT_SHOT;
        }

        // Check for IPIP protocol.
        if (iphdr->protocol == IPPROTO_IPIP)
        {
            // Initialize inner IP header.            
            struct iphdr *inner_ip = data + sizeof(struct ethhdr) + sizeof(struct iphdr);

            // Check inner IP header length.
            if (unlikely(inner_ip + 1 > (struct iphdr *)data_end))
            {
                return TC_ACT_SHOT;
            }

            // Check to see if inner IP header's source IP is a part of BPF map.
            uint8_t *val = bpf_map_lookup_elem(&blacklist_map, &inner_ip->saddr);

            if (val && *val > 0)
            {
                // Drop packet since it was found on the blacklist map.
                return TC_ACT_SHOT;     
            }
        }
    }

    // Pass packet.
    return TC_ACT_OK;
}

// License.
char __license[] SEC("license") = "GPL";