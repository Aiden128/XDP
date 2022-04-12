#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp/xdp_ip_filter")
int xdp_ip_filter(struct xdp_md *ctx)
{
    void *end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    u32 ip_src;
    u64 offset;
    u16 eth_type;

    struct ethhdr *eth = data;
    offset = sizeof(*eth);

    if (data + offset > end)
    {
        return XDP_ABORTED;
    }
    eth_type = eth->h_proto;

    /* handle VLAN tagged packet 处理 VLAN 标记的数据包*/
    if (eth_type == htons(ETH_P_8021Q) || eth_type ==
                                              htons(ETH_P_8021AD))
    {
        struct vlan_hdr *vlan_hdr;

        vlan_hdr = (void *)eth + offset;
        offset += sizeof(*vlan_hdr);
        if ((void *)eth + offset > end)
            return false;
        eth_type = vlan_hdr->h_vlan_encapsulated_proto;
    }

    /* let's only handle IPv4 addresses 只处理 IPv4 地址*/
    if (eth_type == ntohs(ETH_P_IPV6))
    {
        return XDP_PASS;
    }

    struct iphdr *iph = data + offset;
    offset += sizeof(struct iphdr);
    /* make sure the bytes you want to read are within the packet's range before reading them
     * 在读取之前，确保你要读取的子节在数据包的长度范围内
     */
    if (iph + 1 > end)
    {
        return XDP_ABORTED;
    }
    ip_src = iph->saddr;

    if (bpf_map_lookup_elem(&blacklist, &ip_src))
    {
        return XDP_DROP;
    }

    return XDP_PASS;
}
