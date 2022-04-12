#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>

#define SEC(NAME) __attribute__((section(NAME), used))

SEC("prog")

int ping_drop(struct xdp_md *ctx)
{
    void *data = (void*)(long)ctx->data;         //报文数据开始处
    void *end = (void*)(long)ctx->data_end;      //报文数据结束点

    struct ethhdr *eh;                           //以太头
    eh = data;
    if (data > end)                              //这个检测有点多余，一个合格驱动会保证 
        return XDP_PASS;                         //data一定是小于end的
    if ((void*)(eh+1) > end)                //这个检测非常重要，否则在下面读取 eh->h_proto
        return XDP_PASS;                    //的时候，无法通过bpf verifier的验证，程序就无法加载

    if (eh->h_proto != __constant_htons(ETH_P_IP))   //不是IP报文，放过
        return XDP_PASS;

    struct iphdr *iph;
    iph = (void*)(eh + 1);

    if ((void*)(iph+1) > end)               //这里的检测也非常重要，原因同上
        return XDP_PASS;

    if (iph->protocol == IPPROTO_ICMP)      //判断如果是ping报文，丢弃
        return XDP_DROP;                    //返回 XDP_DROP，会导致无法ping通主机，其他如ssh等不受影响 

    return XDP_PASS;
}

char __license[] SEC("license") = "GPL";
