// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2022 Hengqi Chen */
#include <vmlinux.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define TC_ACT_OK 0
#define ETH_P_IP 0x0800 /* Internet Protocol packet	*/

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __be32);
    __type(value, __be32);
    __uint(max_entries, 1 << 10);
} addr_map SEC(".maps");

SEC("tc")
int tc_ingress(struct __sk_buff *ctx) {
  bpf_printk("____________________> BPF STARTING!");
  void *data_end = (void *)(__u64)ctx->data_end;
  void *data = (void *)(__u64)ctx->data;
  struct ethhdr *l2;
  struct iphdr *l3;

  if (ctx->protocol != bpf_htons(ETH_P_IP))
    return TC_ACT_OK;

  l2 = data;
  if ((void *)(l2 + 1) > data_end)
    return TC_ACT_OK;

  l3 = (struct iphdr *)(l2 + 1);
  if ((void *)(l3 + 1) > data_end)
    return TC_ACT_OK;

  u32 key = 42;
  bpf_map_update_elem(&addr_map, &key, &l3->daddr, BPF_ANY);

  bpf_printk("XXX Got IP packet: tot_len: %d, ttl: %d", bpf_ntohs(l3->tot_len), l3->ttl);
  return TC_ACT_OK;
}

char __license[] SEC("license") = "GPL";
