// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2022 Hengqi Chen */
#include <vmlinux.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define TC_ACT_UNSPEC -1
#define TC_ACT_OK 0
#define ETH_P_IP 0x0800 /* Internet Protocol packet	*/

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __be32);
    __type(value, __be32);
    __uint(max_entries, 1 << 10);
} addr_map SEC(".maps");

SEC("tc")
int tc_ingress_old(struct __sk_buff *ctx) {
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

// https://medium.com/@nurkholish.halim/a-deep-dive-into-ebpf-writing-an-efficient-dns-monitoring-2c9dea92abdf
// https://taoshu.in/unix/modify-udp-packet-using-ebpf.html
// https://github.com/moolen/udplb

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, u32);
    __type(value, u64);
    __uint(max_entries, 1 << 10);
} udp_packets SEC(".maps");

SEC("tc")
int tc_egress(struct __sk_buff *skb) {
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;

	if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) > data_end)
		return TC_ACT_UNSPEC;

	struct ethhdr  *eth  = data;
	struct iphdr   *ip   = (data + sizeof(struct ethhdr));
	struct udphdr  *udp  = (data + sizeof(struct ethhdr) + sizeof(struct iphdr));

	// Only allow IP packets
	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return TC_ACT_OK;

	// Only allow UDP
	if (ip->protocol != IPPROTO_UDP)
		return TC_ACT_OK;

  // // Memory access safety checks:
  if ((void *)(eth + 1) > data_end)
    return TC_ACT_OK;

  if ((void *)(ip + 1) > data_end)
    return TC_ACT_OK;

  if ((void *)(udp + 1) > data_end)
    return TC_ACT_OK;

  u32 key = 0;
  u64 *value;

  // Find an empty slot in the BPF array
  for (int i = 0; i < 10; i++) {
      value = bpf_map_lookup_elem(&udp_packets, &key);
      if (value != NULL && *value == 0) {
          break;
      }
      key++;
  }

  // If no empty slot is found, return TC_ACT_OK
  if (value == NULL || *value != 0) {
      return TC_ACT_OK;
  }

  // Add the UDP message to the BPF array
  bpf_map_update_elem(&udp_packets, &key, &udp, BPF_ANY);

  bpf_printk("==> Got UDP message: from: %x UDP len: %d", ip->saddr);

  return TC_ACT_OK;
}

char __license[] SEC("license") = "GPL";
