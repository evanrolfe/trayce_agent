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
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} udp_headers SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} udp_payloads SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} tcp_headers SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} tcp_payloads SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, 1);
} udp_packets_index SEC(".maps");

// https://medium.com/@nurkholish.halim/a-deep-dive-into-ebpf-writing-an-efficient-dns-monitoring-2c9dea92abdf
// https://taoshu.in/unix/modify-udp-packet-using-ebpf.html
// https://github.com/moolen/udplb

SEC("tc")
int tc_egress(struct __sk_buff *skb) {
  if (skb->len > 0)
    bpf_skb_pull_data(skb, skb->len);

  // ===========================================================================
  // Get the new skb:
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;

  struct ethhdr *eth = data;
  struct iphdr *ip;

  if ((void *)eth + sizeof(*eth) > data_end)
      return TC_ACT_OK;

  ip = data + sizeof(*eth);
  if ((void *)ip + sizeof(*ip) > data_end) {
    // bpf_printk("RETURN: ip + sizeof(*ip) > data_end (ip_len: %d)", ip_len);
    return TC_ACT_OK;
  }

  if (ip->protocol != IPPROTO_TCP)
      return TC_ACT_OK;

  if (ip->version != 4) {
    bpf_printk("TODO: Handle IPV6!");
    return TC_ACT_OK;
  }

  // Calculate the length of the TCP header
  int ip_len = bpf_ntohs(ip->tot_len);
  int ip_hdr_len = ip->ihl * 4;

  bpf_printk("---------------------------------------------------------------");
  bpf_printk("ip_len: %d", ip_len);

  // TODO: Check if the packet has a payload instead of using arbitrary 80 const value here
  if (ip_len <= 80) {
    bpf_printk("RETURN: ip_len <= 0");
    return TC_ACT_OK;
  }

  int copy_len = ip_len;
  if (copy_len > 400) {
    bpf_printk("copy_len > 400");
    copy_len = 400;
  }

  if ((void *)ip + copy_len > data_end) {
    bpf_printk("RETURN: Payload out of bounds! ip_len: %d, ip_hdr_len: %d", ip_len, ip_hdr_len);
    return TC_ACT_OK;
  }

  // TODO: Split the ip packet into chunks and send one-at-a-time:
  __u8 my_payload[400] = {0};
  bpf_probe_read_kernel(&my_payload, copy_len, ip);
  bpf_perf_event_output(skb, &tcp_payloads, BPF_F_CURRENT_CPU, &my_payload, copy_len);

  bpf_printk("Got a request");
  return TC_ACT_OK;
}

char __license[] SEC("license") = "GPL";

// for (unsigned int i = 1; i < 3; i++){
//   unsigned int offset = i * 50;
//   struct iphdr *ip_offset = (struct iphdr *)((void *)ip + offset);
//   bpf_probe_read_kernel(&my_payload, copy_len, ip);
//   bpf_perf_event_output(skb, &tcp_payloads, BPF_F_CURRENT_CPU, &my_payload, copy_len);
// }
