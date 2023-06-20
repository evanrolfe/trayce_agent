// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2022 Hengqi Chen */
#include <vmlinux.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define TC_ACT_UNSPEC -1
#define TC_ACT_OK 0
#define ETH_P_IP 0x0800 /* Internet Protocol packet	*/

// struct {
//     __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
//     __uint(key_size, sizeof(u32));
//     __uint(value_size, sizeof(u32));
// } udp_headers SEC(".maps");

// struct {
//     __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
//     __uint(key_size, sizeof(u32));
//     __uint(value_size, sizeof(__u8) * 1500);
//     __uint(max_entries, 1024);
// } udp_headers SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} ip_headers SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} udp_headers SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, 1);
} udp_packets_index SEC(".maps");

// https://medium.com/@nurkholish.halim/a-deep-dive-into-ebpf-writing-an-efficient-dns-monitoring-2c9dea92abdf
// https://taoshu.in/unix/modify-udp-packet-using-ebpf.html
// https://github.com/moolen/udplb
struct event_data {
    struct udphdr udp;
} __attribute__((packed));

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

  __u16 udp_len = bpf_ntohs(udp->len);
  if (udp_len < 8 || udp_len > 10000) {
    return TC_ACT_UNSPEC;
  }

  // if ((void *) ip + 1 > data_end)
  //   return TC_ACT_UNSPEC;

  // if ((void *) udp + udp_len > data_end)
  //   return TC_ACT_UNSPEC;

  // Access the UDP payload
  // __u8 *payload = (void *) udp + udp_len - sizeof(struct udphdr);

  // Find the first empty element of the array:
  __u32 zero_index = 0;
  __u32 *index;
  index = bpf_map_lookup_elem(&udp_packets_index, &zero_index);

  if (!index) {
    bpf_printk("No index value found");
    return TC_ACT_OK;
  }

    // Prepare perf event data
    struct event_data event_data = {};
  __builtin_memcpy(&event_data.udp, udp, sizeof(struct udphdr));

  // Save the UDP header & payload
  // bpf_map_update_elem(&udp_headers, index, payload, BPF_ANY);
  // __u32 value = 10001;
  bpf_perf_event_output(skb, &udp_headers, BPF_F_CURRENT_CPU, &event_data, sizeof(struct event_data));

  // Increment and save the index
  (*index)++;
  bpf_map_update_elem(&udp_packets_index, &zero_index, index, BPF_ANY);

  bpf_printk("Got a request");
  return TC_ACT_OK;
}

char __license[] SEC("license") = "GPL";

  // // Access the UDP length
  // __u16 udp_len = bpf_ntohs(udp->len);

  // // Extract individual decimal digits from UDP length
  // int digit3 = udp_len / 1000;         // Thousands digit
  // int digit2 = (udp_len / 100) % 10;   // Hundreds digit
  // int digit1 = (udp_len / 10) % 10;    // Tens digit
  // int digit0 = udp_len % 10;           // Units digit

  // // Trace print the human-readable decimal digits
  // bpf_printk("UDP source: %lu, len: %d", udp->source, digit3);
  // bpf_printk("UDP len: %d%d%d\n", digit2, digit1, digit0);
