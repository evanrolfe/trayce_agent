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

// SEC("tc")
// int tc_egress(struct __sk_buff *skb) {
// 	void *data = (void *)(long)skb->data;
// 	void *data_end = (void *)(long)skb->data_end;

//   struct ethhdr *eth = data;
//   struct udphdr *udp;
//   struct iphdr *ip;

//   if ((void *)eth + sizeof(*eth) > data_end)
//       return TC_ACT_OK;

//   ip = data + sizeof(*eth);
//   if ((void *)ip + sizeof(*ip) > data_end)
//       return TC_ACT_OK;

//   if (ip->protocol != IPPROTO_UDP)
//       return TC_ACT_OK;

//   udp = (void *)ip + sizeof(*ip);
//   if ((void *)udp + sizeof(*udp) > data_end)
//     return TC_ACT_OK;

//   __u16 udp_len = bpf_ntohs(udp->len);
//   if (udp_len < 8 || udp_len > 10000)
//     return TC_ACT_UNSPEC;

//   if ((void *)udp + udp_len > data_end)
//     return TC_ACT_OK;

//   __u8 c = *((__u8 *)udp + udp_len - 1);

//   __u16 copy_len = udp_len;
//   if (udp_len >= 400) {
//     copy_len = 400;
//   }
//   __u8 my_payload[400] = {0};

//   bpf_probe_read_kernel(&my_payload, copy_len, udp);
//   bpf_perf_event_output(skb, &udp_payloads, BPF_F_CURRENT_CPU, &my_payload, copy_len);

//   bpf_printk("Got a request");
//   return TC_ACT_OK;
// }

SEC("tc")
int tc_egress(struct __sk_buff *skb) {
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;

  struct ethhdr *eth = data;
  struct iphdr *ip;
  struct tcphdr *tcp;

  if ((void *)eth + sizeof(*eth) > data_end)
      return TC_ACT_OK;

  ip = data + sizeof(*eth);
  if ((void *)ip + sizeof(*ip) > data_end)
      return TC_ACT_OK;

  if (ip->protocol != IPPROTO_TCP)
      return TC_ACT_OK;

  if (ip->version != 4) {
    bpf_printk("TODO: Handle IPV6!");
    return TC_ACT_OK;
  }

  tcp = (void *)ip + sizeof(*ip);
  if ((void *)tcp + sizeof(*tcp) > data_end)
    return TC_ACT_OK;

  // Calculate the length of the TCP header
  int tcp_len = bpf_ntohs(ip->tot_len) - (ip->ihl * 4);

  // Check if the packet has a payload
  if (tcp_len <= 0)
    return TC_ACT_OK;


  // Send the TCP Header
  // struct tcphdr my_tcp;
  // bpf_probe_read_kernel(&my_tcp, sizeof(struct tcphdr), tcp);
  // bpf_perf_event_output(skb, &tcp_headers, BPF_F_CURRENT_CPU, &my_tcp, sizeof(struct tcphdr));

  // Send the TCP Payload
  // Get a pointer to the start of the TCP payload
  // void *tcp_payload = (void *)tcp ;
  bpf_printk("tcp_len: %d", tcp_len);


  int copy_len = tcp_len;
  if (copy_len > 400) {
    copy_len = 400;
  }
  __u8 my_payload[400] = {0};

  if ((void *)tcp + copy_len > data_end) {
    bpf_printk("Payload out of bounds! copy_len: %d, diff: %d", copy_len, data_end - (void *)tcp - copy_len);

    return TC_ACT_OK;
  }


  bpf_probe_read_kernel(&my_payload, copy_len, tcp);
  bpf_perf_event_output(skb, &tcp_payloads, BPF_F_CURRENT_CPU, &my_payload, copy_len);

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
