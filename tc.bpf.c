// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2022 Hengqi Chen */
#include <vmlinux.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define TC_ACT_UNSPEC -1
#define TC_ACT_OK 0
#define ETH_P_IP 0x0800 /* Internet Protocol packet	*/
#define BUFFER_CHUNK_SIZE 128
#define IP_HEADER_SIZE 20

// Helper function to find the minimum of two values
static inline unsigned int min(unsigned int a, unsigned int b) {
    return (a < b) ? a : b;
}

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} tcp_payloads SEC(".maps");

SEC("tc")
int tc_egress(struct __sk_buff *skb) {
  if (skb->len > 0)
    bpf_skb_pull_data(skb, skb->len);

	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;

  struct ethhdr *eth = data;
  struct iphdr *ip;

  // Ensure we're not accessing out-of-bounds memory
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

  // Calculate the length of the TCP header
  unsigned int ip_len = bpf_ntohs(ip->tot_len);
  unsigned int ip_hdr_len = ip->ihl * 4;
  unsigned int ip_payload_len = ip_len - ip_hdr_len;

  // TODO: Check if the packet has a payload instead of using arbitrary 80 const value here
  if (ip_len <= 80)
    return TC_ACT_OK;

  // Divide ip_len by chunk size and round up if remainder is non-zero
  unsigned int payload_chunk_size = BUFFER_CHUNK_SIZE-IP_HEADER_SIZE;
  unsigned int num_chunks = ip_payload_len / payload_chunk_size;
  bpf_printk("0 ip_payload_len: %d, num_chunks: %d", ip_payload_len, num_chunks);
  if (ip_payload_len % payload_chunk_size > 0)
    num_chunks++;
  bpf_printk("1 num_chunks: %d", num_chunks);

  // NOTE: For some reason the ebpf verifier won't accept i < num_chunks in this for loop, but it will
  // accept a hardcoded upper-bound and the if () break; line.
  // Max stack size is 512 bytes and max size an IP packet is 65535 bytes. We set BUFFER_CHUNK_SIZE to
  // 400 to allow for other data on the stack.
  // So 164 = 65535 / 400.
  for (__u32 i = 0; i < 200; i++) {
    if (i >= num_chunks)
      break;

    bpf_printk("ip_len: %d, num_chunks: %d", ip_len, num_chunks);

    unsigned int offset = i * payload_chunk_size;
    struct iphdr *ip_header = ip;
    struct iphdr *ip_payload_chunk = (struct iphdr *)((void *)ip + ip_hdr_len + offset);

    // Copy the IP header into header and the payload chunk into payload
    __u8 header[IP_HEADER_SIZE] = {0};
    __u8 payload[BUFFER_CHUNK_SIZE-IP_HEADER_SIZE] = {0};
    bpf_probe_read_kernel(&header, IP_HEADER_SIZE, ip_header);
    bpf_probe_read_kernel(&payload, payload_chunk_size, ip_payload_chunk);

    // Copy the header and payload into the chunk
    __u8 chunk[BUFFER_CHUNK_SIZE] = {0};
    __builtin_memcpy(chunk, header, IP_HEADER_SIZE);
    __builtin_memcpy(chunk + IP_HEADER_SIZE, payload, BUFFER_CHUNK_SIZE - IP_HEADER_SIZE);

    // Send the chunk to the userspace
    bpf_perf_event_output(skb, &tcp_payloads, BPF_F_CURRENT_CPU, &chunk, BUFFER_CHUNK_SIZE);
  }

  return TC_ACT_OK;
}

char __license[] SEC("license") = "GPL";
