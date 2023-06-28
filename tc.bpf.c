// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2022 Hengqi Chen */
#include <vmlinux.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define TC_ACT_UNSPEC -1
#define TC_ACT_OK 0
#define ETH_P_IP 0x0800 /* Internet Protocol packet	*/
#define BUFFER_CHUNK_SIZE 400

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
  int ip_len = bpf_ntohs(ip->tot_len);
  int ip_hdr_len = ip->ihl * 4;

  // TODO: Check if the packet has a payload instead of using arbitrary 80 const value here
  if (ip_len <= 80) {
    bpf_printk("RETURN: ip_len <= 0");
    return TC_ACT_OK;
  }

  // Divide ip_len by chunk size and round up if remainder is non-zero
  unsigned int num_chunks = ip_len / BUFFER_CHUNK_SIZE;
  if (ip_len % BUFFER_CHUNK_SIZE > 0)
    num_chunks++;

  // NOTE: For some reason the ebpf verifier won't accept i < num_chunks in this for loop, but it will
  // accept a hardcoded upper-bound and the if () break; line.
  // Max stack size is 512 bytes and max size an IP packet is 65535 bytes. We set BUFFER_CHUNK_SIZE to
  // 400 to allow for other data on the stack.
  // So 164 = 65535 / 400.
  for (__u32 i = 0; i < 164; i++) {
    if (i >= num_chunks)
      break;

    // TODO: Make it so this only copies the necessary bytes, not all 400
    unsigned int offset = i * BUFFER_CHUNK_SIZE;
    struct iphdr *ip_offset = (struct iphdr *)((void *)ip + offset);

    // TODO: Why is this copying an extra 7 bytes?
    bpf_printk("ip_len: %d, offset: %d, chunk_size: %d", ip_len, offset, ip_len - offset);
    unsigned int chunk_size = min(BUFFER_CHUNK_SIZE, ip_len - offset);

    __u8 chunk[BUFFER_CHUNK_SIZE] = {0};
    bpf_probe_read_kernel(&chunk, BUFFER_CHUNK_SIZE, ip_offset);
    bpf_perf_event_output(skb, &tcp_payloads, BPF_F_CURRENT_CPU, &chunk, chunk_size);
    // bpf_printk("chunk_size: %d", chunk_size);
  }

  return TC_ACT_OK;
}

char __license[] SEC("license") = "GPL";
