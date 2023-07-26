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
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); // 256 KB
} tcp_payloads SEC(".maps");

SEC("tc")
int tc_egress(struct __sk_buff *skb) {
  if (skb->len > 0)
    bpf_skb_pull_data(skb, skb->len);

	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;

  struct ethhdr *eth = data;
  struct iphdr *ip;
  struct tcphdr *tcp;

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

  tcp = data + sizeof(*eth) + sizeof(*ip);
  if ((void *)tcp + sizeof(*tcp) > data_end)
    return TC_ACT_OK;

  // Calculate the length of the TCP header
  unsigned int ip_len = bpf_ntohs(ip->tot_len);
  unsigned int ip_hdr_len = ip->ihl * 4;
  unsigned int ip_payload_len = ip_len - ip_hdr_len;
  unsigned int tcp_header_len = tcp->doff * 4;

  // If there is no TCP payload, then we are not interested
  // if (tcp_header_len == ip_payload_len)
  //   return TC_ACT_OK;

  // Divide ip_len by chunk size and round up if remainder is non-zero
  unsigned int num_chunks = ip_len / BUFFER_CHUNK_SIZE;
  if (ip_len % BUFFER_CHUNK_SIZE > 0)
    num_chunks++;
  bpf_printk("---------------------------------------------------------------");
  bpf_printk("ip_len: %d, num_chunks: %d", ip_len, num_chunks);
  u64 current_pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = current_pid_tgid >> 32;
  u64 current_uid_gid = bpf_get_current_uid_gid();
  u32 uid = current_uid_gid;

  bpf_printk("current_pid_tgid: %d, pid: %d, current_uid_gid: %d", current_pid_tgid, pid, current_uid_gid);

  // NOTE: For some reason the ebpf verifier won't accept i < num_chunks in this for loop, but it will
  // accept a hardcoded upper-bound and the if () break; line.
  // Max stack size is 512 bytes and max size an IP packet is 65535 bytes. We set BUFFER_CHUNK_SIZE to
  // 400 to allow for other data on the stack.
  // So 164 = 65535 / 400.
  for (__u32 i = 0; i < 200; i++) {
    if (i >= num_chunks)
      break;

    unsigned int offset = i * BUFFER_CHUNK_SIZE;
    struct iphdr *ip_chunk = (struct iphdr *)((void *)ip + offset);

    // Get the chunk_size so its... TODO
    __u32 chunk_size = BUFFER_CHUNK_SIZE;
    if (i == num_chunks - 1) {  // If its the last chunk
      chunk_size = ip_len - (BUFFER_CHUNK_SIZE * (num_chunks - 1));
      chunk_size &= 0xffffff;
    }
    if (chunk_size > BUFFER_CHUNK_SIZE)
      return TC_ACT_OK;

    // Copy the IP header into header and the payload chunk into payload
    __u8 payload[BUFFER_CHUNK_SIZE] = {0};
    bpf_probe_read_kernel(&payload, chunk_size, ip_chunk);

    bpf_printk("  %d. chunk_size: %d", i, chunk_size);

    // Copy the header and payload into the chunk
    __u8 chunk[BUFFER_CHUNK_SIZE] = {0};
    __builtin_memcpy(chunk, payload, BUFFER_CHUNK_SIZE);

    // Send the chunk to the userspace
    bpf_ringbuf_output(&tcp_payloads, &chunk, BUFFER_CHUNK_SIZE, 0);

    // if (i == num_chunks - 1) {  // If its the last chunk
    //   __u8 final_chunk[BUFFER_CHUNK_SIZE] = {0};
    //   bpf_ringbuf_output(&tcp_payloads, &final_chunk, BUFFER_CHUNK_SIZE, 0);
    // }
  }

  return TC_ACT_OK;
}

char __license[] SEC("license") = "GPL";
