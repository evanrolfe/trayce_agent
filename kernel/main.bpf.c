//go:build exclude

#include <vmlinux.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "common.h"
#include "socket_kprobes.h"
#include "openssl_uprobes.h"

/***********************************************************
 * BPF Go Uprobes
 ***********************************************************/
SEC("uprobe/main.makeRequest")
int probe_entry_go(struct pt_regs* ctx) {
    void* stack_addr = (void*)ctx->sp;

    int arg1;
    char stack[50];

    bpf_probe_read_user(stack, 50, stack_addr);
    bpf_probe_read_user(&arg1, sizeof(arg1), stack_addr+4);

    bpf_printk("!!!!!!!!! CALLED GO! %d", arg1);
    // bpf_ringbuf_output(&debug_events, &arg1, sizeof(arg1), 0);
    // bpf_ringbuf_output(&debug_events, stack, sizeof(stack), 0);

    return 0;
}

char __license[] SEC("license") = "GPL";
