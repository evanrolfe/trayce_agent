//go:build exclude

#include <vmlinux.h>
#include "bpf/bpf_core_read.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "common.h"
#include "go_arg.h"
#include "socket_kprobes.h"
#include "openssl_uprobes.h"
#include "go_tls_uprobes.h"
#include "node_openssl_trace.h"

char __license[] SEC("license") = "GPL";
