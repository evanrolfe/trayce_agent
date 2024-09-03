# Tracking source & destination addresses on flows

I've tried many different approaches to getting the source and destination addresses on Flows. The fundamental problem is that the `accept4` syscall only gives us the source address, and the `connect` syscall only gives us the destination address. So we need to obtain the other half from somewhere else.

Things that I tried which failed are:
- Using kprobes for various syscalls like `socket()`, `bind()`, etc. (none of them gave me the source/destination address).
- Using a tracepoint for `sock/inet_sock_set_state` (code below), this did give me the address I needed, but it was unreliable when tracking the outgoing request in `/second_http`. Especially in Go, for some reason, there is only a single state change to TCP STATE 2 for the outgoing connection. Also, it did not give me the FD. I tried correlating the FD with other kprobes using `current_pid_tgid`, but that didn't work well in Go and was a nightmare to debug. I gave up on that.
- Using `netstat` - this did not show the source/destination address, I think because the connection is in a different container.
- Using `ss` & `conntrack` - this showed the source/destination address of the connection but did not give the FD, so I had no way to correlate it with eBPF events.

Finally, I noticed when running `strace -f -p 12`, where 12 is the PID of the Ruby server, that `getsockname()` was always called after `accept4()` and it had the destination address as an argument. I noticed it was called after `connect()` too and was consistent in Ruby, Python, and Go. See `./2024-08-30-0930` for strace output.

For incoming requests using the `accept4()` syscall, `getsockname()` is usually called immediately after `accept4()`. Sometimes `getsockname()` is called after the `sendto/write/read/recvfrom` kprobes; therefore, in the `Socket*` structs in Go, I buffer the flows until the `getsockname()` event is received, which completes the source and destination addresses of the socket. At that point, the flows are released in the same order they came in.

For outgoing requests using the `connect()` syscall, `getsockname()` is actually not used. Instead, I set the container's IP on the `cgroup_name_hashes` map and use that value for the source address. The reason for this is that it's a simpler mechanism, and I usually don't care about the source port of a TCP connection, because it's randomly assigned, unlike the destination port, which will usually be something common like 22, 80, 443, 5432, etc.

**Links of interest:**
https://github.com/weaveworks/scope/issues/356
https://aquasecurity.github.io/tracee/v0.14/docs/events/builtin/syscalls/bind/
https://github.com/DataDog/ebpf-training/blob/main/workshop1/capture-traffic/sourcecode.c

**Tracepoint code**
```c
SEC("tracepoint/sock/inet_sock_set_state")
int trace_inet_sock_set_state(struct trace_event_raw_inet_sock_set_state *args) {
    u64 current_pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = current_pid_tgid >> 32;

    if (!should_intercept()) {
        return 0;
    }

    u32 shost;
    bpf_probe_read_kernel(&shost, sizeof(args->saddr), BPF_CORE_READ(args, saddr));
    u32 dhost;
    bpf_probe_read_kernel(&dhost, sizeof(args->daddr), BPF_CORE_READ(args, daddr));

    u16 sport = args->sport;
    u16 dport = args->dport;
    u8 new_state = args->newstate;

    if (new_state != 5) { // only intercept TCP ESTABLISHED state
        return 0;
    }

    struct sock *sk;
    sk = (struct sock *)BPF_CORE_READ(args, skaddr);

    int fd = 0;
    int *fd2 = bpf_map_lookup_elem(&fd_map, &current_pid_tgid);
    if (fd2 == NULL) {
        bpf_printk("tracepoint/sock/inet_sock_set_state ERROR no fd found");
        // return 0;
    } else {
        fd = *fd2;
    }

    bpf_printk("2kprobetracepoint/sock/inet_sock_set_state found ID: %d FD: %d, state: %d", current_pid_tgid, fd, new_state);

    // Build the connect_event and save it to the map
    struct tcp_state_event_t tcp_event;
    __builtin_memset(&tcp_event, 0, sizeof(tcp_event));
    tcp_event.eventtype = eTCPState;
    tcp_event.pid = pid;
    tcp_event.tid = current_pid_tgid;
    tcp_event.fd = fd;
    tcp_event.state = new_state;
    tcp_event.shost = shost;
    tcp_event.sport = sport;
    tcp_event.dhost = dhost;
    tcp_event.dport = dport;
    bpf_ringbuf_output(&data_events, &tcp_event, sizeof(struct tcp_state_event_t), 0);

    bpf_printk("tracepoint/sock/inet_sock_set_state PID: %d, ID: %d, state: %d, dhost: %d", pid, current_pid_tgid, new_state, dhost);
    return 0;
}
```
