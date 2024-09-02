- tried also sorts of krpobes (socket etc.) and tracepoints (tcp_v4_connect etc.)
-  very interesting discussion here: https://github.com/weaveworks/scope/issues/356
- sys call docs; https://aquasecurity.github.io/tracee/v0.14/docs/events/builtin/syscalls/bind/
- using netstat, ss, conntrack etc. did not give me the source/dest IPs, I think because the connection is on a different container
- tracepoint/sock/inet_sock_set_state works well for the incoming connection
- but for an outgoing connection (i.e. in the /second_http test cases) it behaves weird with Go, for some reason there is only a single state change to TCP STATE 2 for the outgoing connection
- accept4 kprobe does not have the destination ip address set, its always 0
- connect kprobe DOES have the dest IP set
- seems impossible to get the FD from any tcp tracepoints
- second best option is to correleate the FD using current_pid_tgid, so the kprobes (write/read/sendto/recvfrom) set the FD on a map with current_pid_tgid as key
- I noticed some kprobe read/writes were called with a buf_len=1 and 0 as the only byte, they setting the FD to a different number and messing it up so I put an if check to prevent that
- In ruby, getsockname() is called after recvfrom("GET / HTTP1.1")

+## Capturing short lived requests
+very interesting discussion here: https://github.com/weaveworks/scope/issues/356
+
+sys call docs; https://aquasecurity.github.io/tracee/v0.14/docs/events/builtin/syscalls/bind/


```
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

    // if (new_state != 5) { // only intercept TCP ESTABLISHED state
    //     return 0;
    // }

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
