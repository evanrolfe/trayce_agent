// go:build exclude

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, u64);
  __type(value, struct accept_args_t);
  __uint(max_entries, 1024*128);
} active_accept4_args_map SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, u64);
  __type(value, struct accept_args_t);
  __uint(max_entries, 1024*128);
} active_getsockname_args_map SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, u64);
  __type(value, struct accept_args_t);
  __uint(max_entries, 1024*128);
} active_connect_args_map SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, u64);
  __type(value, struct close_event_t);
  __uint(max_entries, 1024*128);
} active_close_args_map SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, u64);
  __type(value, struct active_buf);
  __uint(max_entries, 1024*128);
} active_read_args_map SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, u64);
  __type(value, struct active_buf);
  __uint(max_entries, 1024*128);
} active_write_args_map SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, u64);
  __type(value, struct active_buf);
  __uint(max_entries, 1024*128);
} active_sendto_args_map SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, u64);
  __type(value, struct active_buf);
  __uint(max_entries, 1024*128);
} active_recvfrom_args_map SEC(".maps");

// https://linux.die.net/man/3/accept
// int accept(int socket, struct sockaddr *restrict address, socklen_t *restrict address_len);
SEC("kprobe/accept4")
int probe_accept4(struct pt_regs *ctx) {
    u64 current_pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = current_pid_tgid >> 32;

    if (!should_intercept()) {
        return 0;
    }

    bpf_printk("kprobe/accept entry: PID: %d\n", pid);
    struct pt_regs *ctx2 = (struct pt_regs *)PT_REGS_PARM1(ctx);

    struct sockaddr *saddr;
    bpf_probe_read(&saddr, sizeof(saddr), &PT_REGS_PARM2(ctx2));

    // Build the connect_event and save it to the map
    struct accept_args_t accept_args = {};
    accept_args.addr = (struct sockaddr_in *)saddr;
    bpf_map_update_elem(&active_accept4_args_map, &current_pid_tgid, &accept_args, BPF_ANY);

    return 0;
}

SEC("kretprobe/accept4")
int probe_ret_accept4(struct pt_regs *ctx) {
    u64 current_pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = current_pid_tgid >> 32;

    struct accept_args_t* accept_args = bpf_map_lookup_elem(&active_accept4_args_map, &current_pid_tgid);
    if (accept_args == NULL) {
        return 0;
    }

    // Get the FD and check the call to accept4() was successful
    int fd = (int)PT_REGS_RC(ctx);
    if (fd < 0) {
        bpf_printk("kprobe/accept return: failed: PID: %d, FD: %d\n", pid, fd);
        return 0;
    }

    // Get the source IP & port
    struct addr_t src_addr = {};
    parse_address(&src_addr, accept_args);

    // Get the cgroup name
    struct task_struct *cur_tsk = (struct task_struct *)bpf_get_current_task();
    if (cur_tsk == NULL) {
        bpf_printk("kprobe/accept return: failed to get cur task PID: %d, FD: %d\n", pid, fd);
        return -1;
    }
    int cgrp_id = memory_cgrp_id;
    const char *name = BPF_CORE_READ(cur_tsk, cgroups, subsys[cgrp_id], cgroup, kn, name);

    // Build the connect_event and save it to the map
    struct connect_event_t conn_event;
    __builtin_memset(&conn_event, 0, sizeof(conn_event));
    conn_event.eventtype = eConnect;
    conn_event.type = kAccept;
    conn_event.timestamp_ns = bpf_ktime_get_ns();
    conn_event.pid = pid;
    conn_event.tid = current_pid_tgid;
    conn_event.fd = fd;
    conn_event.src_host = src_addr.ip;
    conn_event.src_port = src_addr.port;
    conn_event.dest_host = 0;
    conn_event.dest_port = 0;
    bpf_probe_read_str(&conn_event.cgroup, sizeof(conn_event.cgroup), name);

    bpf_map_delete_elem(&active_accept4_args_map, &current_pid_tgid);
    bpf_printk("kprobe/accept return: PID: %d, FD: %d", pid, fd);
    bpf_ringbuf_output(&data_events, &conn_event, sizeof(struct connect_event_t), 0);

    return 0;
}

// https://linux.die.net/man/3/connect
// int connect(int socket, const struct sockaddr *address, socklen_t address_len);
SEC("kprobe/connect")
int probe_connect(struct pt_regs *ctx) {
    u64 current_pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = current_pid_tgid >> 32;

    if (!should_intercept()) {
        return 0;
    }

    struct pt_regs *ctx2 = (struct pt_regs *)PT_REGS_PARM1(ctx);

    // Get the socket file descriptor
    int fd;
    bpf_probe_read(&fd, sizeof(fd), &PT_REGS_PARM1(ctx2));

    struct sockaddr *saddr;
    bpf_probe_read(&saddr, sizeof(saddr), &PT_REGS_PARM2(ctx2));

    // Build the connect_event and save it to the map
    struct accept_args_t connect_args = {};
    connect_args.addr = (struct sockaddr_in *)saddr;
    connect_args.fd = fd;
    bpf_map_update_elem(&active_connect_args_map, &current_pid_tgid, &connect_args, BPF_ANY);

    return 0;
}

SEC("kretprobe/connect")
int probe_ret_connect(struct pt_regs *ctx) {
    u64 current_pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = current_pid_tgid >> 32;

    // NOTE: we do not check if return value is successful because it might be EINPROGRESS which we still want to track
    struct accept_args_t* connect_args = bpf_map_lookup_elem(&active_connect_args_map, &current_pid_tgid);
    if (connect_args == NULL) {
        return 0;
    }

    // Get the IP of the container which this requests originates from
    u32 src_ip = should_intercept();

    // Get the source IP & port
    struct addr_t dest_addr = {};
    parse_address(&dest_addr, connect_args);

    // Get the cgroup name
    struct task_struct *cur_tsk = (struct task_struct *)bpf_get_current_task();
    if (cur_tsk == NULL) {
        bpf_printk("failed to get cur task\n");
        return -1;
    }
    int cgrp_id = memory_cgrp_id;
    const char *name = BPF_CORE_READ(cur_tsk, cgroups, subsys[cgrp_id], cgroup, kn, name);

    // Build the connect_event and save it to the map
    struct connect_event_t conn_event;
    __builtin_memset(&conn_event, 0, sizeof(conn_event));
    conn_event.eventtype = eConnect;
    conn_event.type = kConnect;
    conn_event.timestamp_ns = bpf_ktime_get_ns();
    conn_event.pid = pid;
    conn_event.tid = current_pid_tgid;
    conn_event.fd = connect_args->fd;
    conn_event.src_host = src_ip;
    conn_event.src_port = 0;
    conn_event.dest_host = dest_addr.ip;
    conn_event.dest_port = dest_addr.port;
    bpf_probe_read_str(&conn_event.cgroup, sizeof(conn_event.cgroup), name);

    bpf_ringbuf_output(&data_events, &conn_event, sizeof(struct connect_event_t), 0);
    bpf_map_delete_elem(&active_connect_args_map, &current_pid_tgid);
    bpf_printk("kprobe/connect: return PID: %d, FD: %d, IP: %d Port: %x", pid, connect_args->fd, dest_addr.ip, dest_addr.port);

    return 0;
}

// https://linux.die.net/man/3/getsockname
// int getsockname(int socket, struct sockaddr *restrict address, socklen_t *restrict address_len);
SEC("kprobe/getsockname")
int probe_getsockname(struct pt_regs *ctx) {
    u64 current_pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = current_pid_tgid >> 32;

    if (!should_intercept()) {
        return 0;
    }
    struct pt_regs *ctx2 = (struct pt_regs *)PT_REGS_PARM1(ctx);

    // Get the socket file descriptor
    int fd;
    bpf_probe_read(&fd, sizeof(fd), &PT_REGS_PARM1(ctx2));

    struct sockaddr *saddr;
    bpf_probe_read(&saddr, sizeof(saddr), &PT_REGS_PARM2(ctx2));

    struct accept_args_t getsockname_args = {};
    getsockname_args.addr = (struct sockaddr_in *)saddr;
    getsockname_args.fd = fd;
    bpf_map_update_elem(&active_getsockname_args_map, &current_pid_tgid, &getsockname_args, BPF_ANY);

    return 0;
}

SEC("kretprobe/getsockname")
int probe_ret_getsockname(struct pt_regs *ctx) {
    u64 current_pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = current_pid_tgid >> 32;

    if (!should_intercept()) {
        return 0;
    }

    struct accept_args_t* getsockname_args = bpf_map_lookup_elem(&active_getsockname_args_map, &current_pid_tgid);
    if (getsockname_args == NULL) {
        return 0;
    }

    // Get the IP address and port
    u32 ip_addr = 0;
    u16 port = 0;
    struct sockaddr_in sin = {};
    struct sockaddr_in6 sin6 = {};

    // Read the address based on the sa_family
    struct sockaddr* saddr = (struct sockaddr *) getsockname_args->addr;
    sa_family_t address_family = 0;
    bpf_probe_read(&address_family, sizeof(address_family), &saddr->sa_family);

    if (address_family == AF_INET) {
        bpf_probe_read(&sin, sizeof(sin), getsockname_args->addr);
        ip_addr = sin.sin_addr.s_addr;
        port = sin.sin_port;
    } else if (address_family == AF_INET6) {
        bpf_probe_read(&sin6, sizeof(sin6), getsockname_args->addr);
        port = sin6.sin6_port;
        u8 ipv6_addr[16];
        bpf_probe_read(&ipv6_addr, sizeof(ipv6_addr), &sin6.sin6_addr);

        // Check if it's an IPv4-mapped IPv6 address (::ffff:0:0/96 prefix)
        if (ipv6_addr[0] == 0 && ipv6_addr[1] == 0 && ipv6_addr[2] == 0 && ipv6_addr[3] == 0 &&
            ipv6_addr[4] == 0 && ipv6_addr[5] == 0 && ipv6_addr[6] == 0 && ipv6_addr[7] == 0 &&
            ipv6_addr[8] == 0 && ipv6_addr[9] == 0 && ipv6_addr[10] == 0xff && ipv6_addr[11] == 0xff) {
            // Extract the IPv4 address from the last 4 bytes
            ip_addr = *(u32 *)&ipv6_addr[12];
        }
    }

    // Deep copy the connect_event
    struct getsockname_event_t sock_event;
    __builtin_memset(&sock_event, 0, sizeof(sock_event));
    sock_event.eventtype = eGetsockname;
    sock_event.timestamp_ns = bpf_ktime_get_ns();
    sock_event.pid = pid;
    sock_event.tid = current_pid_tgid;
    sock_event.fd = getsockname_args->fd;
    sock_event.host = ip_addr;
    sock_event.port = port;

    bpf_ringbuf_output(&data_events, &sock_event, sizeof(struct getsockname_event_t), 0);
    bpf_printk("kprobe/getsockname: return PID: %d, FD: %d, IP: %d Port: %x", pid, getsockname_args->fd, ip_addr, port);

   return 0;
}

// https://linux.die.net/man/3/close
// int connect(int fd);
SEC("kprobe/close")
int probe_close(struct pt_regs *ctx) {
    u64 current_pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = current_pid_tgid >> 32;

    if (!should_intercept()) {
        return 0;
    }

    struct pt_regs *ctx2 = (struct pt_regs *)PT_REGS_PARM1(ctx);

    // Get the socket file descriptor
    int fd;
    bpf_probe_read(&fd, sizeof(fd), &PT_REGS_PARM1(ctx2));

    // Build the connect_event and save it to the map
    struct close_event_t close_event;
    __builtin_memset(&close_event, 0, sizeof(close_event));
    close_event.eventtype = eClose;
    close_event.timestamp_ns = bpf_ktime_get_ns();
    close_event.pid = pid;
    close_event.tid = current_pid_tgid;
    close_event.fd = fd;

    bpf_map_update_elem(&active_close_args_map, &current_pid_tgid, &close_event, BPF_ANY);

    return 0;
}

SEC("kretprobe/close")
int probe_ret_close(struct pt_regs *ctx) {
    u64 current_pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = current_pid_tgid >> 32;

    // Check the call to close() was successful
    int res = (int)PT_REGS_RC(ctx);
    if (res != 0)
        return 0;

    // Send entry data from map
    struct close_event_t *close_event = bpf_map_lookup_elem(&active_close_args_map, &current_pid_tgid);

    if (close_event == NULL) {
        return 0;
    }

    bpf_ringbuf_output(&data_events, close_event, sizeof(struct close_event_t), 0);
    bpf_printk("kprobe/close FD: %d", close_event->fd);
    bpf_map_delete_elem(&active_close_args_map, &current_pid_tgid);

    return 0;
}

SEC("kprobe/sendto")
int probe_sendto(struct pt_regs *ctx) {
    u64 current_pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = current_pid_tgid >> 32;

    if (!should_intercept()) {
        return 0;
    }

    struct pt_regs *ctx2 = (struct pt_regs *)PT_REGS_PARM1(ctx);

    // Get the socket file descriptor
    int fd;
    bpf_probe_read(&fd, sizeof(fd), &PT_REGS_PARM1(ctx2));
    bpf_printk("kprobe/sendto: ID: %d FD: %d", current_pid_tgid, fd);

    // Save the FD incase SSL_Read or SSL_Write need it
    bpf_map_update_elem(&fd_map, &current_pid_tgid, &fd, BPF_ANY);

    // Get the buffer
    const char *buf;
    bpf_probe_read(&buf, sizeof(buf), &PT_REGS_PARM2(ctx2));

    // Get the Address family (important to filter out netlink messages)
    struct sockaddr *saddr;
    bpf_probe_read(&saddr, sizeof(saddr), &PT_REGS_PARM5(ctx2));

    // Get the address family
    sa_family_t address_family = 0;
    bpf_probe_read(&address_family, sizeof(address_family), &saddr->sa_family);

    if (address_family != AF_INET && address_family != 0)
        return 0;

    struct active_buf active_buf_t;
    __builtin_memset(&active_buf_t, 0, sizeof(active_buf_t));
    active_buf_t.fd = fd;
    active_buf_t.version = 0;
    active_buf_t.buf = buf;
    bpf_map_update_elem(&active_sendto_args_map, &current_pid_tgid, &active_buf_t, BPF_ANY);

    return 0;
}

SEC("kretprobe/sendto")
int probe_ret_sendto(struct pt_regs *ctx) {
    u64 current_pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = current_pid_tgid >> 32;

    struct active_buf *active_buf_t = bpf_map_lookup_elem(&active_sendto_args_map, &current_pid_tgid);

    if (active_buf_t != NULL) {
        const char *buf;
        u32 fd = active_buf_t->fd;
        s32 version = active_buf_t->version;
        size_t buf_len = (size_t)PT_REGS_RC(ctx);
        bpf_probe_read(&buf, sizeof(const char *), &active_buf_t->buf);

        process_data(ctx, current_pid_tgid, kSendto, buf, buf_len, fd);
    }
    bpf_map_delete_elem(&active_sendto_args_map, &current_pid_tgid);

    return 0;
}

SEC("kprobe/recvfrom")
int probe_recvfrom(struct pt_regs *ctx) {
    u64 current_pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = current_pid_tgid >> 32;

    if (!should_intercept()) {
        return 0;
    }

    struct pt_regs *ctx2 = (struct pt_regs *)PT_REGS_PARM1(ctx);

    // Get the socket file descriptor
    int fd;
    bpf_probe_read(&fd, sizeof(fd), &PT_REGS_PARM1(ctx2));
    bpf_printk("kprobe/recvfrom: ID: %d FD: %d", current_pid_tgid, fd);

    // Save the FD incase SSL_Read or SSL_Write need it
    bpf_map_update_elem(&fd_map, &current_pid_tgid, &fd, BPF_ANY);

    // Get the buffer
    const char *buf;
    bpf_probe_read(&buf, sizeof(buf), &PT_REGS_PARM2(ctx2));

    // Get the Address family (important to filter out netlink messages)
    struct sockaddr *saddr;
    bpf_probe_read(&saddr, sizeof(saddr), &PT_REGS_PARM5(ctx2));

    // Get the address family
    sa_family_t address_family = 0;
    bpf_probe_read(&address_family, sizeof(address_family), &saddr->sa_family);

    if (address_family != AF_INET && address_family != 0)
        return 0;

    struct active_buf active_buf_t;
    __builtin_memset(&active_buf_t, 0, sizeof(active_buf_t));
    active_buf_t.fd = fd;
    active_buf_t.version = 1;
    active_buf_t.buf = buf;
    bpf_map_update_elem(&active_recvfrom_args_map, &current_pid_tgid, &active_buf_t, BPF_ANY);

    return 0;
}

SEC("kretprobe/recvfrom")
int probe_ret_recvfrom(struct pt_regs *ctx) {
    u64 current_pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = current_pid_tgid >> 32;

    struct active_buf *active_buf_t = bpf_map_lookup_elem(&active_recvfrom_args_map, &current_pid_tgid);

    if (active_buf_t != NULL) {
        const char *buf;
        u32 fd = active_buf_t->fd;
        s32 version = active_buf_t->version;
        size_t buf_len = (size_t)PT_REGS_RC(ctx);
        bpf_probe_read(&buf, sizeof(const char *), &active_buf_t->buf);

        process_data(ctx, current_pid_tgid, kRecvfrom, buf, buf_len, fd);
    }
    bpf_map_delete_elem(&active_recvfrom_args_map, &current_pid_tgid);
    return 0;
}

SEC("kprobe/write")
int probe_write(struct pt_regs *ctx) {
    u64 current_pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = current_pid_tgid >> 32;

    if (!should_intercept()) {
        return 0;
    }

    struct pt_regs *ctx2 = (struct pt_regs *)PT_REGS_PARM1(ctx);

    // Get the socket file descriptor
    int fd;
    bpf_probe_read(&fd, sizeof(fd), &PT_REGS_PARM1(ctx2));

    // Save the FD incase SSL_Read or SSL_Write need it
    bpf_map_update_elem(&fd_map, &current_pid_tgid, &fd, BPF_ANY);

    // Get the buffer
    const char *buf;
    bpf_probe_read(&buf, sizeof(buf), &PT_REGS_PARM2(ctx2));

    // Get the buffer length
    int buf_len;
    bpf_probe_read(&buf_len, sizeof(buf_len), &PT_REGS_PARM3(ctx2));

    struct active_buf active_buf_t;
    __builtin_memset(&active_buf_t, 0, sizeof(active_buf_t));
    active_buf_t.fd = fd;
    active_buf_t.version = 1;
    active_buf_t.buf = buf;
    active_buf_t.buf_len = buf_len;
    bpf_map_update_elem(&active_write_args_map, &current_pid_tgid, &active_buf_t, BPF_ANY);

    bpf_printk("kprobe/write: entry PID: %d FD: %d, ID: %d", pid, fd, current_pid_tgid);

    return 0;
}

SEC("kretprobe/write")
int probe_ret_write(struct pt_regs *ctx) {
    u64 current_pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = current_pid_tgid >> 32;

    // Check the call to close() was successful
    int res = (int)PT_REGS_RC(ctx);
    if (res < 0)
        return 0;

    struct active_buf *active_buf_t = bpf_map_lookup_elem(&active_write_args_map, &current_pid_tgid);

    if (active_buf_t != NULL) {
        const char *buf;
        u32 fd = active_buf_t->fd;
        s32 version = active_buf_t->version;
        size_t buf_len = (size_t)PT_REGS_RC(ctx);
        bpf_probe_read(&buf, sizeof(const char *), &active_buf_t->buf);

        process_data(ctx, current_pid_tgid, kWrite, buf, buf_len, fd);
    }
    bpf_map_delete_elem(&active_write_args_map, &current_pid_tgid);

    return 0;
}

// ssize_t read(int fd, void *buf, size_t count);
SEC("kprobe/read")
int probe_read(struct pt_regs *ctx) {
    u64 current_pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = current_pid_tgid >> 32;

    if (!should_intercept()) {
        return 0;
    }

    struct pt_regs *ctx2 = (struct pt_regs *)PT_REGS_PARM1(ctx);

    // Get the socket file descriptor
    int fd;
    bpf_probe_read(&fd, sizeof(fd), &PT_REGS_PARM1(ctx2));

    // Get the buffer
    const char *buf;
    bpf_probe_read(&buf, sizeof(buf), &PT_REGS_PARM2(ctx2));

    // Get the buffer length
    int buf_len;
    bpf_probe_read(&buf_len, sizeof(buf_len), &PT_REGS_PARM3(ctx2));

    struct active_buf active_buf_t;
    __builtin_memset(&active_buf_t, 0, sizeof(active_buf_t));
    active_buf_t.fd = fd;
    active_buf_t.version = 1;
    active_buf_t.buf = buf;
    active_buf_t.buf_len = buf_len;
    bpf_map_update_elem(&active_read_args_map, &current_pid_tgid, &active_buf_t, BPF_ANY);
    bpf_printk("kprobe/read: entry FD: %d, ID: %d", fd, current_pid_tgid);

    return 0;
}

SEC("kretprobe/read")
int probe_ret_read(struct pt_regs *ctx) {
    u64 current_pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = current_pid_tgid >> 32;

    // Check the call to close() was successful
    int bytes_read = (int)PT_REGS_RC(ctx);
    if (bytes_read < 0)
        return 0;

    struct active_buf *active_buf_t = bpf_map_lookup_elem(&active_read_args_map, &current_pid_tgid);

    if (active_buf_t != NULL) {
        const char *buf;
        u32 fd = active_buf_t->fd;
        s32 version = active_buf_t->version;
        size_t buf_len = (size_t)PT_REGS_RC(ctx);
        bpf_probe_read(&buf, sizeof(const char *), &active_buf_t->buf);

        process_data(ctx, current_pid_tgid, kRead, buf, buf_len, fd);
    }
    bpf_map_delete_elem(&active_read_args_map, &current_pid_tgid);
    return 0;
}
