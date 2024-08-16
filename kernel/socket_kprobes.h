// go:build exclude

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, u64);
  __type(value, struct connect_event_t);
  __uint(max_entries, 1024);
} active_accept4_args_map SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, u64);
  __type(value, struct connect_event_t);
  __uint(max_entries, 1024);
} active_connect_args_map SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, u64);
  __type(value, struct close_event_t);
  __uint(max_entries, 1024);
} active_close_args_map SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, u64);
  __type(value, struct active_buf);
  __uint(max_entries, 1024);
} active_read_args_map SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, u64);
  __type(value, struct active_buf);
  __uint(max_entries, 1024);
} active_write_args_map SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, u64);
  __type(value, struct active_buf);
  __uint(max_entries, 1024);
} active_sendto_args_map SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, u64);
  __type(value, struct active_buf);
  __uint(max_entries, 1024);
} active_recvfrom_args_map SEC(".maps");

// https://linux.die.net/man/3/accept
// int accept(int socket, struct sockaddr *restrict address, socklen_t *restrict address_len);
SEC("kprobe/accept4")
int probe_accept4(struct pt_regs *ctx) {
    u64 current_pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = current_pid_tgid >> 32;

    // Check if PID is intercepted
    u32 *local_ip = bpf_map_lookup_elem(&intercepted_pids, &pid);
    if (local_ip == NULL) {
        return 0;
    }

    struct pt_regs *ctx2 = (struct pt_regs *)PT_REGS_PARM1(ctx);

    // Get the socket file descriptor
    int fd;
    bpf_probe_read(&fd, sizeof(fd), &PT_REGS_PARM1(ctx2));

    struct sockaddr *saddr;
    bpf_probe_read(&saddr, sizeof(saddr), &PT_REGS_PARM2(ctx2));

    // Get the address family
    sa_family_t address_family = 0;
    bpf_probe_read(&address_family, sizeof(address_family), &saddr->sa_family);

    // TODO: Go appears to convert IPv4 hosts to v6, i.e. ::ffff:172.17.0.2, so we need to handle this
    // See:
    // strace -f -e trace=open,close,connect,sendto,recvfrom,send,recv,accept,accept4 -p 1046989

    // Get the ip & port
    struct sockaddr_in *sin = (struct sockaddr_in *)saddr;
    // Build the connect_event and save it to the map
    struct connect_event_t conn_event;
    __builtin_memset(&conn_event, 0, sizeof(conn_event));
    conn_event.eventtype = eConnect;
    conn_event.type = kAccept;
    conn_event.timestamp_ns = bpf_ktime_get_ns();
    conn_event.pid = pid;
    conn_event.tid = current_pid_tgid;
    conn_event.fd = fd;
    conn_event.local = false;
    conn_event.protocol = pUnknown;
    conn_event.local_ip = *local_ip;

    // NOTE: FOr accept4 the IP and port appear to be 0
    bpf_probe_read_user(&conn_event.ip, sizeof(u32), &sin->sin_addr.s_addr);
    bpf_probe_read_user(&conn_event.port, sizeof(u16), &sin->sin_port);

    bpf_map_update_elem(&active_accept4_args_map, &current_pid_tgid, &conn_event, BPF_ANY);

    return 0;
}

// https://linux.die.net/man/3/connect
// int connect(int socket, const struct sockaddr *address, socklen_t address_len);
SEC("kprobe/connect")
int probe_connect(struct pt_regs *ctx) {
    u64 current_pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = current_pid_tgid >> 32;

    // Check if PID is intercepted
    u32 *local_ip = bpf_map_lookup_elem(&intercepted_pids, &pid);
    if (local_ip == NULL) {
        return 0;
    }

    // How the hell did I know to do this ctx2 trick here? Credits to kubearmor:
    // https://github.com/kubearmor/KubeArmor/blob/main/KubeArmor/BPF/system_monitor.c#L1332
    struct pt_regs *ctx2 = (struct pt_regs *)PT_REGS_PARM1(ctx);

    // Get the socket file descriptor
    int fd;
    bpf_probe_read(&fd, sizeof(fd), &PT_REGS_PARM1(ctx2));

    struct sockaddr *saddr;
    bpf_probe_read(&saddr, sizeof(saddr), &PT_REGS_PARM2(ctx2));

    // Get the address family
    sa_family_t address_family = 0;
    bpf_probe_read(&address_family, sizeof(address_family), &saddr->sa_family);

    if (address_family != AF_INET)
        return 0;

    // Get the ip & port
    struct sockaddr_in *sin = (struct sockaddr_in *)saddr;

    // Build the connect_event and save it to the map
    struct connect_event_t conn_event;
    __builtin_memset(&conn_event, 0, sizeof(conn_event));
    conn_event.eventtype = eConnect;
    conn_event.type = kConnect;
    conn_event.timestamp_ns = bpf_ktime_get_ns();
    conn_event.pid = pid;
    conn_event.tid = current_pid_tgid;
    conn_event.fd = fd;
    conn_event.local = false;
    conn_event.protocol = pUnknown;
    conn_event.local_ip = *local_ip;
    bpf_probe_read_user(&conn_event.ip, sizeof(u32), &sin->sin_addr.s_addr);
    bpf_probe_read_user(&conn_event.port, sizeof(u16), &sin->sin_port);

    bpf_map_update_elem(&active_connect_args_map, &current_pid_tgid, &conn_event, BPF_ANY);

    return 0;
}


SEC("kretprobe/accept4")
int probe_ret_accept4(struct pt_regs *ctx) {
    u64 current_pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = current_pid_tgid >> 32;

    // Check the call to connect() was successful
    int fd = (int)PT_REGS_RC(ctx);
    if (fd < 0) {
        return 0;
    }

    // Send entry data from map
    struct connect_event_t *conn_event = bpf_map_lookup_elem(&active_accept4_args_map, &current_pid_tgid);
    if (conn_event != NULL) {
        // Deep copy the connect_event
        struct connect_event_t conn_event2 = copy_connect_event(conn_event, fd);

        // Build the conn_info and save it to the map
        u64 key = gen_pid_fd(current_pid_tgid, fd);
        bpf_map_update_elem(&conn_infos, &key, &conn_event2, BPF_ANY);
        bpf_ringbuf_output(&data_events, &conn_event2, sizeof(struct connect_event_t), 0);
        bpf_printk("kprobe/accept4: Set conn_info ID: %d, FD: %d, Key: %d", current_pid_tgid, fd, key);
    }

    bpf_map_delete_elem(&active_accept4_args_map, &current_pid_tgid);

    return 0;
}

SEC("kretprobe/connect")
int probe_ret_connect(struct pt_regs *ctx) {
    u64 current_pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = current_pid_tgid >> 32;

    // Check the call to connect() was successful
    int res = (int)PT_REGS_RC(ctx);
    if (res > 0)
        return 0;

    // Send entry data from map
    struct connect_event_t *conn_event = bpf_map_lookup_elem(&active_connect_args_map, &current_pid_tgid);

    if (conn_event != NULL) {
        // Deep copy the connect_event
        struct connect_event_t conn_event2 = copy_connect_event(conn_event, conn_event->fd);

        // Build the conn_info and save it to the map
        u64 key = gen_pid_fd(current_pid_tgid, conn_event2.fd);
        bpf_map_update_elem(&conn_infos, &key, &conn_event2, BPF_ANY);
        bpf_ringbuf_output(&data_events, &conn_event2, sizeof(struct connect_event_t), 0);
        bpf_printk("kprobe/connect: Set conn_info PID: %d FD: %d, Key: %d", pid, conn_event2.fd, key);
    }

    bpf_map_delete_elem(&active_connect_args_map, &current_pid_tgid);

    return 0;
}


// https://linux.die.net/man/3/close
// int connect(int fd);
SEC("kprobe/close")
int probe_close(struct pt_regs *ctx) {
    u64 current_pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = current_pid_tgid >> 32;

    // Check if PID is intercepted
    u32 *pid_intercepted = bpf_map_lookup_elem(&intercepted_pids, &pid);
    if (pid_intercepted == NULL) {
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

    if (close_event != NULL) {
        bpf_ringbuf_output(&data_events, close_event, sizeof(struct close_event_t), 0);
        bpf_printk("kprobe/close FD: %d", close_event->fd);

        u64 key = gen_pid_fd(current_pid_tgid, close_event->fd);
        bpf_map_delete_elem(&conn_infos, &key);
    }

    bpf_map_delete_elem(&active_close_args_map, &current_pid_tgid);
    // bpf_map_delete_elem(&fd_map, &current_pid_tgid);

    return 0;
}

SEC("kprobe/sendto")
int probe_sendto(struct pt_regs *ctx) {
    u64 current_pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = current_pid_tgid >> 32;

    // Check if PID is intercepted
    u32 *pid_intercepted = bpf_map_lookup_elem(&intercepted_pids, &pid);
    if (pid_intercepted == NULL) {
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

    // Check if PID is intercepted
    u32 *pid_intercepted = bpf_map_lookup_elem(&intercepted_pids, &pid);
    if (pid_intercepted == NULL) {
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

    // Check if PID is intercepted
    u32 *pid_intercepted = bpf_map_lookup_elem(&intercepted_pids, &pid);
    if (pid_intercepted == NULL) {
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

    // Check if PID is intercepted
    u32 *pid_intercepted = bpf_map_lookup_elem(&intercepted_pids, &pid);
    if (pid_intercepted == NULL) {
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
