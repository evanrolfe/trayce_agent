// go:build exclude

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
    bpf_printk("kprobe/accept4: PID: %d FD: %d", pid, fd);
    struct sockaddr *saddr;
    bpf_probe_read(&saddr, sizeof(saddr), &PT_REGS_PARM2(ctx2));

    // Get the address family
    sa_family_t address_family = 0;
    bpf_probe_read(&address_family, sizeof(address_family), &saddr->sa_family);

    // ---------------------------------------------------------------------------------------------
    // struct socket *sock;
    // struct sockaddr_in *addr_in;

    // bpf_probe_read(&sock, sizeof(sock), &((struct file *)saddr)->private_data);

    // if (address_family == AF_INET) {
    //     struct sockaddr_in *sin = (struct sockaddr_in *)saddr;
    //     // int dport;
    //     // bpf_probe_read(&dport, sizeof(u16), &sin->sin_port);
    //     // dog_debug(pid, current_pid_tgid, dport, "port");
    //     u16 dport;
    //     bpf_probe_read_user(&dport, sizeof(u16), &sin->sin_port);
    //     dog_debug(pid, current_pid_tgid, dport, "port");

    // }
    // ---------------------------------------------------------------------------------------------

    // if (address_family == AF_INET6)
    // TODO: Go appears to convert IPv4 hosts to v6, i.e. ::ffff:172.17.0.2, so we need to handle this
    // See:
    // strace -f -e trace=open,close,connect,sendto,recvfrom,send,recv,accept,accept4 -p 1046989

    // Get the ip & port
    struct sockaddr_in *sin = (struct sockaddr_in *)saddr;
    // Build the connect_event and save it to the map
    struct connect_event_t conn_event;
    __builtin_memset(&conn_event, 0, sizeof(conn_event));
    conn_event.eventtype = eConnect;
    conn_event.timestamp_ns = bpf_ktime_get_ns();
    conn_event.pid = pid;
    conn_event.tid = current_pid_tgid;
    conn_event.fd = fd;
    conn_event.local = false;
    conn_event.ssl = false;
    conn_event.protocol = pUnknown;
    conn_event.local_ip = *local_ip;
    bpf_probe_read_user(&conn_event.ip, sizeof(u32), &sin->sin_addr.s_addr);
    bpf_probe_read_user(&conn_event.port, sizeof(u16), &sin->sin_port);

    bpf_map_update_elem(&active_connect_args_map, &current_pid_tgid, &conn_event, BPF_ANY);


    // Build the conn_info and save it to the map
    u64 key = gen_pid_fd(current_pid_tgid, fd);
    bpf_map_update_elem(&conn_infos, &key, &conn_event, BPF_ANY);

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
    struct connect_event_t *conn_event = bpf_map_lookup_elem(&active_connect_args_map, &current_pid_tgid);
    if (conn_event != NULL) {
        conn_event->fd = fd;
        bpf_ringbuf_output(&data_events, conn_event, sizeof(struct connect_event_t), 0);
    }

    bpf_map_delete_elem(&active_connect_args_map, &current_pid_tgid);

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
        bpf_printk("kprobe/connect: PID: %d FD: %d", pid, fd);
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
    conn_event.timestamp_ns = bpf_ktime_get_ns();
    conn_event.pid = pid;
    conn_event.tid = current_pid_tgid;
    conn_event.fd = fd;
    conn_event.local = false;
    conn_event.ssl = false;
    conn_event.protocol = pUnknown;
    conn_event.local_ip = *local_ip;
    bpf_probe_read_user(&conn_event.ip, sizeof(u32), &sin->sin_addr.s_addr);
    bpf_probe_read_user(&conn_event.port, sizeof(u16), &sin->sin_port);

    bpf_map_update_elem(&active_connect_args_map, &current_pid_tgid, &conn_event, BPF_ANY);

    // Build the conn_info and save it to the map
    u64 key = gen_pid_fd(current_pid_tgid, fd);
    bpf_map_update_elem(&conn_infos, &key, &conn_event, BPF_ANY);

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
        bpf_ringbuf_output(&data_events, conn_event, sizeof(struct connect_event_t), 0);
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
        bpf_printk("kprobe/close: PID: %d FD: %d", pid, fd);

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

        u64 key = gen_pid_fd(current_pid_tgid, close_event->fd);
        bpf_map_delete_elem(&conn_infos, &key);
    }

    bpf_map_delete_elem(&active_close_args_map, &current_pid_tgid);

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
        bpf_probe_read(&buf, sizeof(const char *), &active_buf_t->buf);

        u64 ssl_ptr = 0;
        process_data(ctx, current_pid_tgid, kSendto, buf, fd, version, 0, ssl_ptr);
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
        // bpf_printk("recvfrom pid: %d,, current_pid_tgid %d, fd: %d", pid, current_pid_tgid, fd);
        s32 version = active_buf_t->version;
        bpf_probe_read(&buf, sizeof(const char *), &active_buf_t->buf);
        u64 ssl_ptr = 0;
        process_data(ctx, current_pid_tgid, kRecvfrom, buf, fd, version, 0, ssl_ptr);
    }
    bpf_map_delete_elem(&active_recvfrom_args_map, &current_pid_tgid);
    return 0;
}

/***********************************************************
 * BPF kprobes for Go
 ***********************************************************/
static __inline void infer_http_message(struct connect_event_t *conn_info, const char *buf) {
    if (buf[0] == 'H' && buf[1] == 'T' && buf[2] == 'T' && buf[3] == 'P') {
        conn_info->protocol = pHttp;
    }
    if (buf[0] == 'G' && buf[1] == 'E' && buf[2] == 'T') {
        conn_info->protocol = pHttp;
    }
    if (buf[0] == 'H' && buf[1] == 'E' && buf[2] == 'A' && buf[3] == 'D') {
        conn_info->protocol = pHttp;
    }
    if (buf[0] == 'P' && buf[1] == 'O' && buf[2] == 'S' && buf[3] == 'T') {
        conn_info->protocol = pHttp;
    }
    if (buf[0] == 'P' && buf[1] == 'U' && buf[2] == 'T') {
        conn_info->protocol = pHttp;
    }
    if (buf[0] == 'P' && buf[1] == 'A' && buf[2] == 'T' && buf[3] == 'C' && buf[4] == 'H') {
        conn_info->protocol = pHttp;
    }
    if (buf[0] == 'D' && buf[1] == 'E' && buf[2] == 'L' && buf[3] == 'E' && buf[4] == 'T' && buf[5] == 'E') {
        conn_info->protocol = pHttp;
    }
    if (buf[0] == 'O' && buf[1] == 'P' && buf[2] == 'T' && buf[3] == 'I' && buf[4] == 'O' && buf[5] == 'N' && buf[6] == 'S') {
        conn_info->protocol = pHttp;
    }
    if (buf[0] == 'T' && buf[1] == 'R' && buf[2] == 'A' && buf[3] == 'C' && buf[4] == 'E') {
        conn_info->protocol = pHttp;
    }
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

    // Get the buffer
    const char *buf;
    bpf_probe_read(&buf, sizeof(buf), &PT_REGS_PARM2(ctx2));

    // Get the buffer length
    int buf_len;
    bpf_probe_read(&buf_len, sizeof(buf_len), &PT_REGS_PARM3(ctx2));

    // Find the matching connect event so we can filter out non-socket write() calls
    u64 key = gen_pid_fd(current_pid_tgid, fd);
    struct connect_event_t *conn_info = bpf_map_lookup_elem(&conn_infos, &key);
    if (conn_info == NULL || conn_info->ssl == true) {
        return 0;
    }

    struct active_buf active_buf_t;
    __builtin_memset(&active_buf_t, 0, sizeof(active_buf_t));
    active_buf_t.fd = fd;
    active_buf_t.version = 1;
    active_buf_t.buf = buf;
    active_buf_t.buf_len = buf_len;
    bpf_map_update_elem(&active_write_args_map, &current_pid_tgid, &active_buf_t, BPF_ANY);

    // bpf_printk("----------------> kprobe/write fd: %d, pid: %d", fd, pid);

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

    if (active_buf_t != NULL) {  // Could check socket_event==true here if security_socket_sendmsg krpobe was enabled
        const char *buf;
        u32 fd = active_buf_t->fd;
        s32 version = active_buf_t->version;
        int buf_len = active_buf_t->buf_len;
        bpf_probe_read(&buf, sizeof(const char *), &active_buf_t->buf);

        // TODO: Use procces_data
        struct data_event_t *event = create_data_event(current_pid_tgid);
        if (event == NULL) {
        return 0;
        }

        event->type = kWrite;
        event->fd = fd;
        event->version = version;

        // This is a max function, but it is written in such a way to keep older BPF verifiers happy.
        event->data_len = (buf_len < MAX_DATA_SIZE_OPENSSL ? (buf_len & (MAX_DATA_SIZE_OPENSSL - 1)) : MAX_DATA_SIZE_OPENSSL);
        bpf_probe_read_user(event->data, event->data_len, buf);

        // Find the matching connect event so we can filter out non-socket write() calls
        u64 key = gen_pid_fd(current_pid_tgid, fd);
        struct connect_event_t *conn_info = bpf_map_lookup_elem(&conn_infos, &key);
        if (conn_info == NULL) {
        return 0;
        }

        // Infer the protocol
        infer_http_message(conn_info, event->data);

        // If the protocol is still unknown, then drop it
        if (conn_info->protocol == pUnknown) {
        return 0;
        }

        bpf_get_current_comm(&event->comm, sizeof(event->comm));
        bpf_ringbuf_output(&data_events, event, sizeof(struct data_event_t), 0);
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

    // Find the matching connect event so we can filter out non-socket write() calls
    u64 key = gen_pid_fd(current_pid_tgid, fd);
    struct connect_event_t *conn_info = bpf_map_lookup_elem(&conn_infos, &key);
    if (conn_info == NULL || conn_info->ssl == true) {
        return 0;
    }

    struct active_buf active_buf_t;
    __builtin_memset(&active_buf_t, 0, sizeof(active_buf_t));
    active_buf_t.fd = fd;
    active_buf_t.version = 1;
    active_buf_t.buf = buf;
    active_buf_t.buf_len = buf_len;
    bpf_map_update_elem(&active_read_args_map, &current_pid_tgid, &active_buf_t, BPF_ANY);

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

    if (active_buf_t != NULL) { // Could check socket_event==true here if security_socket_recvmsg krpobe was enabled
        // dog_debug(pid, current_pid_tgid, bytes_read, "read");
        active_buf_t->buf_len = bytes_read;

        bpf_map_delete_elem(&active_read_args_map, &current_pid_tgid);
        // TODO: DRY up the duplication here with probe_red_write()
        const char *buf;
        u32 fd = active_buf_t->fd;
        s32 version = active_buf_t->version;
        int buf_len = active_buf_t->buf_len;
        bpf_probe_read(&buf, sizeof(const char *), &active_buf_t->buf);

        // TODO: Use procces_data
        struct data_event_t *event = create_data_event(current_pid_tgid);
        if (event == NULL) {
        return 0;
        }

        event->type = kRead;
        event->fd = fd;
        event->version = version;

        // This is a max function, but it is written in such a way to keep older BPF verifiers happy.
        event->data_len = (buf_len < MAX_DATA_SIZE_OPENSSL ? (buf_len & (MAX_DATA_SIZE_OPENSSL - 1)) : MAX_DATA_SIZE_OPENSSL);
        bpf_probe_read_user(event->data, event->data_len, buf);

        // Find the matching connect event so we can filter out non-socket write() calls
        u64 key = gen_pid_fd(current_pid_tgid, fd);
        struct connect_event_t *conn_info = bpf_map_lookup_elem(&conn_infos, &key);
        if (conn_info == NULL) {
        return 0;
        }

        // Infer the protocol
        infer_http_message(conn_info, event->data);

        // If the protocol is still unknown, then drop it
        if (conn_info->protocol == pUnknown) {
        return 0;
        }

        // bpf_get_current_comm(&event->comm, sizeof(event->comm));
        bpf_ringbuf_output(&data_events, event, sizeof(struct data_event_t), 0);
    }

    return 0;
}

// NOTE: security_socket_sendmsg and security_socket_recvmsg are not available on linuxkit (used by docker desktop for mac)
// so these are not used currently. But they can be used to filter the send/recv calls intercepted.

// This probe is used to identify when a call to write() comes from a network socket
SEC("kprobe/security_socket_sendmsg")
int probe_entry_security_socket_sendmsg(struct pt_regs *ctx) {
    u64 current_pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = current_pid_tgid >> 32;

    // Check if PID is intercepted
    u32 *pid_intercepted = bpf_map_lookup_elem(&intercepted_pids, &pid);
    if (pid_intercepted == NULL) {
        return 0;
    }

    struct active_buf *active_buf_t = bpf_map_lookup_elem(&active_write_args_map, &current_pid_tgid);

    if (active_buf_t != NULL) {
        active_buf_t->socket_event = true;
    }

    return 0;
}

// This probe is used to identify when a call to read() comes from a network socket
// int security_socket_recvmsg(struct socket *sock, struct msghdr *msg, int size)
SEC("kprobe/security_socket_recvmsg")
int probe_entry_security_socket_recvmsg(struct pt_regs *ctx) {
    u64 current_pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = current_pid_tgid >> 32;

    // Check if PID is intercepted
    u32 *pid_intercepted = bpf_map_lookup_elem(&intercepted_pids, &pid);
    if (pid_intercepted == NULL) {
        return 0;
    }

    struct active_buf *active_buf_t = bpf_map_lookup_elem(&active_read_args_map, &current_pid_tgid);

    if (active_buf_t != NULL) {
        active_buf_t->socket_event = true;
    }

    return 0;
}
