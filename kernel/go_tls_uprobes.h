// go:build exclude

struct active_go_buf {
    const char* buf;
    u32 buf_len;
    u32 fd;
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, u64);
  __type(value, struct active_go_buf);
  __uint(max_entries, 1024);
} active_go_read_args_map SEC(".maps");

struct go_interface {
  int64_t type;
  void* ptr;
};

static __always_inline int gotls_write(struct pt_regs *ctx, bool is_register_abi) {
    u64 current_pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = current_pid_tgid >> 32;

    s32 buf_len;
    const char *buf;
    void *len_ptr;

    buf = (void *)go_get_argument(ctx, is_register_abi, 2);
    len_ptr = (void *)go_get_argument(ctx, is_register_abi, 3);
    bpf_probe_read_kernel(&buf_len, sizeof(buf_len), (void *)&len_ptr);
    if (buf_len == 0) {
        return 0;
    }

    // Get the offset values from user space
    u64 fd_offset = 16;
    u32 kZero = 0;
    struct offsets *off = bpf_map_lookup_elem(&offsets_map, &kZero);
    if (off != NULL) {
        fd_offset = off->go_fd_offset;
    }

    // Get the FD
    // Note here fd_ptr refers to the pointer to the net.netFD struct:
    // net.Conn(*net.TCPConn) *{
    //     conn: net.conn {
    //         fd: *(*net.netFD)(0xc00017a300),},}
    void* conn_ptr = go_get_argument(ctx, is_register_abi, 1);

    struct go_interface conn_intf;
    bpf_probe_read(&conn_intf, sizeof(conn_intf), conn_ptr);

    void* fd_ptr;
    bpf_probe_read(&fd_ptr, sizeof(fd_ptr), conn_intf.ptr);

    // TODO: Get the offset (16) from dwarf, see "FD_Sysfd_offset" in pixie..
    int64_t fd;
    bpf_probe_read(&fd, sizeof(int64_t), fd_ptr + fd_offset);

    process_data(ctx, current_pid_tgid, goTlsWrite, buf, buf_len, fd);

    return 0;
}

// IMPORTANT: If you dont read the entire response body in Go, i.e. `body, _ := io.ReadAll(resp.Body)`, this this
// Read() function will not be called on the body!!!
static __always_inline int gotls_read(struct pt_regs *ctx, bool is_register_abi) {
    u64 current_pid_tgid = bpf_get_current_pid_tgid();
    u64 pid = current_pid_tgid >> 32;

    __u64 goroutine_id = GOROUTINE(ctx);
    __u64 pid_go = pid << 32 | goroutine_id | 0x8000000000000000;

    // Get the offset values from user space
    u64 fd_offset = 16;
    u32 kZero = 0;
    struct offsets *off = bpf_map_lookup_elem(&offsets_map, &kZero);
    if (off != NULL) {
        fd_offset = off->go_fd_offset;
    }

    // Get the FD
    // Note here fd_ptr refers to the pointer to the net.netFD struct:
    // net.Conn(*net.TCPConn) *{
    //     conn: net.conn {
    //         fd: *(*net.netFD)(0xc00017a300),},}
    void* conn_ptr = go_get_argument(ctx, is_register_abi, 1);

    struct go_interface conn_intf;
    bpf_probe_read(&conn_intf, sizeof(conn_intf), conn_ptr);

    void* fd_ptr;
    bpf_probe_read(&fd_ptr, sizeof(fd_ptr), conn_intf.ptr);

    // TODO: Get the offset (16) from dwarf, see "FD_Sysfd_offset" in pixie..
    int64_t fd;
    bpf_probe_read(&fd, sizeof(int64_t), fd_ptr + fd_offset);

    bpf_printk("gotls/read: PID: %d, fd: %d, go id: %d", pid, fd, pid_go);

    // Create the event
    struct active_go_buf active_buf_t;
    __builtin_memset(&active_buf_t, 0, sizeof(active_buf_t));
    active_buf_t.fd = fd;

    const char *buf = (void *)go_get_argument(ctx, is_register_abi, 2);
    void *len_ptr = (void *)go_get_argument(ctx, is_register_abi, 3);

    // TODO: No point trying to read the buf_len here
    active_buf_t.buf = buf;
    bpf_probe_read(&active_buf_t.buf_len, sizeof(u32), &len_ptr);

    bpf_map_update_elem(&active_go_read_args_map, &pid_go, &active_buf_t, BPF_ANY);

    return 0;
}

#define MAX_LEN 128

static __always_inline int gotls_read_exit(struct pt_regs *ctx, bool is_register_abi) {
    u64 current_pid_tgid = bpf_get_current_pid_tgid();
    u64 pid = current_pid_tgid >> 32;

    __u64 goroutine_id = GOROUTINE(ctx);
    __u64 pid_go = pid << 32 | goroutine_id | 0x8000000000000000;
    // bpf_printk("read exit: go routine id: %d", goroutine_id);

    struct active_go_buf *active_buf_t = bpf_map_lookup_elem(&active_go_read_args_map, &pid_go);

    if (active_buf_t != NULL) {
        u32 fd = active_buf_t->fd;
        if (active_buf_t->buf_len == 0) {
            return 0;
        }

        // Get the buffer length from the rax register
        __u32 buf_len;
        void *len_ptr = (void *)go_get_argument(ctx, is_register_abi, 1);
        bpf_probe_read(&buf_len, sizeof(u32), &len_ptr);
        bpf_printk("gotls/read exit: PID: %d buf_len: %d, fd: %d, go id: %d", pid, buf_len, fd, pid_go);

        process_data(ctx, current_pid_tgid, goTlsRead, active_buf_t->buf, buf_len, fd);
    }
    bpf_map_delete_elem(&active_go_read_args_map, &pid_go);

    return 0;
}

SEC("uprobe/gotls_write_register")
int probe_entry_go_tls_write(struct pt_regs* ctx) {
    u64 current_pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = current_pid_tgid >> 32;

    gotls_write(ctx, true);

    return 0;
}

SEC("uprobe/gotls_read_register")
int probe_entry_go_tls_read(struct pt_regs* ctx) {
    u64 current_pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = current_pid_tgid >> 32;

    gotls_read(ctx, true);

    return 0;
}

SEC("uprobe/gotls_exit_read_register")
int probe_exit_go_tls_read(struct pt_regs* ctx) {
    u64 current_pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = current_pid_tgid >> 32;

    gotls_read_exit(ctx, true);

    return 0;
}
