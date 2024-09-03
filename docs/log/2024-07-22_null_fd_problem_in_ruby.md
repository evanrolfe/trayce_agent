# Null-FD problem in Ruby

For some reason the FD in SSL_Read and SSL_Write (used by Ruby) is always 0.

Things I have tried:
- sending over the entire *ssl struct and analysing the bytes in Go, the FD Is nowhere to be found
- saving a pointer to the Fd in the entry probe, then using bpf_probe_read to get teh value of the pointer in return probe, its still 0 (code below)

The solution I've settled on is not elegant but its the only thing that works. I use two ebpf maps `fd_map` and `ssl_fd_map`. Since the FD is set correctly in `kprobe/recvfrom` (which is called with the encrypted payload) I am able to correleate the FD using the `current_pid_tgid` key. Similarly, `SSL_Read` and `SSL_Write` are both called with a pointer to the same address of the `ssl` struct, so I can then correleate using that address. This is the process:
1. in `kprobe/recvfrom` the FD is set on the `fd_map` using `current_pid_tgid` key
2. in `uprobe/SSL_Read` the FD is fetched from `fd_map` (see `get_fd_from_libssl_read()`) and the saved again to `ssl_fd_map` using the `ssl` pointer num as key
3. in `uprobe/SSL_Write` the FD is fetched from `ssl_fd_map` since `SSL_Read` and `SSL_Write` both have the same pointer to the `ssl` arg

Now the `DataEvent`s being sent from `uprobe/SSL_Read` and `uprobe/SSL_Write` will have the correct FD set on them so they can be processed by the correct socket in `SocketMap`.

```c
struct ssl_args_t {
    int* fd;
};

// In entry probe:
int* fd_ptr = (int *)PT_REGS_PARM3(ctx);
struct ssl_args_t ssl_args = {};
ssl_args.fd = fd_ptr;
bpf_map_update_elem(&active_ssl_read_ctx_map, &current_pid_tgid, &ssl_args, BPF_ANY);

// In return probe:
struct ssl_args_t *ssl_args = bpf_map_lookup_elem(&active_ssl_read_ctx_map, &current_pid_tgid);
if (ssl_args == NULL) {
    return 0;
}

int fd_value = 0;
bpf_probe_read(&fd_value, sizeof(fd_value), ssl_args->fd);
bpf_printk("SSL_read FD: %d", fd_value);
```
