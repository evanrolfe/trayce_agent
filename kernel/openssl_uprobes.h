// go:build exclude

// Key is thread ID (from bpf_get_current_pid_tgid).
// Value is a pointer to the data buffer argument to SSL_write/SSL_read.
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, u64);
  __type(value, struct active_buf);
  __uint(max_entries, 1024);
} active_ssl_read_args_map SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, u64);
  __type(value, struct active_buf);
  __uint(max_entries, 1024);
} active_ssl_write_args_map SEC(".maps");

int process_ssl_read_entry(struct pt_regs *ctx, bool is_ex_call) {
  u64 current_pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = current_pid_tgid >> 32;

  // Check if PID is intercepted
  u32 *pid_intercepted = bpf_map_lookup_elem(&intercepted_pids, &pid);
  if (pid_intercepted == NULL) {
    return 0;
  }

  void *ssl = (void *)PT_REGS_PARM1(ctx);
  // https://github.com/openssl/openssl/blob/OpenSSL_1_1_1-stable/crypto/bio/bio_local.h
  struct ssl_st ssl_info;
  bpf_probe_read_user(&ssl_info, sizeof(ssl_info), ssl);

  struct BIO bio_r;
  bpf_probe_read_user(&bio_r, sizeof(bio_r), ssl_info.rbio);

  u32 fd = bio_r.num;

  const char *buf = (const char *)PT_REGS_PARM2(ctx);
  struct active_buf active_buf_t;
  __builtin_memset(&active_buf_t, 0, sizeof(active_buf_t));
  active_buf_t.fd = fd;
  active_buf_t.version = ssl_info.version;
  active_buf_t.buf = buf;

  if (is_ex_call) {
    size_t *ssl_ex_len_ptr = (size_t *)PT_REGS_PARM4(ctx);
    active_buf_t.ssl_ex_len_ptr = ssl_ex_len_ptr;
  }

  bpf_map_update_elem(&active_ssl_read_args_map, &current_pid_tgid, &active_buf_t, BPF_ANY);
  return 0;
}

int process_ssl_read_return(struct pt_regs *ctx, bool is_ex_call) {
  u64 current_pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = current_pid_tgid >> 32;
  // bpf_printk("openssl uretprobe/SSL_read pid :%d\n", pid);

  struct active_buf *active_buf_t = bpf_map_lookup_elem(&active_ssl_read_args_map, &current_pid_tgid);

  if (active_buf_t != NULL) {
    const char *buf;
    u32 fd = active_buf_t->fd;
    bpf_printk("SSL_read pid: %d,, current_pid_tgid %d, fd: %d", pid, current_pid_tgid, fd);
    s32 version = active_buf_t->version;
    bpf_probe_read(&buf, sizeof(const char *), &active_buf_t->buf);

    size_t ssl_ex_len;

    if (is_ex_call) {
      bpf_probe_read(&ssl_ex_len, sizeof(ssl_ex_len), active_buf_t->ssl_ex_len_ptr);
    } else {
      ssl_ex_len = 0;
    }

    // Mark the connection as SSL
    u64 key = gen_pid_fd(current_pid_tgid, fd);
    struct connect_event_t *conn_info = bpf_map_lookup_elem(&conn_infos, &key);
    if (conn_info != NULL) {
      conn_info->ssl = true;
    }

    process_data(ctx, current_pid_tgid, kSSLRead, buf, fd, version, ssl_ex_len);
  }
  bpf_map_delete_elem(&active_ssl_read_args_map, &current_pid_tgid);

  return 0;
}

int process_ssl_write_entry(struct pt_regs *ctx, bool is_ex_call) {
  u64 current_pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = current_pid_tgid >> 32;

  // Check if PID is intercepted
  u32 *pid_intercepted = bpf_map_lookup_elem(&intercepted_pids, &pid);
  if (pid_intercepted == NULL) {
    return 0;
  }
  // bpf_printk("openssl uprobe/SSL_write_ex pid :%d\n", pid);

  void *ssl = (void *)PT_REGS_PARM1(ctx);
  // https://github.com/openssl/openssl/blob/OpenSSL_1_1_1-stable/crypto/bio/bio_local.h
  struct ssl_st ssl_info;
  bpf_probe_read_user(&ssl_info, sizeof(ssl_info), ssl);

  struct BIO bio_w;
  bpf_probe_read_user(&bio_w, sizeof(bio_w), ssl_info.wbio);

  u32 fd = bio_w.num;

  const char *buf = (const char *)PT_REGS_PARM2(ctx);
  struct active_buf active_buf_t;
  __builtin_memset(&active_buf_t, 0, sizeof(active_buf_t));
  active_buf_t.fd = fd;
  active_buf_t.version = ssl_info.version;
  active_buf_t.buf = buf;

  if (is_ex_call) {
    size_t *ssl_ex_len_ptr = (size_t *)PT_REGS_PARM4(ctx);
    size_t ssl_ex_len;
    bpf_probe_read(&ssl_ex_len, sizeof(ssl_ex_len), ssl_ex_len_ptr);
    bpf_printk("SSL_write_ex FD:%d, ex_len: %d\n", fd, ssl_ex_len);
    active_buf_t.ssl_ex_len_ptr = ssl_ex_len_ptr;
  }

  bpf_map_update_elem(&active_ssl_write_args_map, &current_pid_tgid, &active_buf_t, BPF_ANY);

  return 0;
}

int process_ssl_write_return(struct pt_regs *ctx, bool is_ex_call) {
  u64 current_pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = current_pid_tgid >> 32;

  // Send entry data from map
  // bpf_printk("openssl uretprobe/SSL_write_ex pid :%d\n", pid);
  struct active_buf *active_buf_t = bpf_map_lookup_elem(&active_ssl_write_args_map, &current_pid_tgid);

  if (active_buf_t != NULL) {
    const char *buf;
    u32 fd = active_buf_t->fd;
    s32 version = active_buf_t->version;
    bpf_probe_read(&buf, sizeof(const char *), &active_buf_t->buf);

    size_t ssl_ex_len;
    if (is_ex_call) {
      bpf_probe_read(&ssl_ex_len, sizeof(ssl_ex_len), active_buf_t->ssl_ex_len_ptr);
    } else {
      ssl_ex_len = 0;
    }

    // Mark the connection as SSL
    u64 key = gen_pid_fd(current_pid_tgid, fd);
    struct connect_event_t *conn_info = bpf_map_lookup_elem(&conn_infos, &key);
    if (conn_info != NULL) {
      conn_info->ssl = true;
    }

    process_data(ctx, current_pid_tgid, kSSLWrite, buf, fd, version, ssl_ex_len);
  }
  bpf_map_delete_elem(&active_ssl_write_args_map, &current_pid_tgid);
  return 0;
}
/***********************************************************
 * BPF uprobes
 ***********************************************************/
// int SSL_read(SSL *s, void *buf, int num)
SEC("uprobe/SSL_read")
int probe_entry_SSL_read(struct pt_regs *ctx) {
  return process_ssl_read_entry(ctx, false);
}

SEC("uretprobe/SSL_read")
int probe_ret_SSL_read(struct pt_regs *ctx) {
  return process_ssl_read_return(ctx, false);
}

// int SSL_read_ex(SSL *ssl, void *buf, size_t num, size_t *readbytes);
SEC("uprobe/SSL_read_ex")
int probe_entry_SSL_read_ex(struct pt_regs *ctx) {
  return process_ssl_read_entry(ctx, true);
}

SEC("uretprobe/SSL_read_ex")
// int SSL_read_ex(SSL *ssl, void *buf, size_t num, size_t *readbytes);
int probe_ret_SSL_read_ex(struct pt_regs *ctx) {
  return process_ssl_read_return(ctx, true);
}

// int SSL_write(SSL *ssl, const void *buf, int num);
SEC("uprobe/SSL_write")
int probe_entry_SSL_write(struct pt_regs *ctx) {
  return process_ssl_write_entry(ctx, false);
}

SEC("uretprobe/SSL_write")
int probe_ret_SSL_write(struct pt_regs *ctx) {
  return process_ssl_write_return(ctx, false);
}

SEC("uprobe/SSL_write_ex")
int probe_entry_SSL_write_ex(struct pt_regs *ctx) {
  return process_ssl_write_entry(ctx, true);
}

SEC("uretprobe/SSL_write_ex")
int probe_ret_SSL_write_ex(struct pt_regs *ctx) {
  return process_ssl_write_return(ctx, true);
}
