// Copyright 2022 CFC4N <cfc4n.cs@gmail.com>. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <vmlinux.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// -----------------------------------------------------------------------------
// common.h
// -----------------------------------------------------------------------------
#define TASK_COMM_LEN 16
#define PATH_MAX_LEN 256
#define MAX_DATA_SIZE_OPENSSL 1024 * 4
#define MAX_DATA_SIZE_MYSQL 256
#define MAX_DATA_SIZE_POSTGRES 256
#define MAX_DATA_SIZE_BASH 256

// enum_server_command, via
// https://dev.mysql.com/doc/internals/en/com-query.html COM_QUERT command 03
#define COM_QUERY 3

#define AF_INET 2
#define AF_INET6 10
#define SA_DATA_LEN 14
#define BASH_ERRNO_DEFAULT 128

///////// for TC & XDP ebpf programs in tc.h
#define TC_ACT_OK 0
#define ETH_P_IP 0x0800 /* Internet Protocol packet        */
#define SKB_MAX_DATA_SIZE 2048
#define SA_DATA_LEN 14

typedef short unsigned int __kernel_sa_family_t;

typedef __kernel_sa_family_t sa_family_t;
// -----------------------------------------------------------------------------
enum data_event_type { kSSLRead, kSSLWrite };
const u32 invalidFD = 0;
struct data_event_t {
    enum data_event_type type;
    u64 timestamp_ns;
    u32 pid;
    u32 tid;
    char data[MAX_DATA_SIZE_OPENSSL];
    s32 data_len;
    char comm[TASK_COMM_LEN];
    u32 fd;
    s32 version;
};

struct socket_addr_event_t {
    u64 timestamp_ns;
    u32 pid;
    u32 tid;
    u32 fd;
    u32 ip;
    u16 port;
    bool local;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); // 256 KB
} data_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); // 256 KB
} socket_addr_events SEC(".maps");

struct active_buf {
    /*
     * protocol version (one of SSL2_VERSION, SSL3_VERSION, TLS1_VERSION,
     * DTLS1_VERSION)
     * from ssl/ssl_local.h struct ssl_st
     */
    s32 version;
    u32 fd;
    const char* buf;
};

struct socket_args {
    // The IP protocol (TCP/UDP)
    u32 protocol;
};

/***********************************************************
 * Internal structs and definitions
 ***********************************************************/

// Key is thread ID (from bpf_get_current_pid_tgid).
// Value is a pointer to the data buffer argument to SSL_write/SSL_read.
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

// Key is the file descriptor FD, Value is the protocol
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u64);
    __type(value, int);
    __uint(max_entries, 1024);
} socket_protocol_map SEC(".maps");

// Key is the file descriptor FD, Value is the addr
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u64);
    __type(value, struct sockaddr);
    __uint(max_entries, 1024);
} socket_src_addr_map SEC(".maps");

// BPF programs are limited to a 512-byte stack. We store this value per CPU
// and use it as a heap allocated value.
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, u32);
    __type(value, struct data_event_t);
    __uint(max_entries, 1);
} data_buffer_heap SEC(".maps");

// OPENSSL struct to offset , via kern/README.md
typedef long (*unused_fn)();

struct unused {};

struct BIO {
    void* libctx;
    const struct unused* method;
    unused_fn callback;
    unused_fn callback_ex;
    char* cb_arg; /* first argument for the callback */
    int init;
    int shutdown;
    int flags; /* extra storage */
    int retry_reason;
    int num;
};

struct ssl_st {
    s32 version;
    struct unused* method;
    struct BIO* rbio;  // used by SSL_read
    struct BIO* wbio;  // used by SSL_write
};

/***********************************************************
 * General helper functions
 ***********************************************************/

static __inline struct data_event_t* create_data_event(
    u64 current_pid_tgid) {
    u32 kZero = 0;
    struct data_event_t* event = bpf_map_lookup_elem(&data_buffer_heap, &kZero);
    if (event == NULL)
        return NULL;

    const u32 kMask32b = 0xffffffff;
    event->timestamp_ns = bpf_ktime_get_ns();
    event->pid = current_pid_tgid >> 32;
    event->tid = current_pid_tgid & kMask32b;
    event->fd = invalidFD;

    return event;
}

/***********************************************************
 * BPF syscall processing functions
 ***********************************************************/

static int process_data(
    struct pt_regs* ctx,
    u64 id,
    enum data_event_type type,
    const char* buf,
    u32 fd,
    s32 version
) {
    int len = (int)PT_REGS_RC(ctx);
    bpf_printk("-> process_data len: %d", len);
    if (len < 0) {
        return 0;
    }
    // bpf_printk("-----------> process_data() len: %d", len);
    struct data_event_t* event = create_data_event(id);
    if (event == NULL) {
        return 0;
    }
    // bpf_printk("-----------> process_data() got the event!");
    event->type = type;
    event->fd = fd;
    event->version = version;
    // This is a max function, but it is written in such a way to keep older BPF
    // verifiers happy.
    event->data_len = (len < MAX_DATA_SIZE_OPENSSL ? (len & (MAX_DATA_SIZE_OPENSSL - 1)): MAX_DATA_SIZE_OPENSSL);
    bpf_probe_read_user(event->data, event->data_len, buf);
    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    // bpf_printk("-----------> process_data() publishing to data_events, len: %d", event->data_len);
    // bpf_perf_event_output(ctx, &data_events, BPF_F_CURRENT_CPU, event, sizeof(struct data_event_t));
    bpf_ringbuf_output(&data_events, event, sizeof(struct data_event_t), 0);
    return 0;
}

/***********************************************************
 * BPF probe function entry-points
 ***********************************************************/
// Function signature being probed:
// int SSL_read(SSL *s, void *buf, int num)
SEC("uprobe/SSL_read")
int probe_entry_SSL_read(struct pt_regs* ctx) {
    u64 current_pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = current_pid_tgid >> 32;
    u64 current_uid_gid = bpf_get_current_uid_gid();
    u32 uid = current_uid_gid;
    // bpf_printk("openssl uprobe/SSL_read pid :%d\n", pid);

    void* ssl = (void*)PT_REGS_PARM1(ctx);
    // https://github.com/openssl/openssl/blob/OpenSSL_1_1_1-stable/crypto/bio/bio_local.h
    struct ssl_st ssl_info;
    bpf_probe_read_user(&ssl_info, sizeof(ssl_info), ssl);

    struct BIO bio_r;
    bpf_probe_read_user(&bio_r, sizeof(bio_r), ssl_info.rbio);

    // get fd ssl->rbio->num
    u32 fd = bio_r.num;
    bpf_printk("openssl uprobe sizeof(ssl_info): %d, PID:%d, SSL_read FD:%d\n", sizeof(ssl_info), pid, fd);

    const char* buf = (const char*)PT_REGS_PARM2(ctx);
    struct active_buf active_buf_t;
    __builtin_memset(&active_buf_t, 0, sizeof(active_buf_t));
    active_buf_t.fd = fd;
    active_buf_t.version = ssl_info.version;
    active_buf_t.buf = buf;
    bpf_map_update_elem(&active_read_args_map, &current_pid_tgid, &active_buf_t, BPF_ANY);
    return 0;
}

SEC("uretprobe/SSL_read")
int probe_ret_SSL_read(struct pt_regs* ctx) {
    u64 current_pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = current_pid_tgid >> 32;
    u64 current_uid_gid = bpf_get_current_uid_gid();
    u32 uid = current_uid_gid;
    // bpf_printk("openssl uretprobe/SSL_read pid :%d\n", pid);

    struct active_buf* active_buf_t = bpf_map_lookup_elem(&active_read_args_map, &current_pid_tgid);

    if (active_buf_t != NULL) {
        const char* buf;
        u32 fd = active_buf_t->fd;
        s32 version = active_buf_t->version;
        bpf_probe_read(&buf, sizeof(const char*), &active_buf_t->buf);
        process_data(ctx, current_pid_tgid, kSSLRead, buf, fd, version);
    }
    bpf_map_delete_elem(&active_read_args_map, &current_pid_tgid);
    return 0;
}

// Function signature being probed:
// int SSL_write(SSL *ssl, const void *buf, int num);
// SSL_write() writes num bytes from the buffer buf into the specified ssl connection
SEC("uprobe/SSL_write")
int probe_entry_SSL_write(struct pt_regs* ctx) {
    u64 current_pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = current_pid_tgid >> 32;
    u64 current_uid_gid = bpf_get_current_uid_gid();
    u32 uid = current_uid_gid;

    // bpf_printk("openssl uprobe/SSL_write pid :%d\n", pid);

    void* ssl = (void*)PT_REGS_PARM1(ctx);
    // https://github.com/openssl/openssl/blob/OpenSSL_1_1_1-stable/crypto/bio/bio_local.h
    struct ssl_st ssl_info;
    bpf_probe_read_user(&ssl_info, sizeof(ssl_info), ssl);

    struct BIO bio_w;
    bpf_probe_read_user(&bio_w, sizeof(bio_w), ssl_info.wbio);

    // get fd ssl->wbio->num
    u32 fd = bio_w.num;
    bpf_printk("openssl uprobe SSL_write FD:%d\n", fd);

    const char* buf = (const char*)PT_REGS_PARM2(ctx);
    struct active_buf active_buf_t;
    __builtin_memset(&active_buf_t, 0, sizeof(active_buf_t));
    active_buf_t.fd = fd;
    active_buf_t.version = ssl_info.version;
    active_buf_t.buf = buf;
    bpf_map_update_elem(&active_write_args_map, &current_pid_tgid, &active_buf_t, BPF_ANY);

    return 0;
}

SEC("uretprobe/SSL_write")
int probe_ret_SSL_write(struct pt_regs* ctx) {
    u64 current_pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = current_pid_tgid >> 32;
    u64 current_uid_gid = bpf_get_current_uid_gid();
    u32 uid = current_uid_gid;

    // Send entry data from map
    // bpf_printk("openssl uretprobe/SSL_write pid :%d\n", pid);
    struct active_buf* active_buf_t = bpf_map_lookup_elem(&active_write_args_map, &current_pid_tgid);

    if (active_buf_t != NULL) {
        const char* buf;
        u32 fd = active_buf_t->fd;
        s32 version = active_buf_t->version;
        bpf_probe_read(&buf, sizeof(const char*), &active_buf_t->buf);
        process_data(ctx, current_pid_tgid, kSSLWrite, buf, fd, version);
    }
    bpf_map_delete_elem(&active_write_args_map, &current_pid_tgid);
    return 0;
}

// https://github.com/lattera/glibc/blob/895ef79e04a953cac1493863bcae29ad85657ee1/socket/connect.c
// int __connect (int fd, __CONST_SOCKADDR_ARG addr, socklen_t len)
SEC("uprobe/connect")
int probe_connect(struct pt_regs* ctx) {
    u64 current_pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = current_pid_tgid >> 32;
    u64 current_uid_gid = bpf_get_current_uid_gid();
    u32 uid = current_uid_gid;

    u32 fd = (u32)PT_REGS_PARM1(ctx);

    struct sockaddr* saddr = (struct sockaddr*)PT_REGS_PARM2(ctx);
    if (!saddr) {
        return 0;
    }

    sa_family_t address_family = 0;
    bpf_probe_read_user(&address_family, sizeof(address_family), &saddr->sa_family);

    if (address_family != AF_INET) {
        return 0;
    }

    // Get the IP Protocol
    bpf_printk("probe_connect pid: %d, current_pid_tgid: %d, fd: %d", pid, current_pid_tgid, fd);

    // Get the socket address
    struct sockaddr_in* sin = (struct sockaddr_in*)saddr;

    // Build the socket_addr_event
    struct socket_addr_event_t conn_event;
    __builtin_memset(&conn_event, 0, sizeof(conn_event));
    conn_event.timestamp_ns = bpf_ktime_get_ns();
    conn_event.pid = pid;
    conn_event.tid = current_pid_tgid;
    conn_event.fd = fd;
    conn_event.local = false;

    bpf_probe_read_user(&conn_event.ip, sizeof(u32), &sin->sin_addr.s_addr);
    bpf_probe_read_user(&conn_event.port, sizeof(u16), &sin->sin_port);
    bpf_ringbuf_output(&socket_addr_events, &conn_event, sizeof(struct socket_addr_event_t), 0);

    return 0;
}

// SEC("uretprobe/connect")
// int probe_ret_connect(struct pt_regs* ctx) {
//     u64 current_pid_tgid = bpf_get_current_pid_tgid();
//     u32 pid = current_pid_tgid >> 32;
//     u64 current_uid_gid = bpf_get_current_uid_gid();
//     u32 uid = current_uid_gid;

//     u32 fd = (u32)PT_REGS_PARM1(ctx);
//     bpf_printk("RETURN: probe_connect fd: %d", fd);

//     struct sockaddr* saddr = (struct sockaddr*)PT_REGS_PARM2(ctx);
//     if (!saddr) {
//         return 0;
//     }

//     sa_family_t address_family = 0;
//     bpf_probe_read_user(&address_family, sizeof(address_family), &saddr->sa_family);

//     if (address_family != AF_INET) {
//         return 0;
//     }

//     struct sockaddr_in* sin = (struct sockaddr_in*)saddr;
//     struct socket_addr_event_t conn_event;
//     __builtin_memset(&conn_event, 0, sizeof(conn_event));

//     conn_event.timestamp_ns = bpf_ktime_get_ns();
//     conn_event.pid = pid;
//     conn_event.tid = current_pid_tgid;
//     conn_event.fd = fd;

//     bpf_probe_read_user(&conn_event.ip, sizeof(u32), &sin->sin_addr.s_addr);
//     bpf_probe_read_user(&conn_event.port, sizeof(u16), &sin->sin_port);
//     bpf_ringbuf_output(&socket_addr_events, &conn_event, sizeof(struct socket_addr_event_t), 0);

//     return 0;
// }

// int getsockname(int sockfd, struct sockaddr *restrict addr, socklen_t *restrict addrlen);
SEC("uretprobe/getsockname")
int probe_ret_getsockname(struct pt_regs* ctx) {
    u64 current_pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = current_pid_tgid >> 32;
    u64 current_uid_gid = bpf_get_current_uid_gid();
    u32 uid = current_uid_gid;

    u32 fd = (u32)PT_REGS_PARM1(ctx);

    struct sockaddr* saddr = (struct sockaddr*)PT_REGS_PARM2(ctx);
    if (!saddr) {
        return 0;
    }

    sa_family_t address_family = 0;
    bpf_probe_read_user(&address_family, sizeof(address_family), &saddr->sa_family);

    if (address_family != AF_INET) {
        return 0;
    }

    // Get the socket address
    struct sockaddr_in* sin = (struct sockaddr_in*)saddr;

    // Build the socket_addr_event
    struct socket_addr_event_t conn_event;
    __builtin_memset(&conn_event, 0, sizeof(conn_event));
    conn_event.timestamp_ns = bpf_ktime_get_ns();
    conn_event.pid = pid;
    conn_event.tid = current_pid_tgid;
    conn_event.fd = fd;
    conn_event.local = true;

    bpf_probe_read_user(&conn_event.ip, sizeof(u32), &sin->sin_addr.s_addr);
    bpf_probe_read_user(&conn_event.port, sizeof(u16), &sin->sin_port);
    bpf_ringbuf_output(&socket_addr_events, &conn_event, sizeof(struct socket_addr_event_t), 0);

    // bpf_printk("!!!!!!!!> GETSOCKNAME fd: %d, pid: %d, current_pid_tgid: %d", fd, pid, current_pid_tgid);
    // bpf_map_update_elem(&socket_src_addr_map, &fd, &saddr, BPF_ANY);

    return 0;
}

// int socket(int domain, int type, int protocol);
SEC("uretprobe/socket")
int probe_ret_socket(struct pt_regs* ctx) {
    int domain = (int)PT_REGS_PARM1(ctx);
    int protocol = (int)PT_REGS_PARM3(ctx);
    int fd = (int)PT_REGS_RC(ctx);

    if (domain != AF_INET) {
        return 0;
    }

    bpf_map_update_elem(&socket_protocol_map, &fd, &protocol, BPF_ANY);

    return 0;
}

// ssize_t sendto(int fd, const void *buf, size_t length, int flags, const struct sockaddr *dest_addr, socklen_t dest_len);
SEC("uprobe/send")
int probe_entry_send(struct pt_regs* ctx) {
    u64 current_pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = current_pid_tgid >> 32;
    u64 current_uid_gid = bpf_get_current_uid_gid();
    u32 uid = current_uid_gid;

    u32 fd = (u32)PT_REGS_PARM1(ctx);

    size_t len = (size_t)PT_REGS_PARM3(ctx);

    bpf_printk("======> entry_send pid: %d, current_pid_tgid: %d, fd: %d", pid, current_pid_tgid, fd);
    bpf_printk("======> entry_send len: %d", len);

    const char* buf = (const char*)PT_REGS_PARM2(ctx);
    struct active_buf active_buf_t;
    __builtin_memset(&active_buf_t, 0, sizeof(active_buf_t));
    active_buf_t.fd = fd;
    active_buf_t.buf = buf;
    bpf_map_update_elem(&active_write_args_map, &current_pid_tgid, &active_buf_t, BPF_ANY);

    return 0;
}

// ssize_t send(int fd, const void *buf, size_t length, int flags, const struct sockaddr *dest_addr, socklen_t dest_len);
SEC("uretprobe/send")
int probe_ret_send(struct pt_regs* ctx) {
    u64 current_pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = current_pid_tgid >> 32;
    u64 current_uid_gid = bpf_get_current_uid_gid();
    u32 uid = current_uid_gid;

    int len = (int)PT_REGS_RC(ctx);
    bpf_printk("====== >return_send current_pid_tgid: %d, len: %d", current_pid_tgid, len);

    struct active_buf* active_buf_t = bpf_map_lookup_elem(&active_write_args_map, &current_pid_tgid);

    if (active_buf_t != NULL) {
        // bpf_printk("return_send current_pid_tgid: %d, fd: %d", current_pid_tgid, active_buf_t->fd);
        const char* buf;
        u32 fd = active_buf_t->fd;
        s32 version = active_buf_t->version;
        bpf_probe_read(&buf, sizeof(const char*), &active_buf_t->buf);
        process_data(ctx, current_pid_tgid, kSSLWrite, buf, fd, version);
    }

    bpf_map_delete_elem(&active_write_args_map, &current_pid_tgid);

    return 0;
}

char __license[] SEC("license") = "GPL";
