//go:build exclude

// -----------------------------------------------------------------------------
// common.h
// -----------------------------------------------------------------------------
#define TASK_COMM_LEN 16
#define PATH_MAX_LEN 256
#define MAX_DATA_SIZE_OPENSSL 4096
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
enum event_type { eConnect, eData, eClose, eDebug };
enum data_event_type { kSSLRead, kSSLWrite, kRead, kWrite, kRecvfrom, kSendto, goTlsRead, goTlsWrite };
enum protocol_type { pUnknown, pHttp };
const u32 invalidFD = 0;

struct data_event_t {
    u64 eventtype;
    u64 type;
    u64 timestamp_ns;
    u32 pid;
    u32 tid;
    char comm[TASK_COMM_LEN];
    u32 fd;
    s32 version;
    u64 rand;
    s32 data_len;
    char data[MAX_DATA_SIZE_OPENSSL];
};

struct connect_event_t {
    u64 eventtype;
    u64 timestamp_ns;
    u32 pid;
    u32 tid;
    u32 fd;
    u32 ip;
    u16 port;
    bool local;
    bool ssl;
    u32 protocol;
    u32 local_ip;
};

struct close_event_t {
    u64 eventtype;
    u64 timestamp_ns;
    u32 pid;
    u32 tid;
    u32 fd;
};

struct debug_event_t {
    u64 eventtype;
    u64 timestamp_ns;
    u32 pid;
    u32 tid;
    u32 fd;
    s32 data_len;
    char data[300];
};

// OPENSSL struct to offset , via kern/README.md
typedef long (*unused_fn)();

struct unused {};

struct bio_st_v1_1_1 {
    struct unused* method;
    unused_fn callback;
    unused_fn callback_ex; // new field
    char* cb_arg;
    int init;
    int shutdown;
    int flags;
    int retry_reason;
    int num; // fd
};

struct bio_st_v3_0 {
    struct unused* context; // new field
    struct unused* method;
    unused_fn callback;
    unused_fn callback_ex;
    char* cb_arg;
    int init;
    int shutdown;
    int flags;
    int retry_reason;
    int num; // fd
};

struct ssl_st {
    __s32 version;
    struct unused* method;
    struct bio_st_v3_0* rbio;  // used by SSL_read
    struct bio_st_v3_0* wbio;  // used by SSL_write
};

struct active_buf {
    /*
     * protocol version (one of SSL2_VERSION, SSL3_VERSION, TLS1_VERSION,
     * DTLS1_VERSION)
     * from ssl/ssl_local.h struct ssl_st
     */
    s32 version;
    u32 fd;
    const char* buf;
    size_t* ssl_ex_len_ptr;
    int buf_len;
    bool socket_event;
    const struct ssl_st* ssl_info;
    u64 ssl_ptr;                    // ssl_ptr is used when fd=0 to correleate requests with responses
};

struct offsets {
    __u64 go_fd_offset;
};

/***********************************************************
 * Exported bpf maps
 ***********************************************************/
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32);
    __type(value, u32);
    __uint(max_entries, 1024);
} intercepted_pids SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32);
    __type(value, struct offsets);
    __uint(max_entries, 1024);
} offsets_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32);
    __type(value, struct offsets);
    __uint(max_entries, 1024);
} libssl_versions_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u64);
    __type(value, struct connect_event_t);
    __uint(max_entries, 1024);
} conn_infos SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); // 256 KB
} data_events SEC(".maps");

// BPF programs are limited to a 512-byte stack. We store this value per CPU
// and use it as a heap allocated value.
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, u32);
    __type(value, struct data_event_t);
    __uint(max_entries, 1);
} data_buffer_heap SEC(".maps");

/***********************************************************
 * Helper Functions
 ***********************************************************/

static __inline struct data_event_t* create_data_event(u64 current_pid_tgid) {
    u32 kZero = 0;

    struct data_event_t* event = bpf_map_lookup_elem(&data_buffer_heap, &kZero);
    if (event == NULL)
        return NULL;

    const u32 kMask32b = 0xffffffff;
    event->eventtype = eData;
    event->timestamp_ns = bpf_ktime_get_ns();
    event->pid = current_pid_tgid >> 32;
    event->tid = current_pid_tgid & kMask32b;
    event->fd = invalidFD;
    event->rand = 0;

    return event;
}

// >> 32 - PID
// << 32 - TGID
static __inline u64 gen_pid_fd(u64 current_pid_tgid, int fd) {
    u32 pid = current_pid_tgid >> 32;
    u32 tgid = current_pid_tgid << 32;

    // I'm not sure why this works, but it works.
    return pid | tgid;
    // return tgid | (u32)fd;
}

static int process_data(struct pt_regs* ctx, u64 id, enum data_event_type type, const char* buf, u32 fd, s32 version, size_t ssl_ex_len, u64 ssl_ptr) {
    int len = (int)PT_REGS_RC(ctx);

    if (len < 0) {
        return 0;
    }

    struct data_event_t* event = create_data_event(id);
    if (event == NULL) {
        return 0;
    }
    event->type = type;
    event->fd = fd;
    event->version = version;
    event->rand = ssl_ptr;

    // This is a max function, but it is written in such a way to keep older BPF verifiers happy.
    if (ssl_ex_len > 0) {
        event->data_len = (ssl_ex_len < MAX_DATA_SIZE_OPENSSL ? (ssl_ex_len & (MAX_DATA_SIZE_OPENSSL - 1)): MAX_DATA_SIZE_OPENSSL);
    } else {
        event->data_len = (len < MAX_DATA_SIZE_OPENSSL ? (len & (MAX_DATA_SIZE_OPENSSL - 1)): MAX_DATA_SIZE_OPENSSL);
    }
    bpf_probe_read_user(event->data, event->data_len, buf);
    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    bpf_ringbuf_output(&data_events, event, sizeof(struct data_event_t), 0);
    return 0;
}

static u32 get_fd_from_libssl(struct ssl_st ssl_info, u32 pid) {
    int res;
    u32 fd;
    int *libssl_version = bpf_map_lookup_elem(&libssl_versions_map, &pid);
    if (libssl_version == NULL) {
        return 0;
    }
    if (*libssl_version == 1) {
        struct bio_st_v1_1_1 bio_r;
        res = bpf_probe_read_user(&bio_r, sizeof(bio_r), ssl_info.rbio);
        if (res < 0) {
            bpf_printk("SSL_read enty bpf_probe_read_user ssl_info.rbio failed: %d", res);
        }
        fd = bio_r.num;
    } else if(*libssl_version == 3) {
        struct bio_st_v3_0 bio_r;
        res = bpf_probe_read_user(&bio_r, sizeof(bio_r), ssl_info.rbio);
        if (res < 0) {
            bpf_printk("SSL_read enty bpf_probe_read_user ssl_info.rbio failed: %d", res);
        }
        fd = bio_r.num;
        bpf_printk("fd: %d", fd);
    }

    return fd;
}

int dog_debug(u32 pid, u64 tid, int fd, char *str) {
    struct debug_event_t debug_event;
    __builtin_memset(&debug_event, 0, sizeof(debug_event));

    debug_event.eventtype = eDebug;
    debug_event.timestamp_ns = bpf_ktime_get_ns();
    debug_event.pid = pid;
    debug_event.tid = tid;
    debug_event.fd = fd;

    // const char *str = "hello";
    for (int i = 0; i < 5; i++) {
        debug_event.data[i] = str[i];
    }
    debug_event.data_len = 5;

    bpf_ringbuf_output(&data_events, &debug_event, sizeof(struct debug_event_t), 0);

    return 0;
}
