//go:build exclude

// -----------------------------------------------------------------------------
// common.h
// -----------------------------------------------------------------------------
#define TASK_COMM_LEN 16
#define CGROUP_LEN 128
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
enum connect_event_type { kConnect, kAccept };
enum data_event_type { kSSLRead, kSSLWrite, kRead, kWrite, kRecvfrom, kSendto, goTlsRead, goTlsWrite };
enum protocol_type { pUnknown, pHttp };
const u32 invalidFD = 0;

struct data_event_t {
    u64 eventtype;
    u64 type;
    u64 timestamp_ns;
    u32 pid;
    u32 tid;
    char cgroup[CGROUP_LEN];
    u32 fd;
    s32 version;
    u64 rand;
    s32 data_len;
    char data[MAX_DATA_SIZE_OPENSSL];
};

struct connect_event_t {
    u64 eventtype;
    u64 type;
    u64 timestamp_ns;
    u32 pid;
    u32 tid;
    u32 fd;
    char cgroup[CGROUP_LEN];
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
// The key is the djb2 hash of a ccgroup name, the value is 1 if we want to intercept this cgroup
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u64);
    __type(value, u32);
    __uint(max_entries, 1024);
} cgroup_name_hashes SEC(".maps");

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
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u64);
    __type(value, u32);
    __uint(max_entries, 1024);
} fd_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u64);
    __type(value, u32);
    __uint(max_entries, 1024);
} ssl_fd_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1024 * 1024); // Important that its big enough otherwise events will be dropped and cause weird behaviour
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

static __inline struct connect_event_t copy_connect_event(struct connect_event_t *conn_event, int new_fd) {
    struct connect_event_t conn_event2;
    __builtin_memset(&conn_event2, 0, sizeof(conn_event2));
    conn_event2.eventtype = eConnect;
    conn_event2.type = conn_event->type;
    conn_event2.timestamp_ns = bpf_ktime_get_ns();
    conn_event2.pid = conn_event->pid;
    conn_event2.tid = conn_event->tid;
    conn_event2.fd = new_fd;
    bpf_probe_read_str(&conn_event2.cgroup, sizeof(conn_event2.cgroup), conn_event->cgroup);

    return conn_event2;
}

// >> 32 - PID
// << 32 - TGID
static __inline u64 gen_pid_fd(u64 current_pid_tgid, int fd) {
    u32 pid = current_pid_tgid >> 32;
    u32 tgid = current_pid_tgid << 32;

    // Don't ask me why this works, but it does..
    return (u64) tgid | (u32) fd;
}

static int process_data(struct pt_regs* ctx, u64 id, enum data_event_type type, const char* buf, size_t buf_len, u32 fd) {
    if (buf_len < 0) {
        return 0;
    }

    // Get the cgroup name
    struct task_struct *cur_tsk = (struct task_struct *)bpf_get_current_task();
    if (cur_tsk == NULL) {
        bpf_printk("failed to get cur task\n");
        return -1;
    }
    int cgrp_id = memory_cgrp_id;
    const char *name = BPF_CORE_READ(cur_tsk, cgroups, subsys[cgrp_id], cgroup, kn, name);

    // Handling buffer split
    const char *str_ptr = buf;
    s32 remaining_buf_len = buf_len;
    const char *current_str_ptr = str_ptr;
    s32 chunk_size;

    // NOTE: For some reason EBPF verifier will not accept `while (remaining_buf_len <= 0)`, so instead we have to use this
    // for loop where 5000 is arbitrary an upper limit that is still acceptable by the ebpf verifier.
    // This effectively means that we can handle response payloads up to 20MB large. (5000 * 4096 bytes = 20.48MB)
    for (int i = 0; i < 5000; i++) { // Unroll the loop up to 32 times, adjust as necessary
        if (remaining_buf_len <= 0) {
            break;
        }

        struct data_event_t* event = create_data_event(id);
        if (event == NULL) {
            return 0;
        }
        event->type = type;
        event->fd = fd;
        bpf_probe_read_str(&event->cgroup, sizeof(event->cgroup), name); // be careful with the placement of this line, it can upset the verifier
        event->data_len = (remaining_buf_len < MAX_DATA_SIZE_OPENSSL ? (remaining_buf_len & (MAX_DATA_SIZE_OPENSSL - 1)): MAX_DATA_SIZE_OPENSSL);

        bpf_probe_read_user(event->data, event->data_len, current_str_ptr);
        bpf_ringbuf_output(&data_events, event, sizeof(struct data_event_t), 0);

        // Move the pointer and reduce the remaining length
        current_str_ptr += event->data_len;
        remaining_buf_len -= event->data_len;
    }

    return 0;
}

static u32 get_fd_from_libssl_read(struct ssl_st ssl_info, u32 pid, u64 current_pid_tgid) {
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
    }

    if (fd == -1) {
        int* fd2 = bpf_map_lookup_elem(&fd_map, &current_pid_tgid);

        if (fd2 != NULL) {
            fd = *fd2;
        }
    }

    return fd;
}

static u32 get_fd_from_libssl_write(struct ssl_st ssl_info, u32 pid, u64 ssl_ptr) {
    int res;
    u32 fd;
    int *libssl_version = bpf_map_lookup_elem(&libssl_versions_map, &pid);
    if (libssl_version == NULL) {
        return 0;
    }
    if (*libssl_version == 1) {
        struct bio_st_v1_1_1 bio_w;
        res = bpf_probe_read_user(&bio_w, sizeof(bio_w), ssl_info.wbio);
        if (res < 0) {
            bpf_printk("SSL_write enty bpf_probe_read_user ssl_info.rbio failed: %d", res);
        }
        fd = bio_w.num;
    } else if(*libssl_version == 3) {
        struct bio_st_v3_0 bio_w;
        res = bpf_probe_read_user(&bio_w, sizeof(bio_w), ssl_info.wbio);
        if (res < 0) {
            bpf_printk("SSL_write enty bpf_probe_read_user ssl_info.rbio failed: %d", res);
        }
        fd = bio_w.num;
    }

    if (fd == -1) {
        int* fd2 = bpf_map_lookup_elem(&ssl_fd_map, &ssl_ptr);

        if (fd2 != NULL) {
            fd = *fd2;
        }
    }

    return fd;
}

int trayce_debug(u32 pid, u64 tid, int fd, char *str) {
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

// hash_string implements the djb2 algorithm, see http://www.cse.yorku.ca/~oz/hash.html
static __inline u64 hash_string(const char *str, int length) {
    u64 hash = 5381;
    int c;
    for (int i = 0; i < length && (c = str[i]) != '\0'; i++) {
        hash = ((hash << 5) + hash) + c; // hash * 33 + c
    }
    return hash;
}

// compare the djb2 hash of the cgroup with whats in the map, we use a hash because string comparison and substring operations
// are tricky in ebpf given the max 512 byte stack size
static __inline int should_intercept() {
    struct task_struct *cur_tsk = (struct task_struct *)bpf_get_current_task();
    if (cur_tsk == NULL) {
        bpf_printk("failed to get cur task\n");
        return -1;
    }
    int cgrp_id = memory_cgrp_id;
    const char *name = BPF_CORE_READ(cur_tsk, cgroups, subsys[cgrp_id], cgroup, kn, name);

    char cgroupname[CGROUP_LEN];
    bpf_probe_read_str(&cgroupname, sizeof(cgroupname), name);

    u64 hash = hash_string(cgroupname, CGROUP_LEN);
    u32 *intercepted = bpf_map_lookup_elem(&cgroup_name_hashes, &hash);
    if (intercepted != NULL) {
        return 1;
    }

    return 0;
}



// check for sub string
// int i = 0, j = 0;
// for (i = 0; i < CGROUP_LEN && cgroupname[i] != '\0'; i++) {
//     if (cgroupname[i] == substr[0]) {
//         // Check the rest of the substring
//         for (j = 0; j < 12 && substr[j] != '\0'; j++) {
//             // If characters don't match or main string ends, break
//             if (i + j >= CGROUP_LEN || cgroupname[i + j] != substr[j]) {
//                 break;
//             }
//         }

//         if (j == 12 && substr[j] == '\0') {
//             bpf_printk("matched cgroup: %s", cgroupname);
//             return 1;
//         }
//     }
// }
