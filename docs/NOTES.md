# Notes

### DockerHub
1. Sign in via command line: `docker login -u pntest`

2. Build with the correct tag: `docker build . --target production -t pntest/trayce_agent`

2. Publish the image with: `docker push pntest/trayce_agent`

### Useful Commands

Start a server with ltrace:
```
ltrace -f -x "@libssl.so.3" ruby start.rb s -b 'ssl://0.0.0.0:3000?key=./config/ssl/localhost.key&cert=./config/ssl/localhost.crt'
```

Install Go dev dependencies:
`go install github.com/shuLhan/go-bindata/cmd/go-bindata@latest`

Get network interface indexes:
`ip link show`

Get trace pipe output (note - this seems to only work from uprobes, not kprobes):
```
mount -t debugfs debugfs /sys/kernel/debug
cat /sys/kernel/debug/tracing/trace_pipe
```

bpftool prog show netdev eth0 egress
tc filter show dev eth0 egress
tc filter del dev eth0 egress pref 49152

Tracing:
`strace -o strace_curl.txt -f -e trace=open,close,connect,sendto,recvfrom,send,recv bash -c 'curl --parallel --parallel-immediate --http1.1 --config urls.txt'`

`strace -f -e trace=open,close,connect,sendto,recvfrom,send,recv,accept,accept4 -p 3437319`
*You need `-f` for Go especially because of threads.

Trace library calls:
`ltrace -x "@libssl.so.3" -o strace.txt curl https://www.pntest.io --http1.1`

Trace libssl with rails (cd ror):
`ltrace -f -x "@libssl.so.3" ruby run.rb s  -b 'ssl://0.0.0.0:3004?key=./config/ssl/localhost.key&cert=./config/ssl/localhost.crt'`

Kernel args wrapped twice (https://stackoverflow.com/questions/69842674/cannot-read-arguements-properly-from-ebpf-kprobe)? Check:
`$ sudo cat /boot/config-$(uname -r) | grep CONFIG_ARCH_HAS_SYSCALL_WRAPPER`

SSL_Set_FD example:
https://github.com/alessandrod/snuffy/blob/master/snuffy-probes/src/snuffy/main.rs#L130

### NsEnter
`docker contaienr inspect ...` to get the PID of the container you want to intercept.

From the dd container:
```
nsenter -t {PID} -n
```

To strace Go you need use -f because of the way it uses threads:
`strace -f ./go_request`

### BPFTrace

`bpftrace -e 'uretprobe:/usr/lib/x86_64-linux-gnu/libssl.so.3:SSL_read { printf("PID %d: SSL_read \n", pid); }'`

`bpftrace trace_libssl_pid.bt`


### Installing curl from source:

Download tag from github

(ensure libssl-dev is installed)

follow instructions (https://curl.se/docs/install.html):
```
./configure --with-openssl
make
make install
```

Try: `/usr/local/bin/curl --version`

May need to run `ldconfig`

### Using dlv
(Go 1.21.4)

dlv debug ./cmd/request/ --build-flags="-buildvcs=false"

b /usr/local/go/src/crypto/tls/conn.go:1182
b /usr/local/go/src/crypto/tls/conn.go:1365
c
print c.conn.fd.pfd.Sysfd

### NodeJS
Get symbols from nodejs (must use a later version, not the one from apt)

`nm -D ./test/mega_server/node/node | grep _ZN4node6crypto7TLSWrap`

### Go TLS

IMPORTANT: If you dont read the entire response body in Go, i.e. `body, _ := io.ReadAll(resp.Body)`, this this
Read() function will not be called on the body!!!

### Links
https://www.linuxjournal.com/article/7905
https://lwn.net/Articles/132196/
https://sungju.github.io/kernel/internals/debugging.html

https://github.com/weaveworks/tcptracer-bpf
https://github.com/yuuki/go-conntracer-bpf

https://www.grant.pizza/blog/tracing-go-functions-with-ebpf-part-2/

https://aquasecurity.github.io/tracee/latest/docs/install/docker/
docker run --name tracee -it --rm \
  --pid=host --cgroupns=host --privileged \
  -v /etc/os-release:/etc/os-release-host:ro \
  -v /var/run:/var/run:ro \
  aquasec/tracee:latest

### Issues with Ruby HTTPS

The FD is never set in Ruby HTTPS requests. One solution I tried was to set the fd to the pointer num of ssl which does work in correleating
the SSL_Reads and SSL_Writes together, but it means we never get to know which connect event they relate to, which means we dont get the
dest or src address.
Instead what I have done now is to set the fd=0 and then in socket_map.go we just pick the first open socket from the map. This needs to be
investigated further because if ruby lets us have multiple sockets open this would cause issues. We might want to use the thread idea because
presumabely there can only be one open socket per thread in Ruby.

```c
    // Instead we use the address of the *ssl arg as a way of correleating SSL_reads with SSL_writes.
    if (fd == -1) {
        fd = ssl;

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
        conn_event.local_ip = 0;
        bpf_probe_read_user(&conn_event.ip, sizeof(u32), &local_ip);
        conn_event.port = 0; // We dont know the port

        bpf_ringbuf_output(&data_events, &conn_event, sizeof(struct connect_event_t), 0);
    }
```

Update: it seems that the TID value is unreliable (connects happen on one TID, then data events on another, sometimes close on a third). However If I ignore the TID and only use PID-FD as the socket key then this all works because the as soon as new connection is opened, the previous one is closed.

It seems to be that puma is calling connect() and SSL_read/write() on separate PIDs and threads, so theres no way to correleate. We should test with a different server and have a fail-safe where if we can correleate simply using the *ssl pointer to correleate requests/response but they won't get the src/dest addresses.

Update 2: I've opted to use two maps in order to track the FD from between different probes, see HOW_IT_WORKS.md

### Go HTTP2 Tracing

https://blog.px.dev/ebpf-http2-tracing/
https://github.com/pixie-io/pixie-demos/tree/main/http2-tracing

HPack Static Table:
https://datatracker.ietf.org/doc/html/rfc7541#appendix-A
