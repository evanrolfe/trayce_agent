# Notes

### DockerHub
1. Sign in via command line: `docker login -u pntest`

2. Build with the correct tag: `docker build . -t pntest/trayce_agent`

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

### Links
https://www.linuxjournal.com/article/7905
https://lwn.net/Articles/132196/
https://sungju.github.io/kernel/internals/debugging.html

https://github.com/weaveworks/tcptracer-bpf
https://github.com/yuuki/go-conntracer-bpf

https://www.grant.pizza/blog/tracing-go-functions-with-ebpf-part-2/
