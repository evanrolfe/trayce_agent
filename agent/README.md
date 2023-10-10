# DockerDog

### Build
Start the build container:
```
docker build . -t ddbuild -f Dockerfile.build
docker run --privileged -v ./:/app -v /var/run/docker.sock:/var/run/docker.sock -it ddbuild
```

Then from within the container run:
```
make install-libbpf
make
```

### Run
Once you have the built binary at `./dd_agent` run:

```
docker build . -t dd
docker run --pid=host --privileged -it dd
```

### Test
Run tests with:
```
make test
```

### Commands

`curl https://www.pntest.io --http1.1`

Install Go dev dependencies:
`go install github.com/shuLhan/go-bindata/cmd/go-bindata@latest`

Get network interface indexes:
`ip link show`

Get trace pipe output:
`cat /sys/kernel/debug/tracing/trace_pipe`

bpftool prog show netdev eth0 egress
tc filter show dev eth0 egress
tc filter del dev eth0 egress pref 49152

Tracing:
`strace -o strace_curl.txt -f -e trace=open,close,connect,sendto,recvfrom,send,recv bash -c 'curl --parallel --parallel-immediate --http1.1 --config urls.txt'`

Trace library calls:
`ltrace -x "@libssl.so.3" -o strace.txt curl https://www.pntest.io --http1.1`

Kernel args wrapped twice (https://stackoverflow.com/questions/69842674/cannot-read-arguements-properly-from-ebpf-kprobe)? Check:
`$ sudo cat /boot/config-$(uname -r) | grep CONFIG_ARCH_HAS_SYSCALL_WRAPPER`

### NsEnter
`docker contaienr inspect ...` to get the PID of the container you want to intercept.

From the dd container:
```
nsenter -t {PID} -n
```

To strace Go you need use -f because of the way it uses threads:
`strace -f ./go_request`

### Installing curl:

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

### Links
https://www.linuxjournal.com/article/7905
https://lwn.net/Articles/132196/
https://sungju.github.io/kernel/internals/debugging.html

https://github.com/weaveworks/tcptracer-bpf
https://github.com/yuuki/go-conntracer-bpf

https://www.grant.pizza/blog/tracing-go-functions-with-ebpf-part-2/
