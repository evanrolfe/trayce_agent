# DockerDog

### Setup

Download libbf-bootstrap & lbpfgo:
```
git clone --recurse-submodules https://github.com/libbpf/libbpf-bootstrap ./third_party/libbpf-bootstrap
git clone https://github.com/aquasecurity/libbpfgo  ./third_party/libbpfgo
cd third_party/libbpfgo && rmdir libbpf && ln -s ../libbpf-bootstrap/libbpf ./libbpf
```

### Build
```
docker build . -t ddbuild -f Dockerfile.build
docker run --pid=host --privileged -v ./:/app -it ddbuild
cd third_party/libbpfgo && make libbpfgo-static
cd ../../
make ssl && make go
./dd_agent
```

### Run
```
docker build . -t dd
docker run --pid=host --privileged -it dd
```

### Commands

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

### NsEnter
`docker contaienr inspect ...` to get the PID of the container you want to intercept.

From the dd container:
```
nsenter -t {PID} -n
```
