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
docker run --privileged -v ./:/app -it ddbuild
cd third_party/libbpfgo && make libbpfgo-static
cd ../../ && make tc
make go
./dd_agent
```

### SSL
go build -o testuprobe ./cmd/testuprobe/main.go
make go && ./dd_agent ./testuprobe main.testFunction
./testuprobe

./dd_agent /usr/lib/x86_64-linux-gnu/libssl.so.3 SSL_write

### Run
```
docker build . -t dd
docker run --privileged -it dd
```

### Commands

Get network interface indexes:
`ip link show`

Get trace pipe output:
`cat /sys/kernel/debug/tracing/trace_pipe`


bpftool prog show netdev eth0 egress
tc filter show dev eth0 egress
tc filter del dev eth0 egress pref 49152
