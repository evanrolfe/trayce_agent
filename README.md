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
cd ../../ && make
make go
./dd_agent
```

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
