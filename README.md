# DockerDog

### Setup

Download libbf-bootstrap:
```
git clone --recurse-submodules https://github.com/libbpf/libbpf-bootstrap
```

### Build
```
docker build . -t ddbuild -f Dockerfile.build
docker run --privileged -v ./:/app -it ddbuild
make
EXAMPLE_BTF_FILE=5.8.0-23-generic.btf ./tc
```

### Run
```
docker build . -t dd
docker run --privileged -v ./:/app -it dd
```

### Commands

Get network interface indexes:
`ip link show`
