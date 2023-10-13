CGO_CFLAGS_STATIC = "-I/app/third_party/libbpfgo/output/"
CGO_LDFLAGS_STATIC = "-lelf -lz /app/third_party/libbpfgo/output/libbpf.a"
CGO_EXTLDFLAGS_STATIC = '-w -extldflags "-static"'
CGO_CFLAGS_STATIC = "-I/app/third_party/libbpfgo/output"
CGO_FLAGS = CC=$(CLANG) CGO_CFLAGS=$(CGO_CFLAGS_STATIC) CGO_LDFLAGS=$(CGO_LDFLAGS_STATIC) GOARCH=$(ARCH_FOR_CGO) GOOS=linux CGO_ENABLED=1
ARCH_FOR_CGO := $(shell uname -m | sed 's/x86_64/amd64/g; s/aarch64/arm64/g')
DIV = "+------------------------------------------------+"

.PHONY: all test clean

all: build-bpf build

# Install libbpf - clone libbpf-bootstrap which comes with extra tools we need, clone libbpfgo and link it to our
# copy of libbpf from libbpf-bootstrap, then build libbpfgo statically
install-libbpf: clean
	git clone --recurse-submodules https://github.com/libbpf/libbpf-bootstrap ./third_party/libbpf-bootstrap
	git clone https://github.com/aquasecurity/libbpfgo  ./third_party/libbpfgo
	cd third_party/libbpfgo && rmdir libbpf && ln -s ../libbpf-bootstrap/libbpf ./libbpf
	cd third_party/libbpfgo && make libbpfgo-static

# Compile the BPF code to .output/main.bpf.o
build-bpf:
	make -C kernel main

generate:
# Bundle the BPF binary into our Go code:
	cp .output/main.bpf.o bundle/main.bpf.o
	go-bindata -o ./internal/bundle.go ./bundle

# Generate the grpc code
	protoc --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative api/api.proto

# Compile our Go binary using .output/main.bpf.o
build: generate
# Compile the Go app to our final executable ./dd_agent
	$(CGO_FLAGS) \
	go build \
	-tags netgo -ldflags $(CGO_EXTLDFLAGS_STATIC) \
	-o dd_agent ./cmd/dd_agent/main.go

	@echo "\n$(DIV)\n+ Build complete. Binary executable at: ./dd_agent\n$(DIV)"

test:
	$(CGO_FLAGS) \
	go test ./test -v -count=1 -short
# -run Test_kprobe_write2

testload:
	$(CGO_FLAGS) \
	go test ./test -v -count=1

testunit: generate
	$(CGO_FLAGS) \
	ginkgo \
	-tags netgo -ldflags $(CGO_EXTLDFLAGS_STATIC) \
	-v -r ./internal/... ./api/...

clean:
	rm -rf .output
	rm -rf third_party/libbpf-bootstrap
	rm -rf third_party/libbpfgo
	rm -f internal/bundle.go
