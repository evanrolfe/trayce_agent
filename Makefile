CGO_CFLAGS_STATIC = "-I/app/third_party/libbpfgo/output/"
CGO_LDFLAGS_STATIC = "-lelf -lz /app/third_party/libbpfgo/output/libbpf.a"
CGO_EXTLDFLAGS_STATIC = '-w -extldflags "-static"'
CGO_CFLAGS_STATIC = "-I/app/third_party/libbpfgo/output"

ARCH_FOR_CGO := $(shell uname -m | sed 's/x86_64/amd64/g; s/aarch64/arm64/g')
DIV = "+------------------------------------------------+"

all: build-bpf build

# Install libbpf - clone libbpf-bootstrap which comes with extra tools we need, clone libbpfgo and link it to our
# copy of libbpf from libbpf-bootstrap, then build libbpfgo statically
install-libbpf: clean
	git clone --recurse-submodules https://github.com/libbpf/libbpf-bootstrap ./third_party/libbpf-bootstrap
	git clone https://github.com/aquasecurity/libbpfgo  ./third_party/libbpfgo
	cd third_party/libbpfgo && rmdir libbpf && ln -s ../libbpf-bootstrap/libbpf ./libbpf
	cd third_party/libbpfgo && make libbpfgo-static

# Compile the BPF code to .output/ssl.bpf.o
build-bpf:
	make -C kernel ssl

# Compile our Go binary using .output/ssl.bpf.o
build:
# Bundle the BPF binary into our Go code:
	cp .output/ssl.bpf.o bundle/ssl.bpf.o
	go-bindata -o ./internal/bundle.go ./bundle

# Compile the Go app to our final executable ./dd_agent
	CC=$(CLANG) \
		CGO_CFLAGS=$(CGO_CFLAGS_STATIC) \
		CGO_LDFLAGS=$(CGO_LDFLAGS_STATIC) \
		GOOS=linux GOARCH=$(ARCH_FOR_CGO) \
		CGO_ENABLED=1 \
		go build \
		-tags netgo -ldflags $(CGO_EXTLDFLAGS_STATIC) \
		-o dd_agent ./cmd/dd_agent/main.go

	@echo "\n$(DIV)\n+ Build complete. Binary file at: ./dd_agent\n$(DIV)"

clean:
	rm -rf .output
	rm -rf third_party/libbpf-bootstrap
	rm -rf third_party/libbpfgo
	rm -f internal/bundle.go
