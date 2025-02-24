CGO_CFLAGS_STATIC = "-I/app/third_party/libbpfgo/output/"
CGO_LDFLAGS_STATIC = "/app/third_party/libbpfgo/output/libbpf/libbpf.a -lelf -lzstd"
CGO_EXTLDFLAGS_STATIC = '-w'
CGO_CFLAGS_STATIC = "-I/app/third_party/libbpfgo/output"
CGO_FLAGS = CC=$(CLANG) CGO_CFLAGS=$(CGO_CFLAGS_STATIC) CGO_LDFLAGS=$(CGO_LDFLAGS_STATIC) GOARCH=$(ARCH_FOR_CGO) GOOS=linux CGO_ENABLED=1
ARCH_FOR_CGO := $(shell uname -m | sed 's/x86_64/amd64/g; s/aarch64/arm64/g')
DIV = "+------------------------------------------------+"
SED_PASS = ''/PASS/s//$$(printf "\033[32mPASS\033[0m")/''
SED_FAIL = ''/FAIL/s//$$(printf "\033[31mFAIL\033[0m")/''

.PHONY: all test clean

all: build-bpf build

# Install libbpf - clone libbpf-bootstrap which comes with extra tools we need, clone libbpfgo and link it to our
# copy of libbpf from libbpf-bootstrap, then build libbpfgo statically
install-libbpf: clean
	git clone --recurse-submodules https://github.com/libbpf/libbpf-bootstrap ./third_party/libbpf-bootstrap
	git clone https://github.com/aquasecurity/libbpfgo  ./third_party/libbpfgo
	cd third_party/libbpf-bootstrap && git checkout 70de71d17613a25b7d43ce9a0ec649be1af1c4c9
	cd third_party/libbpfgo && make libbpfgo-static

# Compile the BPF code to .output/main.bpf.o
build-bpf:
	rm -f .output/main.*
	make -C kernel main

generate:
# Bundle the BPF binary into our Go code:
	cp .output/main.bpf.o bundle/main.bpf.o
	go-bindata -o ./internal/bundle.go ./bundle

# Generate the grpc code
	protoc --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative api/api.proto

# Generates the code for the grpc test server in mega_server
generate-test:
	go build -o test/mega_server/go -buildvcs=false -gcflags "all=-N -l" ./cmd/mock_server/
	go build -o test/mega_server/go -buildvcs=false -gcflags "all=-N -l" ./cmd/grpc_server/

# Compile our Go binary using .output/main.bpf.o
build: generate
# Compile the Go app to our final executable ./trayce_agent
	$(CGO_FLAGS) \
	go build \
	-tags netgo -ldflags $(CGO_EXTLDFLAGS_STATIC) \
	-o trayce_agent ./cmd/trayce_agent/main.go

	@echo "\n$(DIV)\n+ Build complete. Binary executable at: ./trayce_agent\n$(DIV)"

# test runs the tests but it also starts the trayce_agent process, its intended to be used during local development
# from within the build container
test:
	START_AGENT=false go test ./test -v -count=1 -short -run Test_agent_server

testload:
	$(CGO_FLAGS) \
	START_AGENT=true go test ./test -v -count=1 -run Test_agent_server | sed $(SED_PASS) | sed $(SED_FAIL)

testunit: generate
	$(CGO_FLAGS) \
	ginkgo \
	-tags netgo -ldflags $(CGO_EXTLDFLAGS_STATIC) \
	-v -r ./internal/sockets

mockgrpc:
	$(CGO_FLAGS) \
	go run ./cmd/grpc_server

clean:
	rm -rf .output
	rm -rf third_party/libbpf-bootstrap
	rm -rf third_party/libbpfgo
	rm -f internal/bundle.go

dev:
	docker run --pid=host --privileged -v ./:/app -v /var/run/docker.sock:/var/run/docker.sock --network trayce_network -it trayce_agent:local bash

decision:
	@timestamp=$$(date +"%Y-%m-%d"); \
	touch "docs/log/$${timestamp}_TODO.md"
