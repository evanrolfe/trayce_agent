#
# Build Image
#
FROM ubuntu:25.04 AS build
ENV GO_VERSION=1.23.8

# Build dependencies:
RUN apt update -y
RUN apt upgrade -y
RUN apt install --fix-missing -y \
    clang \
    libelf1 \
    libelf-dev \
    zlib1g-dev \
    make \
    build-essential \
    libz-dev \
    libcap-dev \
    llvm \
    llvm-dev \
    lld \
    binutils-dev \
    pkg-config \
    linux-tools-generic \
    wget \
    binutils \
    git \
    libssl-dev \
    protobuf-compiler \
    gcc \
    libzstd-dev

# Debugging tools:
# RUN apt install -y curl net-tools iproute2 dnsutils strace ltrace
# RUN apt install -y python3-pip ruby
# RUN pip3 install requests

# Install Go
RUN export ARCH=$(dpkg --print-architecture) \
  && wget -q https://go.dev/dl/go${GO_VERSION}.linux-${ARCH}.tar.gz -O /tmp/go.tar.gz \
  && tar -C /usr/local -xf /tmp/go.tar.gz
ENV PATH="$PATH:/usr/local/go/bin:/root/go/bin"

# Go Build dependencies
RUN go install github.com/shuLhan/go-bindata/cmd/go-bindata@latest
RUN go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.28
RUN go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.2
RUN go install github.com/onsi/ginkgo/v2/ginkgo@v2.12.0
RUN echo "PS1='${debian_chroot:+($debian_chroot)}\[\033[01;35m\]\u@\h\[\033[00m\]:\[\033[01;34m\]\w\[\033[00m\]\$'" >> ~/.bashrc

WORKDIR /app
ADD . /app

RUN make install-libbpf
RUN make

#
# Final Image
#
FROM ubuntu:25.04 AS final

WORKDIR /app
RUN apt update -y && apt install -y libelf-dev ca-certificates

COPY --from=build /app/trayce_agent /app/trayce_agent

ENTRYPOINT ["/app/trayce_agent"]
