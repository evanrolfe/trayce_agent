FROM ubuntu:22.04 AS build

WORKDIR /app

ADD . /app

# Build dependencies:
RUN apt-get update -y \
  && apt-get install -y \
  clang libelf1 libelf-dev zlib1g-dev make build-essential libz-dev libcap-dev \
  llvm llvm-dev lld binutils-dev pkg-config linux-tools-generic wget binutils \
  git libssl-dev protobuf-compiler \
  # debugging tools
  curl net-tools iproute2 dnsutils strace ltrace bash python3-pip ruby \
  && pip3 install requests

ENV GO_VERSION=1.21.12

# Install Go
RUN export ARCH=$(dpkg --print-architecture) \
  && wget -q https://go.dev/dl/go${GO_VERSION}.linux-${ARCH}.tar.gz -O /tmp/go${GO_VERSION}.linux-${ARCH}.tar.gz \
  && tar -C /usr/local -xf /tmp/go${GO_VERSION}.linux-${ARCH}.tar.gz
ENV PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/go/bin:/root/go/bin

RUN echo "PS1='${debian_chroot:+($debian_chroot)}\[\033[01;35m\]\u@\h\[\033[00m\]:\[\033[01;34m\]\w\[\033[00m\]\$'" >> ~/.bashrc

RUN make build-deps && make install-libbpf

FROM build AS compile

# not sure why I have to move this archive, its not in the expected place
RUN mv ./third_party/libbpfgo/output/app/third_party/libbpfgo/output/libbpf/libbpf.a ./third_party/libbpfgo/output/ \
  && make

FROM alpine:latest AS production

WORKDIR /app

COPY --from=compile /app/trayce_agent /app/trayce_agent

ENTRYPOINT ["./trayce_agent"]
