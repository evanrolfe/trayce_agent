FROM ubuntu:22.04
ENV GO_VERSION=1.22.1

WORKDIR /app

# Build dependencies:
RUN apt update -y
RUN apt install -y ruby-full python3-pip wget libssl-dev git libyaml-dev default-jre default-jdk nodejs

# Debugging tools:
RUN apt install -y curl net-tools iproute2 dnsutils strace ltrace

# Install Ruby/Rails
RUN gem install rails bundler
# Install Python/Flask
RUN pip3 install requests flask pyopenssl

# Install Go
RUN export ARCH=$(dpkg --print-architecture) \
  && wget -q https://go.dev/dl/go${GO_VERSION}.linux-${ARCH}.tar.gz -O /tmp/go.tar.gz \
  && tar -C /usr/local -xf /tmp/go.tar.gz
ENV PATH "$PATH:/usr/local/go/bin:/root/go/bin"

RUN echo "PS1='${debian_chroot:+($debian_chroot)}\[\033[01;35m\]\u@\h\[\033[00m\]:\[\033[01;34m\]\w\[\033[00m\]\$'" >> ~/.bashrc

ADD . /app
RUN cd go && GOARCH=$(dpkg --print-architecture) go build -o mock_server -buildvcs=false -gcflags "all=-N -l" .
RUN cd ror && bundle install

CMD ./run.sh
