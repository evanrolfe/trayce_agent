FROM ubuntu:22.04

WORKDIR /app

ADD . /app

# Build dependencies:
RUN apt update -y
RUN apt install -y ruby-full python3-pip wget libssl-dev git libyaml-dev

# Debugging tools:
RUN apt install -y curl net-tools iproute2 dnsutils strace ltrace

# Install Ruby/Rails
RUN gem install rails bundler
RUN cd ror && bundle install
# Install Python/Flask
RUN pip3 install requests flask pyopenssl

# Install Go
RUN wget https://go.dev/dl/go1.21.4.linux-amd64.tar.gz -O /tmp/go1.21.4.linux-amd64.tar.gz
RUN tar -C /usr/local -xf /tmp/go1.21.4.linux-amd64.tar.gz
ENV PATH "$PATH:/usr/local/go/bin:/root/go/bin"

RUN echo "PS1='${debian_chroot:+($debian_chroot)}\[\033[01;35m\]\u@\h\[\033[00m\]:\[\033[01;34m\]\w\[\033[00m\]\$'" >> ~/.bashrc

CMD ./run.sh
