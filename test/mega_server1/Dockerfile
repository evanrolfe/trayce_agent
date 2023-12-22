FROM ubuntu:20.04

WORKDIR /app

ADD . /app

# Build dependencies:
RUN apt update -y
RUN apt install -y python3-pip wget git libyaml-dev

# Debugging tools:
# RUN apt install -y curl net-tools iproute2 dnsutils strace ltrace

# Install Python/Flask
RUN pip3 install requests flask pyopenssl

CMD bash
