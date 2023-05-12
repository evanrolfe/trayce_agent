FROM ubuntu:latest

WORKDIR /app
COPY ./5.8.0-23-generic.btf /app/5.8.0-23-generic.btf
COPY ./tc /app/tc

RUN apt update -y
RUN apt upgrade -y
RUN apt install -y libelf-dev

CMD mount -t debugfs debugfs /sys/kernel/debug && EXAMPLE_BTF_FILE=5.8.0-23-generic.btf ./tc
