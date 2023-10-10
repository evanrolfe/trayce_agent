FROM alpine:latest

WORKDIR /app
RUN mkdir /app/.output

COPY .output/ssl.bpf.o /app/.output/ssl.bpf.o
COPY ./5.8.0-23-generic.btf /app/5.8.0-23-generic.btf
COPY ./dd_agent /app/dd_agent

CMD mount -t debugfs debugfs /sys/kernel/debug && sh # ./dd_agent
