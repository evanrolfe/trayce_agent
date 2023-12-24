FROM alpine:latest

WORKDIR /app
RUN mkdir /app/.output

COPY .output/ssl.bpf.o /app/.output/ssl.bpf.o
COPY ./5.8.0-23-generic.btf /app/5.8.0-23-generic.btf
COPY ./trayce_agent /app/trayce_agent

CMD mount -t debugfs debugfs /sys/kernel/debug && sh # ./trayce_agent
