FROM alpine:latest

WORKDIR /app

COPY ./trayce_agent /app/trayce_agent

ENTRYPOINT ["./trayce_agent"]
