FROM python:3.11-slim

ENV HOST_NAME=0.0.0.0
ENV PORT=8090

WORKDIR /app
ADD ./ /app

RUN apt update -y
# RUN apt install -y curl iproute2 inetutils-ping net-tools traceroute tcpdump

RUN pip install --upgrade pip
RUN pip install requests

EXPOSE 8090

ENTRYPOINT ["bash"]
