FROM alpine:3.17

WORKDIR /app
ADD ./ /app

RUN apk upgrade --no-cache
RUN apk add bash curl git make gcc perl musl-dev linux-headers automake autoconf libtool m4

RUN git clone https://github.com/openssl/openssl.git
RUN cd openssl && ./Configure && make


ENTRYPOINT ["bash"]
