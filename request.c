// gcc request.c -lssl -lcrypto -o request

// Copyright 2021 Alexey Kutepov <reximkut@gmail.com>
//
// Permission is hereby granted, free of charge, to any person obtaining
// a copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to
// permit persons to whom the Software is furnished to do so, subject to
// the following conditions:
//
// The above copyright notice and this permission notice shall be
// included in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
// NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
// LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
// OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
// WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

#define _POSIX_C_SOURCE 200112L

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdbool.h>

#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#define HOST "tsoding.github.io"
#define PORT "443"

int main(int argc, char **argv)
{
    struct addrinfo hints = {0};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    struct addrinfo *addrs;
    if (getaddrinfo(HOST, PORT, &hints, &addrs) < 0) {
        fprintf(stderr, "Could not get address of `"HOST"`: %s\n", strerror(errno));
        exit(1);
    }

    int fd = 0;
    for (struct addrinfo *addr = addrs; addr != NULL; addr = addr->ai_next) {
        fd = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);

        if (fd == -1) break;
        if (connect(fd, addr->ai_addr, addr->ai_addrlen) == 0) break;

        close(fd);
        fd = -1;
    }
    freeaddrinfo(addrs);

    if (fd == -1) {
        fprintf(stderr, "Could not connect to "HOST":"PORT": %s\n", strerror(errno));
        exit(1);
    }

    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());

    if (ctx == NULL) {
        fprintf(stderr, "ERROR: could not initialize the SSL context: %s\n", strerror(errno));
        exit(1);
    }

    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, fd);

    if (SSL_connect(ssl) < 0) {
        fprintf(stderr, "ERROR: could not connect via SSL: %s\n", strerror(errno));
        exit(1);
    }

    const char *request =
        "GET / HTTP/1.1\r\n"
        "Host: tsoding.github.io\r\n"
        "Connection: close\r\n"
        "\r\n";

    SSL_write(ssl, request, strlen(request));

    int ssl_fd = SSL_get_fd(ssl);
    printf("FD from SSL: %d\n", ssl_fd);

    char buffer[1024];
    ssize_t n = SSL_read(ssl, buffer, sizeof(buffer));
    while (n > 0) {
        fwrite(buffer, 1, n, stdout);
        n = SSL_read(ssl, buffer, sizeof(buffer));
    }

    ssl_fd = SSL_get_fd(ssl);
    printf("FD from SSL: %d\n", ssl_fd);

    SSL_set_shutdown(ssl, SSL_RECEIVED_SHUTDOWN | SSL_SENT_SHUTDOWN);
    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ctx);

    close(fd);
    fprintf(stdout, "FD: %d\n", fd);

    return 0;
}