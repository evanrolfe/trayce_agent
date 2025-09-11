# Issues intercepting curl on alpine

I started an alpine container and make a curl request to https://trayce.dev and noticed nothing came back. Turns out libssl was located in a path that wasn't account for so I added `/usr/lib/libssl.so.3` and `/usr/lib/libssl.so.1.1` to `containers.go`.

There was another issue that it was extracting the incorrect fd from `ssl_info.rbio` in `get_fd_from_libssl_read()`. However we had the correct fd stored in `fd_map` so I made that the first choice for getting the fd and did the same in `get_fd_from_libssl_write()`.

Remaining issues are now all in the user-space Go code. The HTTP2 parsing seems to fail for `curl https://trayce.dev` so this needs to be looked at.
