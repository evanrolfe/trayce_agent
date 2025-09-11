# Issues intercepting curl on alpine

I started an alpine container and make a curl request to https://trayce.dev and noticed nothing came back. Turns out libssl was located in a path that wasn't account for so I added `/usr/lib/libssl.so.3` and `/usr/lib/libssl.so.1.1` to `containers.go`.

There was another issue that it was extracting the incorrect fd from `ssl_info.rbio` in `get_fd_from_libssl_read()`. However we had the correct fd stored in `fd_map` so I made that the first choice for getting the fd and did the same in `get_fd_from_libssl_write()`.

Remaining issues are now all in the user-space Go code. The HTTP2 parsing seems to fail for `curl https://trayce.dev` so this needs to be looked at.

# Issues with outgoing https requests

The solution I came up with in `docs/log/2024-07-22_null_fd_problem_in_ruby.md` only works for incoming requests. So I modified `get_fd_from_libssl_write()` and `get_fd_from_libssl_read()` so that it works symmetrically. For example, before it would only work in this direction:

1. kprobe/recvfrom sets fd_map
2. uproble/ssl_read gets fd_map[id], sets ssl_fd_map[*ssl]
3. uprobe/ssl_write gets ssl_fd_map[*ssl]

Now it works in the other direction too:
1. kprobe/sendto sets fd_map
2. uprobe/ssl_write gets fd_map[id], sets ssl_fd_map[*ssl]
3. uproble/ssl_read gets ssl_fd_map[*ssl]
