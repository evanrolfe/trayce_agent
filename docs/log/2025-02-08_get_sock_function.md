# get_sock() function
This wondrous function in `kernel/common.h` enables all data events to have their source and destination TCP addresses sent with them. I no longer need to track `connect()`, `fork()`, or `getsockname()` syscalls to get those addresses. This vastly simplifies the SocketMap too. The key used in SocketMap is now the source and destination address i.e. `172.18.0.1:12345->172.18.0.2:80`. This means I don't have to care about process forking anymore.

There is still one unresolved issue: the source and destination addresses are sometimes in the wrong place.

I did also try writing tracepoints instead of kprobes (i.e., `tracepoint/syscalls/sys_enter_recvfrom`). That worked fine for sendto, but for recvfrom, for some reason it was sending the payload along with a bunch of other data - basically, the buf_len was always 8192 even though the real payload was only ~50 bytes long. I couldn't figure out why this was happening, and the same behavior did not occur in kprobes, so I ditched the tracepoints.

**Postgres Prepared Queries**

I've discovered that for prepared queries, Postgres will save that query in the database, so you only see it sent over TCP once. This is obviously problematic for us, but if you disable prepared queries, then we get the query sent over TCP every time. It appears that MySQL works in the same way.
