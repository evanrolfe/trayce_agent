# get_sock()

This wonderous function in `kernel/common.h` means that all data events have the source and destination TCP addresses sent with them. I no longer need to track `connect()`, `fork()` or `getsockname()` syscalls anymore to get those addresses. This vastly simplifes the SocketMap too.

I have also changed the key used in SocketMap to be the source and destination address i.e. "172.18.0.1:12345->172.18.0.2:80", this means I dont have to care about process forking.

There is still one unresolved issue which is that the source and destination addresses are sometimes in the wrong place.

I did also try writing tracepoints instead of krpobes i.e. `tracepoint/syscalls/sys_enter_recvfrom`, that worked fine for sendto, but for recvfrom, for some reason it was sending the payload along with a bunch of other data, basically the buf_len was always 8192 event though the real payload was only ~50 bytes long. I couldn't figure out why this was happening and the same behaviour did not occur in kprobes so I ditched the tracepoints.

**Postgres prepared queries**
I've discovered that for prepared queries postgres will somehow save that query in the database, so you only see it sent over TCP once. This obviously problematic for us, but if you disable prepared queries then we get the query sent over TCP every time. It appears that MySQL works in the same way.
