# Implementation Details

Network traffic is captured using a combination of eBPF kprobes and uprobes which send events from kernel-space to user-space (Go). In user-space the events are using to build up a `SocketMap` which contains the details of each socket, each socket in the `SocketMap` collects data sent kernel-space until a complete HTTP1.1 or HTTP2 has been gather, at which point it sends the Flow to the GUI over GRPC.

The eBPF probes and their uses are listed below:
- **kprobe/accept4:** indicates an incoming connection has been opened, sends a `ConnectEvent` to Go which creates a socket in `SocketMap`
- **kprobe/connect:** indicates an outgoing connection has been opened, sends a `ConnectEvent` to Go which creates a socket in `SocketMap`
- **kprobe/getsockname:** sends a `GetsocknameEvent` to Go which is used to populate the source/dest address of a socket in `SocketMap`
- **kprobe/close:** indicates a connection has been closed, sends a `CloseEvent` which deletes a socket (if it exists) from the `SocketMap`
- **kprobe/sendto:** indicates data has been sent over a non-encrypted connection, sends a `DataEvent` which collects the data in a socket from `SocketMap` (if it exists)
- **kprobe/recvfrom:** see above
- **kprobe/write:** see above
- **kprobe/read:** see above
- **uprobe/SSL_read:** indicates data has been sent over an encrypted connection, sends a `DataEvent` which collects the data in a socket from `SocketMap` (if it exists)
- **uprobe/SSL_write:** see above
- **uprobe/SSL_write_ex:** see above
- **uprobe/SSL_read_ex:** see above

For non-TLS HTTP traffic, only the kprobes are used. Requests and responses are sent from eBPF to user-space in the form of a `DataEvent`. They are then processed by the `SocketMap`. As soon as a `DataEvent` is received containing a string which identifies the protocol in use (i.e. HTTP1.1 or HTTP2), then the socket is upgraded from `SocketUnknown` to `SocketHTTP11` or `SocketHTTP2`. After the upgrade it will be able to parse a stream of `DataEvent` into Request/Response Flows which are sent over GRPC to the GUI.

![](https://github.com/evanrolfe/trayce_agent/blob/main/docs/img/non_tls_traffic.png)

For TLS-encrypted HTTP traffic by OpenSSL, uprobes for the OpenSSL library calls (`SSL_read`/`SSL_read_ex`/`SSL_write`/`SSL_write_ex`) are using to collect the un-ecrypted data being sent & received. As soon as a `DataEvent` is received from a probe indicating encrypted traffic, the socket in the `SocketMap` is marked as `SSl=true` and all future `DataEvent`s coming from kprobes are ignored so that it does not try to process encrypted data.

For TLS-encrypted HTTP traffic by Go's `crypto/tls` package, uprobes for the functions `crypto/tls.(*Conn).Write` and `crypto/tls.(*Conn).Read` are attached to the running process. These uprobes send `DataEvents` which contain the unecrypted data. It also marks the socket with `SSl=true`.

**eBPF Probes**

|        Probe        | Python | Python TLS | Ruby | Ruby TLS | Go  | Go TLS |
| ------------------- | ------ | ---------- | ---- | -------- | --- | ------ |
| kprobe/accept4      | X      | X          | X    | X        | X   | X      |
| kprobe/connect      | X      | X          | X    | X        | X   | X      |
| kprobe/getsockname  | X      | X          | X    | X        | X   | X      |
| kprobe/close        | X      | X          | X    | X        | X   | X      |
| kprobe/sendto       | X      | .          | X    | .        | .   | .      |
| kprobe/recvfrom     | X      | .          | X    | .        | .   | .      |
| kprobe/write        | .      | .          | .    | .        | X   | .      |
| kprobe/read         | .      | .          | .    | .        | X   | .      |
| uprobe/SSL_read     | .      | .          | .    | X        | .   | .      |
| uprobe/SSL_write    | .      | .          | .    | X        | .   | .      |
| uprobe/SSL_write_ex | .      | X          | .    | .        | .   | .      |
| uprobe/SSL_read_ex  | .      | X          | .    | .        | .   | .      |

**Trayce Agent Go Implementation**

The Trayce Agent repo follows a standard Go package layout, with the compiled binary entrypoint at `./cmd/trayce_agent/main.go`. The package at `./api` is used for the GRPC client which sends and receives data to the GUI. Some of the package in `./internal` are:
- `docker` - uses the docker client to get the containers running on this machine and which processes belong to them
- `ebpf` - sets up and runs the eBPF probes, it also receives events from eBPF and outputs them to a channel
- `events` - structs for the events sent from eBPF probes
- `sockets` - receives the events from the ebpf output channel and parses them into request/response Flows

**Container tracking**

Every time a new container is set to be intercepted, `internal/ebpf/stream.go` checks if there is an OpenSSL lib on the container, if there is then it attaches uprobes to it to intercept the SSL_*() calls. It also sets the container ID on the `cgroup_name_hashes` map which ebpf uses to filter out calls based on the cgroup name of the PID.

Every time a new process on a container is open, `internal/ebpf/stream.go` attempts to attach uprobes to the Go `crypto/tls` function calls,  if it fails its probably not a Go binary.

**Null-FD workaround**

Connections are stored in the `SocketMap` using their PID and FD (file descriptor) as key, it matches up `DataEvent`s with Connections using that same key. In some cases, (i.e. Ruby TLS traffic), the FD is always set to -1 when `SSL_Read` & `SSL_Write` are called, this is a problem because it prevents us from matching up `DataEvents` with their connections in the `SocketMap`. So in order to keep find the FD for the `DataEvent`, two maps are used to keep track the FD between different calls:
- in `kprobe/recvfrom` the FD is set on the `fd_map` using `current_pid_tgid` key
- in `uprobe/SSL_Read` the FD is fetched from `fd_map` (see `get_fd_from_libssl_read()`) and the saved again to `ssl_fd_map` using the `ssl` pointer num as key
- in `uprobe/SSL_Write` the FD is fetched from `ssl_fd_map` since `SSL_Read` and `SSL_Write` both have the same pointer to the `ssl` arg

![](https://github.com/evanrolfe/trayce_agent/blob/main/docs/img/fd_map.png)
