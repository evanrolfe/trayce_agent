# Implementation Details

**Overview**
Network traffic is captured using a combination of eBPF kprobes and uprobes. `kprobe/accept4` is called when a new connection is opened, we immediately send the connection to the user-space Go program which opens up a new socket in the SocketMap. When `kprobe/close` is called the socket is deleted from SocketMap. Because we only intercept the accept4() syscall and not connect(), we only track incoming requests to containers, this means we dont have to deal with duplicate traffic when multiple containers are intercepted and requests are made from container-to-container. The downside is that outbound requests are ignored.

For non-TLS HTTP traffic, only the kprobes are used. Requests and responses are sent from eBPF to user-space in the form of a DataEvent. They are then processed by the SocketMap. As soon as a DataEvent is received containing a string which identifies the protocol in use (i.e. HTTP1.1 or HTTP2), then the socket is upgraded from SocketUnknown to SocketHTTP11 or SocketHTTP2. After the upgrade it will be able to parse a stream of DataEvents into Request/Response Flows which are sent over GRPC to the GUI.

![](https://github.com/evanrolfe/trayce_agent/blob/main/docs/non_tls_traffic.png)

For TLS-encrypted HTTP traffic (OpenSSL), the accept4() and close() kprobes are used along with uprobes for the OpenSSL library calls (SSL_read/SSL_read_ex/SSL_write/SSL_write_ex). As soon as a DataEvent is received from a probe indicating encrypted traffic, the socket in the SocketMap is marked as `SSl=true` and all future DataEvents coming from kprobes are ignored so that it does not try to process encrypted data.

For TLS-encrypted HTTP traffic (Go), the accept4() and close() kprobes are used along with uprobes for the `crypto/tls.(*Conn).Write` and `crypto/tls.(*Conn).Read` functions in Go's `crypto/tls` package.

**Null-FD workaround**
Connections are stored in the SocketMap using their PID and FD as key, it matches up DataEvents with Connections using that same key. In some cases, (i.e. Ruby TLS traffic), the FD is always set to -1 when SSL_Read & SSL_Write are called, this is a problem because it prevents us from matching up DataEvents with their connections in the SocketMap. So in order to keep find the FD for the DataEvent, two maps are used to keep track the FD between different calls:
- in `kprobe/recvfrom` the FD is set on the `fd_map` using `current_pid_tgid` key
- in `uprobe/SSL_Read` the FD is fetched from `fd_map` (see `get_fd_from_libssl_read()`) and the saved again to `ssl_fd_map` using the `ssl` pointer num as key
- in `uprobe/SSL_Write` the FD is fetched from `ssl_fd_map` since `SSL_Read` and `SSL_Write` both have the same pointer to the `ssl` arg

**eBPF Probes**

Probe               | Python | Python TLS | Ruby | Ruby TLS | Go | Go TLS
--------------------|--------|------------|------|----------|----|-------
kprobe/accept4      | X      | X          | X    | X        | X  | X
kprobe/close        | X      | X          | X    | X        | X  | X
kprobe/sendto       | X      | .          | X    | .        | .  | .
kprobe/recvfrom     | X      | .          | X    | .        | .  | .
kprobe/write        | .      | .          | .    | .        | X  | .
kprobe/read         | .      | .          | .    | .        | X  | .
uprobe/SSL_read     | .      | .          | .    | X        | .  | .
uprobe/SSL_write    | .      | .          | .    | X        | .  | .
uprobe/SSL_write_ex | .      | X          | .    | .        | .  | .
uprobe/SSL_read_ex  | .      | X          | .    | .        | .  | .

**Trayce Agent Go Implementation**

The Trayce Agent repo follows a standard Go package layout, with the compiled binary entrypoint at `./cmd/trayce_agent/main.go`. The package at `./api` is used for the GRPC client which sends and receives data to the GUI. Some of the package in `./internal` are:
- `docker` - uses the docker client to get the containers running on this machine and which processes belong to them
- `ebpf` - sets up and runs the eBPF probes, it also receives events from eBPF and outputs them to a channel
- `events` - structs for the events sent from eBPF probes
- `sockets` - receives the events from the ebpf output channel and parses them into request/response Flows

**Container and PID tracking**

For each container that we are supposed to intercept, the PIDs belonging to that container are fetched using the docker client and sent to the eBPF probes over the `intercepted_pids` map. The eBPF probes check that map to make sure only the necessary processes are monitored.

Every time a new container is set to be intercepted, `internal/ebpf/stream.go` checks if there is an OpenSSL lib on the container, if there is then it attaches uprobes to it to intercept the SSL_*() calls.

Every time a new process on a container is open, `internal/ebpf/stream.go` attempts to attach uprobes to the Go `crypto/tls` function calls,  if it fails its probably not a Go binary.

