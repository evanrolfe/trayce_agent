# Trayce Agent

**EBPF Probes:**

Probe                          | Python | Python TLS | Ruby | Ruby TLS | Go | Go TLS | Node | Node TLS | Java
-------------------------------|--------|------------|------|----------|----|--------|------|----------|-----
kprobe/connect                 | X      | X          | X    | X        | .  | .      | .    | .        | .
kprobe/close                   | X      | X          | X    | X        | .  | .      | .    | .        | .
kprobe/sendto                  | X      | .          | X    | .        | .  | .      | .    | .        | .
kprobe/recvfrom                | X      | .          | X    | .        | .  | .      | .    | .        | .
kprobe/write                   | .      | .          | .    | .        | .  | .      | .    | .        | .
kprobe/read                    | .      | .          | .    | .        | .  | .      | .    | .        | .
kprobe/security_socket_sendmsg | .      | .          | .    | .        | .  | .      | .    | .        | .
kprobe/security_socket_recvmsg | .      | .          | .    | .        | .  | .      | .    | .        | .
uprobe/SSL_read                | .      | .          | .    | X        | .  | .      | .    | .        | .
uprobe/SSL_write               | .      | .          | .    | X        | .  | .      | .    | .        | .
uprobe/SSL_write_ex            | .      | X          | .    | .        | .  | .      | .    | .        | .
uprobe/SSL_read_ex             | .      | X          | .    | .        | .  | .      | .    | .        | .
