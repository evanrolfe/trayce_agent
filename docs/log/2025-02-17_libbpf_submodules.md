# libbpf, libbpfgo & libbpf-bootstrap
In the `make install-libbpf` step we download these two repos:
- https://github.com/libbpf/libbpf-bootstrap
- https://github.com/aquasecurity/libbpfgo

Both have `libbpf` as a submodule, its best to let `libbpfgo` use its own `libbpf` submodule because it will use exactly the right version it requires. But its possible that `libbpfgo` and `libbpf-bootstrap` could have two separate versions of libbpf which might cause conflicts.

I have also checked out an older version of `libbpf-bootstrap` to avoid an error: 70de71d17613a25b7d43ce9a0ec649be1af1c4c9.
```
0.211 main.bpf.c:3:10: fatal error: vmlinux.h: No such file or directory
0.211     3 | #include <vmlinux.h>
0.211       |          ^~~~~~~~~~~
```

TODO: Figure out whats causing this and fix it.
