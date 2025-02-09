# Source & Destination Address Order

**Problem:** the source & destination addresses were sometimes being sent in the wrong order, here is an example of what it looked like:
TrayceAgent: 172.20.0.4
MegaServer: 172.20.0.3
```
[DataEvent]  163 bytes, source: kprobe/recvfrom , PID: 2833553 , TID: 2861587 FD: 4 , cgroup: docker-1e8e87df0dd18b808f0922dd73ed61cbf41c789b6c53546af2365346300c2567.scope
 172.20.0.3:3001->172.20.0.4:49142
00000000  47 45 54 20 2f 73 65 63  6f 6e 64 5f 68 74 74 70  |GET /second_http|
00000010  20 48 54 54 50 2f 31 2e  31 0d 0a 48 6f 73 74 3a  | HTTP/1.1..Host:|
00000020  20 31 37 32 2e 32 30 2e  30 2e 33 3a 33 30 30 31  | 172.20.0.3:3001|
00000030  0d 0a 55 73 65 72 2d 41  67 65 6e 74 3a 20 47 6f  |..User-Agent: Go|
00000040  2d 68 74 74 70 2d 63 6c  69 65 6e 74 2f 31 2e 31  |-http-client/1.1|
00000050  0d 0a 41 63 63 65 70 74  2d 45 6e 63 6f 64 69 6e  |..Accept-Encodin|
00000060  67 3a 20 69 64 65 6e 74  69 74 79 0d 0a 58 2d 52  |g: identity..X-R|
00000070  65 71 75 65 73 74 2d 49  64 3a 20 33 31 32 61 66  |equest-Id: 312af|

[DataEvent]  141 bytes, source: kprobe/sendto , PID: 2833553 , TID: 2861587 FD: 5 , cgroup: docker-1e8e87df0dd18b808f0922dd73ed61cbf41c789b6c53546af2365346300c2567.scope
 172.20.0.3:57366->172.67.155.78:80
00000000  47 45 54 20 2f 20 48 54  54 50 2f 31 2e 31 0d 0a  |GET / HTTP/1.1..|
00000010  48 6f 73 74 3a 20 74 72  61 79 63 65 2e 64 65 76  |Host: trayce.dev|
00000020  0d 0a 55 73 65 72 2d 41  67 65 6e 74 3a 20 70 79  |..User-Agent: py|
00000030  74 68 6f 6e 2d 72 65 71  75 65 73 74 73 2f 32 2e  |thon-requests/2.|
00000040  33 32 2e 33 0d 0a 41 63  63 65 70 74 2d 45 6e 63  |32.3..Accept-Enc|
00000050  6f 64 69 6e 67 3a 20 67  7a 69 70 2c 20 64 65 66  |oding: gzip, def|
00000060  6c 61 74 65 0d 0a 41 63  63 65 70 74 3a 20 2a 2f  |late..Accept: */|
00000070  2a 0d 0a 43 6f 6e 6e 65  63 74 69 6f 6e 3a 20 6b  |*..Connection: k|

[DataEvent]  3714 bytes, source: kprobe/recvfrom , PID: 2833553 , TID: 2861587 FD: 5 , cgroup: docker-1e8e87df0dd18b808f0922dd73ed61cbf41c789b6c53546af2365346300c2567.scope
 172.20.0.3:57366->172.67.155.78:80
00000000  48 54 54 50 2f 31 2e 31  20 32 30 30 20 4f 4b 0d  |HTTP/1.1 200 OK.|
00000010  0a 44 61 74 65 3a 20 53  75 6e 2c 20 30 39 20 46  |.Date: Sun, 09 F|
00000020  65 62 20 32 30 32 35 20  30 39 3a 34 30 3a 32 37  |eb 2025 09:40:27|
00000030  20 47 4d 54 0d 0a 43 6f  6e 74 65 6e 74 2d 54 79  | GMT..Content-Ty|
00000040  70 65 3a 20 74 65 78 74  2f 68 74 6d 6c 3b 20 63  |pe: text/html; c|
00000050  68 61 72 73 65 74 3d 75  74 66 2d 38 0d 0a 54 72  |harset=utf-8..Tr|
00000060  61 6e 73 66 65 72 2d 45  6e 63 6f 64 69 6e 67 3a  |ansfer-Encoding:|
00000070  20 63 68 75 6e 6b 65 64  0d 0a 43 6f 6e 6e 65 63  | chunked..Connec|

[DataEvent]  174 bytes, source: kprobe/sendto , PID: 2833553 , TID: 2861587 FD: 4 , cgroup: docker-1e8e87df0dd18b808f0922dd73ed61cbf41c789b6c53546af2365346300c2567.scope
 172.20.0.3:3001->172.20.0.4:49142
00000000  48 54 54 50 2f 31 2e 31  20 32 30 30 20 4f 4b 0d  |HTTP/1.1 200 OK.|
00000010  0a 53 65 72 76 65 72 3a  20 57 65 72 6b 7a 65 75  |.Server: Werkzeu|
00000020  67 2f 33 2e 31 2e 33 20  50 79 74 68 6f 6e 2f 33  |g/3.1.3 Python/3|
00000030  2e 31 30 2e 31 32 0d 0a  44 61 74 65 3a 20 53 75  |.10.12..Date: Su|
00000040  6e 2c 20 30 39 20 46 65  62 20 32 30 32 35 20 30  |n, 09 Feb 2025 0|
00000050  39 3a 34 30 3a 32 37 20  47 4d 54 0d 0a 43 6f 6e  |9:40:27 GMT..Con|
00000060  74 65 6e 74 2d 54 79 70  65 3a 20 74 65 78 74 2f  |tent-Type: text/|
00000070  68 74 6d 6c 3b 20 63 68  61 72 73 65 74 3d 75 74  |html; charset=ut|
```

**Solution:**
Looking at this output, it's clear that for ingress traffic it was the wrong way around, but for egress traffic it was correct. So in the eBPF code, I added a BPF map called socket_map which tracks the sockets and whether they are egress or ingress. The key used is source address + destination address + container ID hash. This is necessary because the same traffic can be monitored twice if a request goes from one container to another and you are intercepting both containers.
I also updated the SocketMap in Go to use that same key instead of PID+FD. It works better because the PID and FD can be volatile, i.e., in databases where the process is often forked for new queries.


