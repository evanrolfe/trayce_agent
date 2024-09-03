# Capturing short-lived requests

Initially the approach was to using the [docker container top](https://docs.docker.com/reference/cli/docker/container/top/) command via the Go client to fetch all the PIDs of processes running in our intercepted containers, then send those PIDs to ebpf using a `pids_map`. That worked fine for servers but did not work for short-lived requets i.e. from `curl`. It refreshed those PIDs every 5ms but even at that rate, a very short-lived request like curl to a server on the same network was too fast for that PID to be propogated to ebpf.

After learning about cgroups I realised that in each kprobe we can get the cgroup name and that contains the ID of the docker container. I wanted to do a straight-forward string comparision but that was a problem because on Mac the cgroups names are like: `docker-7d15edd8496d92281ba0cae75a3e96f1a5aafbf0ebd37ece0499f0ab2f8cacf6.scope` while on Linux they are just the ID: `7d15edd8496d92281ba0cae75a3e96f1a5aafbf0ebd37ece0499f0ab2f8cacf6`. Doing string operations in ebpf is hard, I managed to get a substring function working (code below) but that ran into problems with a for loop having too many code-pathways for the ebpf-verifier to accept.

In the end I opted use a simple hashing algorithm called [djb2](http://www.cse.yorku.ca/~oz/hash.html). So in Go it hashes the Mac & Linux cgroup names, then sets those two keys on the `cgroup_name_hashes` map to `1`. In ebpf it gets the cgroup name in the kprobes, djb2 hashes it, and then checks if that value is set on the `cgroup_name_hashes`. If its not then the kprobe returns 0.

```c
int i = 0, j = 0;
for (i = 0; i < CGROUP_LEN && cgroupname[i] != '\0'; i++) {
    if (cgroupname[i] == substr[0]) {
        // Check the rest of the substring
        for (j = 0; j < 12 && substr[j] != '\0'; j++) {
            // If characters don't match or main string ends, break
            if (i + j >= CGROUP_LEN || cgroupname[i + j] != substr[j]) {
                break;
            }
        }
        if (j == 12 && substr[j] == '\0') {
            bpf_printk("matched cgroup: %s", cgroupname);
            return 1;
        }
    }
}
```
