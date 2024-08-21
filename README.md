# TrayceAgent
[![CircleCI](https://dl.circleci.com/status-badge/img/circleci/3buPB9tzLBfg8maGYBUAcy/MsH4GqtpozYgoKLx8htMUW/tree/main.svg?style=shield)](https://dl.circleci.com/status-badge/redirect/circleci/3buPB9tzLBfg8maGYBUAcy/MsH4GqtpozYgoKLx8htMUW/tree/main)  ![](https://img.shields.io/badge/Go-1.23-blue)  [![ebpf.io](https://img.shields.io/badge/ebpf-yellow)](https://ebpf.io/) [![trayce.dev](https://img.shields.io/badge/Website-orange)](https://trayce.dev/)

TrayceAgent is a binary executable, packaged in a Docker container, which uses EBPF to monitor network requests between Docker containers and to external hosts. It can be used along with the [TrayceGUI](https://github.com/evanrolfe/trayce_gui/) to inspect traffic.

Read the [docs](https://github.com/evanrolfe/trayce_agent/tree/main/docs) for implementation details.

### Build

1. Build an image for local-use (only) with:
```
docker build -t trayce_agent:local .
```

2. Run the built container, replacing `-s` with the address of your GRPC server for receiving network flows (i.e. from TraceGUI).
```
docker run --pid=host --privileged -v /var/run/docker.sock:/var/run/docker.sock -it trayce_agent:local -s 192.168.0.1:50051
```

### Develop
Run the bash on the build container with a volume so you can make changes, rebuild and run trayce_agent easily. First comment out the final build stage of the Dockerfile, then build it to `trayce_agent:local` and run:
```
make dev
```
Then from within the container run:
```
make
./trayce_agent -s 192.168.0.20:50051
```
(You must have a GRPC server running at 192.168.0.20:50051, you can do that by starting the GUI).

### Test
First ensure the mega server is server is running:
```
docker build -t mega_server test/mega_server
make megaserver
```

Run tests from within the build container (from the "Develop" step):
```
make test
```

Run load tests:
```
make testload
```

Run unit tests:
```
make testunit
```

Generate mocks with `mockery` (`go install github.com/vektra/mockery/v2@v2.43.2`).
