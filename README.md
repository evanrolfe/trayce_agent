# TrayceAgent

TrayceAgent is a binary executable, packaged in a Docker container, which uses EBPF to monitor network requests between Docker containers and to external hosts.

### Build
1. Build executable binary:
```
docker build . --target build -t trayce_build 
docker run -v ./:/app -t trayce_build
```
2. Build and run the final distributable docker container:
```
docker build . --target production -t traycer/trayce_agent:0.0.1
```
3. [Optional] Publish the container:
```
docker push traycer/trayce_agent:0.0.1
```

### Run
Run the built container, replacing `-s` with the address of your GRPC server for receiving network flows (i.e. from TraceGUI).
```
docker run --pid=host --privileged -v /var/run/docker.sock:/var/run/docker.sock -it traycer/trayce_agent:0.0.1 -s 192.168.0.1:50051
```

### Develop
Run the bash on the build container with a volume so you can make changes, rebuild and run trayce_agent easily:
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
First ensure the mega server is server is running (see next section).

Run tests from within the build container:
```
make test
```

Run load tests (known issue the Go HTTP test cases send over a few duplicated flows):
```
make testload
```

Run unit tests:
```
make testunit
```

Generate mocks with `mockery` (`go install github.com/vektra/mockery/v2@v2.43.2`).

### MegaServer

Build and start:
```
docker build -t mega_server test/mega_server
docker run -v ./test/mega_server:/app -it mega_server
```
