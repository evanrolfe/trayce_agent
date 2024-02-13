# TrayceAgent

### Build & Run
1. Build executable binary:
```
docker build . -t trayce_build -f Dockerfile.build
docker run -v ./:/app -t trayce_build
```
2. Build and run the final distributable docker container:
```
docker build . -t trayce_agent
docker run --pid=host --privileged -it trayce_agent -grpcaddr 192.168.0.1:50051
```
Replace `192.168.0.1:50051` with the address of your GRPC server for receiving network flows.

### Develop
Run the bash on the build container with a volume so you can make changes, rebuild and run trayce_agent easily:
```
docker run --pid=host --privileged -v ./:/app -v /var/run/docker.sock:/var/run/docker.sock -it trayce_build bash
```
Then from within the container run:
```
make
./trayce_agent
```

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

### MegaServer

Build and start:
```
docker build -t mega_server test/mega_server
docker run -v ./test/mega_server:/app -it mega_server
```
