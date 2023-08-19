# Testing
 
## Running Docker python slim

```
cd test/docker_py
docker build -t app1 .
docker run -it app1:latest
```

## Running Docker debian slim

```
cd test/docker_deb
docker build -t appdeb .
docker run -it appdeb:latest
```

## Running Docker alpine

```
cd test/docker_alp
docker build -t test_alp .
docker run -it test_alp:latest
```