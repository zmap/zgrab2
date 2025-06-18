## HTTP Docker Tests

The goal of this effort was to provide test web servers that have strictly HTTP1 and HTTP2 behavior to test ZGrab's HTTP module.

## Running the containers
From this directory, run:
```shell
docker-compose up --build
```

Then from a separate terminal, run:
```shell
curl http://localhost:8081/index.html   
curl -k --http2 https://localhost:8082/index.html   
```