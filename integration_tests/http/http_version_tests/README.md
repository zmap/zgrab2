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

## Tests
I didn't find out how to easily have docker-run.sh mount the ZGrab code Docker into a namespace where it can reach all the HTTP version test containers at once. I'm sure this is possible, but I've settled for manual testing for now.

### Test Setup
From integration_tests/http/http_version_tests run:
```shell
docker-compose up --build
```

In a separate terminal, from the main zgrab2 directory, run:
```shell
make
```

### HTTP/1.1 Test
#### Test Command
```shell
echo "localhost" | ./zgrab2 http --port=8081
```

#### Expected Behavior
 - Status Code: 200
 - Protocol: HTTP/1.1


### HTTP/2.0 over TLS Test
#### Test Command
```shell
echo "localhost" | ./zgrab2 http --port=8082 --use-https
```

#### Expected Behavior
- Status Code: 200
- Protocol: HTTP/2.0
