ifeq ($(OS),Windows_NT)
  EXECUTABLE_EXTENSION := .exe
else
  EXECUTABLE_EXTENSION :=
endif

GO_FILES = $(shell find . -type f -name '*.go')
TEST_MODULES ?= 

all: zgrab2

.PHONY: all clean integration-test integration-test-clean gofmt test

# Test currently only runs on the modules folder because some of the 
# third-party libraries in lib (e.g. http) are failing.
test:
	cd lib/output/test && go test -v ./...
	cd modules && go test -v ./...

lint:
	gofmt -s -w $(shell find . -type f -name '*.go'| grep -v "/.template/")
	black .

zgrab2: $(GO_FILES)
	cd cmd/zgrab2 && go build && cd ../..
	rm -f zgrab2
	ln -s cmd/zgrab2/zgrab2$(EXECUTABLE_EXTENSION) zgrab2

integration-test:
	rm -rf zgrab-output
	docker compose -p zgrab -f integration_tests/docker-compose.yml build --no-cache service_base # ensure the apt cache is up to date
	docker compose -p zgrab -f integration_tests/docker-compose.yml build $(TEST_MODULES)
	docker compose -p zgrab -f integration_tests/docker-compose.yml up -d $(TEST_MODULES)
	sleep 10 # Wait for services to start
	TEST_MODULES="$(TEST_MODULES)" python3 integration_tests/test.py
	# Shut off the services
	docker compose -p zgrab -f integration_tests/docker-compose.yml down

integration-test-clean:
	rm -rf zgrab-output
	docker compose -p zgrab -f integration_tests/docker-compose.yml down

clean:
	cd cmd/zgrab2 && go clean
	rm -f zgrab2
