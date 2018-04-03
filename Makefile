ifeq ($(OS),Windows_NT)
  EXECUTABLE_EXTENSION := .exe
else
  EXECUTABLE_EXTENSION :=
endif

GO_FILES = $(shell find . -type f -name '*.go')
TEST_MODULES ?= 

all: zgrab2

.PHONY: all clean integration-test integration-test-clean docker-runner container-clean gofmt test

# Test currently only runs on the modules folder because some of the 
# third-party libraries in lib (e.g. http) are failing.
test:
	cd lib/output/test && go test -v ./...
	cd modules && go test -v ./...

gofmt:
	goimports -w -l $(GO_FILES)

zgrab2: $(GO_FILES)
	cd cmd/zgrab2 && go build && cd ../..
	rm -f zgrab2
	ln -s cmd/zgrab2/zgrab2$(EXECUTABLE_EXTENSION) zgrab2

docker-runner: zgrab2
	make -C docker-runner

integration-test: docker-runner
	rm -rf zgrab-output
	TEST_MODULES=$(TEST_MODULES) ./integration_tests/test.sh

integration-test-clean:
	rm -rf zgrab-output
	./integration_tests/cleanup.sh
	make -C docker-runner clean

# This is the target for re-building from source in the container
container-clean:
	rm -f zgrab2
	cd cmd/zgrab2 && go build -v -a . && cd ../..
	ln -s cmd/zgrab2/zgrab2$(EXECUTABLE_EXTENSION) zgrab2

clean:
	cd cmd/zgrab2 && go clean
	rm -f zgrab2
