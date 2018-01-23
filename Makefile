ifeq ($(OS),Windows_NT)
  EXECUTABLE_EXTENSION := .exe
else
  EXECUTABLE_EXTENSION :=
endif

GO_FILES = $(shell find . -type f -name '*.go')

all: zgrab2

.PHONY: all clean integration-test integration-test-clean docker-runner container-clean gofmt

gofmt:
	goimports -w -l $(GO_FILES)

zgrab2: $(GO_FILES)
	cd cmd/zgrab2 && go build && cd ../..
	rm -f zgrab2
	ln -s cmd/zgrab2/zgrab2$(EXECUTABLE_EXTENSION) zgrab2

docker-runner: zgrab2
	make -C docker-runner

.integration-test-setup: | docker-runner
	./integration_tests/setup.sh
	touch .integration-test-setup

integration-test: docker-runner .integration-test-setup
	rm -rf zgrab-output
	./integration_tests/test.sh

integration-test-clean:
	rm -f .integration-test-setup
	rm -rf zgrab-output
	./integration_tests/cleanup.sh
	make -C docker-runner clean

# This is the target for re-building from source in the container
container-clean:
	rm -f zgrab2
	cd cmd/zgrab2 && go build -v -a && cd ../..
	ln -s cmd/zgrab2/zgrab2$(EXECUTABLE_EXTENSION) zgrab2

clean:
	cd cmd/zgrab2 && go clean
	rm -f .integration-test-setup
	rm -f zgrab2
