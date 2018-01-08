ifeq ($(OS),Windows_NT)
  EXECUTABLE_EXTENSION := .exe
else
  EXECUTABLE_EXTENSION :=
endif

all: zgrab2

.PHONY: clean integration-test integration-test-clean docker-runner container-clean

zgrab2: 
	cd cmd/zgrab2 && go build && cd ../..
	ln -s cmd/zgrab2/zgrab2$(EXECUTABLE_EXTENSION) zgrab2
	# the docker-runner must be re-built
	make -C docker-runner clean

docker-runner: zgrab2
	make -C docker-runner

.integration-test-setup: | docker-runner
	./integration_tests/setup.sh
	touch .integration-test-setup

integration-test: docker-runner .integration-test-setup
	./integration_tests/test.sh

integration-test-clean:
	rm -f .integration-test-setup
	rm -rf zgrab-output
	./integration_tests/cleanup.sh
	make -C docker-runner clean

# This is the target for re-building from source in the container
container-clean:
	rm -f zgrab2
	cd cmd/zgrab2 && go build && cd ../..
	ln -s cmd/zgrab2/zgrab2$(EXECUTABLE_EXTENSION) zgrab2

clean:
	cd cmd/zgrab2 && go clean
	rm -f .integration-test-setup
	rm -f .docker-runner
	rm -f zgrab2
