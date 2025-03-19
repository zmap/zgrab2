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
	make integration-test-build
	sleep 15  # Wait for services to start
	make integration-test-run
	# Shut off the services
	docker compose -p zgrab -f integration_tests/docker-compose.yml down
integration-test-build:
	docker compose -p zgrab -f integration_tests/docker-compose.yml build --no-cache service_base runner # ensure the apt cache is up to date and we've built the runner fresh
	# TEST_MODULES will specify the names of the ZGrab modules to run in the integration test
	# However, the containers are (usually) named module_name_version like smtp_1.0. So we need to do a fuzzy search
	# to see what containers to run.
	TEST_SERVICES=$$(docker compose -p zgrab -f integration_tests/docker-compose.yml config --services | grep -E "$$(echo $(TEST_MODULES) | sed 's/ /|/g')"); \
	if [ -n "$(TEST_MODULES)" ] && [ -z "$$TEST_SERVICES" ]; then \
		echo "Error: TEST_MODULES is set, but no matching services were found."; \
		exit 1; \
	fi; \
	docker compose -p zgrab -f integration_tests/docker-compose.yml build $$TEST_SERVICES; \
	docker compose -p zgrab -f integration_tests/docker-compose.yml up -d $$TEST_SERVICES;

integration-test-run:
	rm -rf zgrab-output
	TEST_MODULES="$(TEST_MODULES)" python3 integration_tests/test.py

integration-test-clean:
	rm -rf zgrab-output
	docker compose -p zgrab -f integration_tests/docker-compose.yml down

clean:
	cd cmd/zgrab2 && go clean
	rm -f zgrab2
