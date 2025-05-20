ifeq ($(OS),Windows_NT)
  EXECUTABLE_EXTENSION := .exe
else
  EXECUTABLE_EXTENSION :=
endif

GO_FILES = $(shell find . -type f -name '*.go')
TEST_MODULES ?= 

all: zgrab2

.PHONY: all clean integration-test integration-test-clean integration-test-run integration-test-build gofmt test

# Test currently only runs on the modules folder because some of the 
# third-party libraries in lib (e.g. http) are failing.
test:
	go test -v -failfast .
	cd lib/output/test && go test -v -failfast ./...
	cd modules && go test -v -failfast ./...

lint:
	gofmt -s -w $(shell find . -type f -name '*.go'| grep -v "/.template/")
	goimports -w -local "github.com/zmap/zgrab2" ./
	golangci-lint run
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
	make integration-test-clean

integration-test-build:
	@TEST_SERVICES=$$(docker compose -p zgrab -f integration_tests/docker-compose.yml config --services | grep -E "$$(echo $(TEST_MODULES) | sed 's/ /|/g')"); \
	if [ -n "$(TEST_MODULES)" ] && [ -z "$$TEST_SERVICES" ]; then \
		echo "Error: TEST_MODULES is set, but no matching services were found."; \
		exit 1; \
	fi; \
	echo "Filtered services: $$TEST_SERVICES"; \
	docker compose -p zgrab -f integration_tests/docker-compose.yml build --no-cache service_base; \
	docker compose -p zgrab -f integration_tests/docker-compose.yml build $$TEST_SERVICES; \
	docker compose -p zgrab -f integration_tests/docker-compose.yml up -d $$TEST_SERVICES

integration-test-run:
	rm -rf zgrab-output
	docker compose -p zgrab -f integration_tests/docker-compose.yml build runner
	TEST_MODULES="$(TEST_MODULES)" python3 integration_tests/test.py

integration-test-clean:
	rm -rf zgrab-output
	docker compose -p zgrab -f integration_tests/docker-compose.yml down

clean:
	cd cmd/zgrab2 && go clean
	rm -f zgrab2
