ifeq ($(OS),Windows_NT)
  EXECUTABLE_EXTENSION := .exe
else
  EXECUTABLE_EXTENSION :=
endif

GO_FILES = $(shell find . -type f -name '*.go')
TEST_MODULES ?=
.DEFAULT_GOAL := zgrab2

all: zgrab2

.PHONY: all clean integration-test integration-test-clean integration-test-run integration-test-build gofmt test install uninstall

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

zgrab2: $(GO_FILES) setup-config
	cd cmd/zgrab2 && go build && cd ../..
	rm -f zgrab2
	ln -s cmd/zgrab2/zgrab2$(EXECUTABLE_EXTENSION) zgrab2

install: setup-config
	cd cmd/zgrab2 && go install && cd ../..

CONFIG_DIR=$(HOME)/.config/zgrab2
uninstall:
	@echo "This will remove the zgrab2 configuration directory at $(CONFIG_DIR) and the zgrab2 binary."
	@read -p "Do you wish to continue? (y/N): " choice; \
	if [[ $$choice != [yY] ]]; then \
		echo "Uninstallation aborted"; \
		exit 0; \
	else \
		echo "Removing zgrab2 configuration directory at $(CONFIG_DIR) and the zgrab2 binary."; \
		rm -rf $(CONFIG_DIR); \
		rm -f $(shell which zgrab2); \
	fi

setup-config:
	@echo "Setting up zgrab2 configuration directory at $(CONFIG_DIR)"
# Make sure the config directory exists
	mkdir -p $(CONFIG_DIR)
# Copy the default config file if it doesn't exist
	cp -n ./conf/blocklist.conf $(CONFIG_DIR)/blocklist.conf || true



integration-test:
	make integration-test-build
# Wait for services to start
	sleep 15
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
