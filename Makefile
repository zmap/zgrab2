all: zgrab2

.PHONY: clean zgrab2 integration_test integration_test_clean

zgrab2: 
	cd cmd/zgrab2 && go build

.integration_test_setup:
	./integration_tests/setup.sh
	touch .integration_test_setup

integration_test: .integration_test_setup
	./integration_tests/test.sh
	./integration_tests/cleanup.sh

integration_test_clean:
	rm test_setup
	./integration_tests/cleanup.sh
	# Wipe out any zgrab docker images so that they can be built fresh
	bash -c 'for id in `docker images --format "{{.Repository}},{{.ID}}" | grep "zgrab" | cut -d, -f 2`; do docker rmi $$id; done'

clean:
	cd cmd/zgrab2 && go clean
