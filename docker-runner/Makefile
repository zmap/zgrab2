ifeq ($(OS),Windows_NT)
  EXECUTABLE_EXTENSION := .exe
else
  EXECUTABLE_EXTENSION :=
endif

all: docker-runner.id

.PHONY: clean clean-all base-apt-update

service-base-image.id: service-base.Dockerfile
	docker build -t zgrab2_service_base:latest -f service-base.Dockerfile -q . > service-base-image.id || (rm -f service-base-image.id && exit 1)

runner-base-image.id: runner-base.Dockerfile
	docker build -t zgrab2_runner_base:latest -f runner-base.Dockerfile -q . > runner-base-image.id || (rm -f runner-base-image.id && exit 1)

base-apt-update:
	IMAGE_ID=zgrab2_service_base:latest ./base-apt-update.sh
	IMAGE_ID=zgrab2_runner_base:latest ./base-apt-update.sh

docker-runner.id: Dockerfile ../cmd/zgrab2/zgrab2$(EXECUTABLE_EXTENSION) runner-base-image.id service-base-image.id
	docker build -t zgrab2_runner:latest -f Dockerfile -q .. > docker-runner.id || (rm -f docker-runner.id && exit 1)

clean:
	if [ -f docker-runner.id ]; then docker rmi -f $$(cat docker-runner.id) && rm -f docker-runner.id; fi
 
clean-all: clean
	if [ -f service-base-image.id ]; then docker rmi -f $$(cat service-base-image.id) && rm -f service-base-image.id; fi
	if [ -f runner-base-image.id ]; then docker rmi -f $$(cat runner-base-image.id) && rm -f runner-base-image.id; fi
