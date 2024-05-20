ifeq ($(OS),Windows_NT)
  EXECUTABLE_EXTENSION := .exe
else
  EXECUTABLE_EXTENSION :=
endif

PROJ_ROOT := $(shell git rev-parse --show-toplevel)

all: docker-runner.id service-base-image.id

.PHONY: clean clean-all base-apt-update

service-base-image.id: service-base.Dockerfile
	docker build -t zgrab2_service_base:latest -f service-base.Dockerfile -q . > service-base-image.id || (rm -f service-base-image.id && exit 1)

base-apt-update:
	IMAGE_ID=zgrab2_service_base:latest ./base-apt-update.sh

docker-runner.id: $(PROJ_ROOT)/Dockerfile
	docker build -t zgrab2_runner:latest -f $(PROJ_ROOT)/Dockerfile -q $(PROJ_ROOT) > docker-runner.id || (rm -f docker-runner.id && exit 1)

clean:
	if [ -f docker-runner.id ]; then docker rmi -f $$(cat docker-runner.id) && rm -f docker-runner.id; fi
 
clean-all: clean
	if [ -f service-base-image.id ]; then docker rmi -f $$(cat service-base-image.id) && rm -f service-base-image.id; fi
