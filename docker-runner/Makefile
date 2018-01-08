all: docker-runner.id

.PHONY: clean clean-all

service-base-image.id:
	docker build -t zgrab2_service_base:latest -f service-base.Dockerfile -q . > service-base-image.id || rm -f service-base-image.id

runner-base-image.id:
	docker build -t zgrab2_runner_base:latest -f runner-base.Dockerfile -q . > runner-base-image.id || rm -f runner-base-image.id

docker-runner.id: runner-base-image.id service-base-image.id
	docker build -t zgrab2_runner:latest -f Dockerfile -q .. > docker-runner.id || rm -f docker-runner.id

clean:
	if [ -f docker-runner.id ]; then docker rmi -f $$(cat docker-runner.id) && rm -f docker-runner.id; fi
 
clean-all: clean
	if [ -f service-base-image.id ]; then docker rmi -f $$(cat service-base-image.id) && rm -f service-base-image.id; fi
	if [ -f runner-base-image.id ]; then docker rmi -f $$(cat runner-base-image.id) && rm -f runner-base-image.id; fi
