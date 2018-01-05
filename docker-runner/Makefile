all: .docker-runner

.PHONY: clean clean-all

.base-image:
	./build-base.sh
	touch .base-image

.docker-runner: .base-image
	./build-runner.sh
	touch .docker-runner

clean:
	rm -f .docker-runner

clean-all: clean
	rm -f .base-image


