PROJECT_DIR := $(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))

CONTAINER_ENGINE ?= podman
BUILD_OPTS ?=

MOUNTFLAGS = ro
ifeq ($(UNAME_S),Linux)
	MOUNTFLAGS += ,z
endif

.PHONY: build_test_container run tests

build_test_container: # Build the test/development container image
	$(CONTAINER_ENGINE) build $(BUILD_OPTS) --file $(PROJECT_DIR)/containers/test/Dockerfile --tag tsd-file-api-test $(PROJECT_DIR)

run: build_test_container # Run development server
	$(CONTAINER_ENGINE) run --rm --replace --name tsd-file-api-test --publish 127.0.0.1:3003:3003 --volume $(PROJECT_DIR):/file-api:$(MOUNTFLAGS) tsd-file-api-test

tests: # Run tests against the development server
	$(CONTAINER_ENGINE) exec tsd-file-api-test python tsdfileapi/test_file_api.py
