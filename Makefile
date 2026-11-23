PROJECT_DIR := $(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))
UNAME_S := $(shell uname -s)
UNAME_M := $(shell uname -m)

CONTAINER_ENGINE ?= podman
BUILD_OPTS ?=

MOUNTFLAGS = ro
ifeq ($(UNAME_S),Linux)
	MOUNTFLAGS := ro,z
endif

# RPM build settings (all overridable)
EL_VERSION ?= 9
BASE_IMAGE ?= docker.io/rockylinux/rockylinux
PYTHON_PKG ?= $(if $(filter 10,$(EL_VERSION)),python3,python3.12)
PLATFORM ?= $(if $(filter x86_64 amd64,$(UNAME_M)),linux/amd64,$(if $(filter aarch64 arm64,$(UNAME_M)),linux/arm64,linux/amd64))
RPM_VERSION ?= $(shell poetry version --short --no-ansi 2>/dev/null || git describe --tags --always 2>/dev/null | sed -e 's/^v//' -e 's/-/./g' || echo 0.0.0)
RPM_BUILDER_HASH ?= $(shell git hash-object $(PROJECT_DIR)/containers/rpm/Containerfile 2>/dev/null | cut -c1-12 || echo unknown)
RPM_BUILDER_IMAGE ?= tsd-file-api-rpm-builder:el$(EL_VERSION)-$(PYTHON_PKG)-$(RPM_BUILDER_HASH)
RPM_BUILDER_PULL ?=
RPM_SPEC ?= containers/rpm/tsdfileapi.spec

SRC_DIR ?= $(PROJECT_DIR)
OUT_DIR ?= $(PROJECT_DIR)/dist
SRC_MOUNT ?= /src
OUT_MOUNT ?= /out
CONTAINER_RPMBUILD_DIR ?= /root/rpmbuild
LOCAL_RPMBUILD_DIR ?= $(PROJECT_DIR)/build/rpmbuild
PIP_INDEX_URL ?=

.PHONY: build_test_container run tests
.PHONY: rpm rpm-all rpm-builder rpm-builder-build rpm-builder-pull rpm-builder-push rpm-local rpm-test-upgrade clean-rpm

build_test_container: # Build the test/development container image
	$(CONTAINER_ENGINE) build $(BUILD_OPTS) --file $(PROJECT_DIR)/containers/test/Dockerfile --tag tsd-file-api-test $(PROJECT_DIR)

run: build_test_container # Run development server
	$(CONTAINER_ENGINE) run --rm --replace --name tsd-file-api-test --publish 127.0.0.1:3003:3003 --volume $(PROJECT_DIR):/file-api:$(MOUNTFLAGS) tsd-file-api-test

tests: # Run tests against the development server
	$(CONTAINER_ENGINE) exec tsd-file-api-test python tsdfileapi/test_file_api.py

rpm-builder-build: # Build the RPM builder image
	$(CONTAINER_ENGINE) build $(BUILD_OPTS) \
		--platform $(PLATFORM) \
		--build-arg BASE_IMAGE=$(BASE_IMAGE) \
		--build-arg EL_VERSION=$(EL_VERSION) \
		--build-arg PYTHON_PKG=$(PYTHON_PKG) \
		--tag $(RPM_BUILDER_IMAGE) \
		--file $(PROJECT_DIR)/containers/rpm/Containerfile \
		$(PROJECT_DIR)

rpm-builder-pull: # Pull the RPM builder image from a registry
	$(CONTAINER_ENGINE) pull $(RPM_BUILDER_IMAGE)

rpm-builder: # Pull the builder image (optional), otherwise build it if missing
	@if [ -n "$(RPM_BUILDER_PULL)" ]; then $(CONTAINER_ENGINE) pull $(RPM_BUILDER_IMAGE) || true; fi
	@if ! $(CONTAINER_ENGINE) image inspect $(RPM_BUILDER_IMAGE) >/dev/null 2>&1; then $(MAKE) rpm-builder-build; fi

rpm-builder-push: rpm-builder # Push the RPM builder image to a registry
	$(CONTAINER_ENGINE) push $(RPM_BUILDER_IMAGE)

rpm: rpm-builder # Build an RPM in the builder container
	mkdir -p $(OUT_DIR)
	$(CONTAINER_ENGINE) run --rm \
		--platform $(PLATFORM) \
		--volume $(SRC_DIR):$(SRC_MOUNT):$(MOUNTFLAGS) \
		--volume $(OUT_DIR):$(OUT_MOUNT) \
		--env RPM_VERSION='$(RPM_VERSION)' \
		$(if $(PIP_INDEX_URL),--env PIP_INDEX_URL='$(PIP_INDEX_URL)',) \
		$(RPM_BUILDER_IMAGE) \
		sh -c 'set -e; \
			rpmbuild -bb \
				--define "_topdir $(CONTAINER_RPMBUILD_DIR)" \
				--define "pkg_version $$RPM_VERSION" \
				--define "python_pkg $(PYTHON_PKG)" \
				--define "src_dir $(SRC_MOUNT)" \
				$(SRC_MOUNT)/$(RPM_SPEC); \
			cp $(CONTAINER_RPMBUILD_DIR)/RPMS/*/*.rpm $(OUT_MOUNT)/'
	@echo "RPMs written to $(OUT_DIR)"

rpm-all: # Build RPMs for EL8, EL9 and EL10
	$(MAKE) rpm EL_VERSION=8
	$(MAKE) rpm EL_VERSION=9
	$(MAKE) rpm EL_VERSION=10

rpm-local: # Build an RPM on the host (requires rpm-build, Poetry and the Python toolchain)
	@command -v rpmbuild >/dev/null 2>&1 || { echo "rpmbuild not found; install rpm-build" >&2; exit 1; }
	@command -v poetry >/dev/null 2>&1 || { echo "poetry not found" >&2; exit 1; }
	@command -v $(PYTHON_PKG) >/dev/null 2>&1 || { echo "$(PYTHON_PKG) not found; install $(PYTHON_PKG)-devel" >&2; exit 1; }
	mkdir -p $(OUT_DIR) $(LOCAL_RPMBUILD_DIR)
	RPM_VERSION='$(RPM_VERSION)' POETRY_DYNAMIC_VERSIONING_BYPASS='$(RPM_VERSION)' $(if $(PIP_INDEX_URL),PIP_INDEX_URL='$(PIP_INDEX_URL)',) \
	rpmbuild -bb \
		--define "_topdir $(LOCAL_RPMBUILD_DIR)" \
		--define "pkg_version $(RPM_VERSION)" \
		--define "python_pkg $(PYTHON_PKG)" \
		--define "src_dir $(SRC_DIR)" \
		$(SRC_DIR)/$(RPM_SPEC)
	cp $(LOCAL_RPMBUILD_DIR)/RPMS/*/*.rpm $(OUT_DIR)/
	@echo "RPMs written to $(OUT_DIR)"

rpm-test-upgrade: # OLD_RPM=... NEW_RPM=... upgrade-test the new RPM over an old one
	@test -n "$(OLD_RPM)" || { echo "usage: make rpm-test-upgrade OLD_RPM=/path/old.rpm NEW_RPM=/path/new.rpm [EL_VERSION=8]" >&2; exit 1; }
	@test -n "$(NEW_RPM)" || { echo "usage: make rpm-test-upgrade OLD_RPM=/path/old.rpm NEW_RPM=/path/new.rpm [EL_VERSION=8]" >&2; exit 1; }
	CONTAINER_ENGINE='$(CONTAINER_ENGINE)' PLATFORM='$(PLATFORM)' EL_VERSION='$(EL_VERSION)' PYTHON_PKG='$(PYTHON_PKG)' BASE_IMAGE='$(BASE_IMAGE)' \
		$(PROJECT_DIR)/containers/rpm/test-upgrade.sh '$(OLD_RPM)' '$(NEW_RPM)'

clean-rpm: # Remove RPM build output
	rm -rf $(OUT_DIR) $(LOCAL_RPMBUILD_DIR)
