# Licensed under the Apache-2.0 license

CONTAINER_RUNTIME=docker
TIME_STAMP=$(shell date +%m-%d-%y-%H%M%S)
ARTIFACT_DIR=caliptra-artifacts

# this has to be set manually so that it can be pushed correctly
BASE_NAME="ghcr.io/leongross/caliptra-sw"
BASE_TAG="clptr-build-ubuntu"
BASE_FULL=$(BASE_NAME):$(BASE_TAG)

BUILD_NAME=$(BASE_NAME)
BUILD_TAG=clptr-build-runner
BUILD_FULL=$(BUILD_NAME):$(BUILD_TAG)
BUILD_CONTAINER_NAME=$(BUILD_TAG)-$(TIME_STAMP)

all: base build

base: Containerfile.base
	$(CONTAINER_RUNTIME) build -t $(BASE_FULL) -f $^ .
	$(CONTAINER_RUNTIME) push $(BASE_FULL)

build: Containerfile
	mkdir -p $(ARTIFACT_DIR)/$(TIME_STAMP)
	$(CONTAINER_RUNTIME) build -t $(BUILD_FULL) -f $^ .
	$(CONTAINER_RUNTIME) run --name $(BUILD_CONTAINER_NAME) -t $(BUILD_FULL) 
	$(CONTAINER_RUNTIME) cp $(BUILD_CONTAINER_NAME):/build/caliptra-sw/FROZEN_IMAGES.sha384sum $(ARTIFACT_DIR)/$(TIME_STAMP)
	
	# cd into there so we don't get diff errors due to different path names for easier parsing
	$(CONTAINER_RUNTIME) rm $(BUILD_CONTAINER_NAME)

clean:
	-rm -rf $(ARTIFACT_DIR)
	-$(CONTAINER_RUNTIME) rm $(BUILD_CONTAINER_NAME)
	-$(CONTAINER_RUNTIME) rm $(BASE_FULL)

.PHONEY: base build clean
