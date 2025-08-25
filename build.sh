#!/bin/bash

set -eux

mkdir -p /tmp/caliptra-test-firmware/caliptra-test-firmware

cargo run --release -p caliptra-builder -- --all_elfs /tmp/caliptra-test-firmware

rsync -avxz /tmp/caliptra-test-firmware ocp-host:/tmp/caliptra-test-firmware
