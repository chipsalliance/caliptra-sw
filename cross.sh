#!/bin/bash

set -eux

docker run --rm -v$PWD:/work-dir -w/work-dir -v$HOME/.cargo/registry:/root/.cargo/registry -v$HOME/.cargo/git:/root/.cargo/git fpga-tools:latest /bin/bash -c "(cd /work-dir && echo 'Cross compiling tests' && CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc cargo nextest archive --features=fpga_subsystem,itrng --target=aarch64-unknown-linux-gnu --archive-file=caliptra-test-binaries.tar.zst --target-dir cross-target/ )"

echo "Copying Caliptra test binaries"
rsync -avxz caliptra-test-binaries.tar.zst ocp-host:.

