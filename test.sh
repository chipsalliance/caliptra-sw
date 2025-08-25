
#!/bin/bash

set -eux
# ssh ocp-host -t '(cd caliptra-mcu-sw && tar -xvf ../caliptra-test-binaries.tar.zst)'

echo "Running tests"

# Clear old logs
ssh ocp-host -t '(sudo rm /tmp/junit.xml || true)'
ssh ocp-host -t '(cd caliptra-sw && \
    sudo CPTRA_MCU_ROM=/home/runner/mcu-rom-fpga.bin CPTRA_UIO_NUM=0 CALIPTRA_PREBUILT_FW_DIR=/tmp/caliptra-test-firmware/caliptra-test-firmware CALIPTRA_IMAGE_NO_GIT_REVISION=1 cargo-nextest nextest run \
      --workspace-remap=. \
      --archive-file $HOME/caliptra-test-binaries.tar.zst \
      -E "binary_id(caliptra-drivers::drivers_integration_tests) and test(test_ocp_lock)" \
      --test-threads=1 --no-fail-fast --profile=nightly)'
rsync ocp-host:/tmp/junit.xml .


