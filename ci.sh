#!/bin/bash
#
# Licensed under the Apache-2.0 license

set -e

# Set current directory to script location
cd "${0%/*}"

ARGC=$#
ARGV=$@

WORK_DIR="$(mktemp -d)"
function cleanup() {
    rm -rf "${WORK_DIR}"
}
trap cleanup EXIT

function optional_task_enabled() {
    for i in "${ARGV[@]}"; do
        if [[ $i == $1 ]]; then
            return 0
        fi
    done
    return 1
}

function task_enabled() {
    if [ $ARGC -eq 0 ]; then 
      # If no arguments, run all the non-optional tasks
      return 0
    fi
    optional_task_enabled "$1"
}

FROZEN_IMAGE_FILE="${PWD}/FROZEN_IMAGES.sha384sum"

# Tell caliptra-builder to make warnings errors
export GITHUB_ACTIONS=1

EXTRA_CARGO_CONFIG="target.'cfg(all())'.rustflags = [\"-Dwarnings\"]"

fw_dir="${WORK_DIR}/fw"
mkdir -p "${fw_dir}"

cov_dir="${WORK_DIR}/cov"
mkdir -p "${cov_dir}"

mkdir -p target-ci

export CARGO_TARGET_DIR="${PWD}/target-ci"

function build_rom_images() {
    rm -rf "${CARGO_TARGET_DIR}/riscv32imc-unknown-none-elf"
    CALIPTRA_IMAGE_NO_GIT_REVISION=1 cargo --config "${EXTRA_CARGO_CONFIG}" run -p caliptra-builder \
        --features=hw-latest -- \
        --rom-with-log "${WORK_DIR}/caliptra-rom-with-log.bin"
    rm -rf "${CARGO_TARGET_DIR}/riscv32imc-unknown-none-elf"
    CALIPTRA_IMAGE_NO_GIT_REVISION=1 cargo --config "${EXTRA_CARGO_CONFIG}" run -p caliptra-builder \
        --features=hw-latest -- \
        --rom-no-log "${WORK_DIR}/caliptra-rom-no-log.bin"
}


if task_enabled "check_cargo_lock"; then
  cargo tree --locked > /dev/null || (
    echo "Please include required changes to Cargo.lock in your pull request"
    # Without the --locked flag, cargo will do the minimal possible update to Cargo.lock
    cargo tree > /dev/null 2> /dev/null
    # Print out the differences to ease debugging
    git diff Cargo.lock
    exit 1
  )
fi

if task_enabled "check_fmt"; then
  echo Check source code formatting
  cargo fmt --check --all
fi


if task_enabled "check_lint"; then
  echo Clippy lint check
  RUSTFLAGS="-Dwarnings" cargo clippy --locked --all-targets -- -D warnings
fi

if task_enabled "check_license"; then
  echo Check license headers
  cargo --config "${EXTRA_CARGO_CONFIG}" run -p caliptra-file-header-fix --locked -- --check
fi

if task_enabled "build"; then
  echo Build
  cargo --config "${EXTRA_CARGO_CONFIG}" build --locked
fi

if task_enabled "build_fw"; then
  echo Build firmware images
  cargo --config "${EXTRA_CARGO_CONFIG}" run -p caliptra-builder  -- --all_elfs "${fw_dir}"
fi

if task_enabled "test"; then
  echo Run tests
  if cargo nextest help > /dev/null 2>/dev/null; then
    CPTRA_COVERAGE_PATH="${cov_dir}" CALIPTRA_PREBUILT_FW_DIR="${fw_dir}" cargo nextest run --config "${EXTRA_CARGO_CONFIG}" --locked
  else
    CPTRA_COVERAGE_PATH="${cov_dir}" CALIPTRA_PREBUILT_FW_DIR="${fw_dir}" cargo --config "${EXTRA_CARGO_CONFIG}" test --locked
  fi
  CALIPTRA_PREBUILT_FW_DIR="${fw_dir}" CPTRA_COVERAGE_PATH="${cov_dir}" cargo --config "${EXTRA_CARGO_CONFIG}" run --manifest-path ./coverage/Cargo.toml
fi

if task_enabled "check_frozen_images"; then
    echo Checking frozen images
    build_rom_images
    (cd "${WORK_DIR}" && sha384sum -c "${FROZEN_IMAGE_FILE}") || (
        echo "The Caliptra ROM is frozen; changes that affect the binary"
        echo "require approval from the TAC."
        echo
        echo "If you have approval, run ./ci.sh update_frozen_images"
        false
    )
fi
if optional_task_enabled "update_frozen_images"; then
    echo "Updating frozen images"
    build_rom_images

    echo "# WARNING: Do not update this file without the approval of the Caliptra TAC" > "${FROZEN_IMAGE_FILE}"
    (cd "${WORK_DIR}" && sha384sum caliptra-rom-no-log.bin caliptra-rom-with-log.bin) >> "${FROZEN_IMAGE_FILE}"
fi
