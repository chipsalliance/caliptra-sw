# Licensed under the Apache-2.0 license

#!/bin/bash
set -e

# Set current directory to script location
cd "${0%/*}"

# Tell caliptra-builder to make warnings errors
export GITHUB_ACTIONS=1

EXTRA_CARGO_CONFIG="target.'cfg(all())'.rustflags = [\"-Dwarnings\"]"

fw_dir="$(mktemp -d -t caliptra-fw.XXXXXXXXXXX)"
function cleanup() {
  rm -rf "${fw_dir}"
}
trap cleanup EXIT

mkdir -p target-ci

export CARGO_TARGET_DIR="${PWD}/target-ci"

cargo tree --locked > /dev/null || (
  echo "Please include required changes to Cargo.lock in your pull request"
  # Without the --locked flag, cargo will do the minimal possible update to Cargo.lock
  cargo tree > /dev/null 2> /dev/null
  # Print out the differences to ease debugging
  git diff Cargo.lock
  exit 1
)

echo Check source code formatting
cargo fmt --check --all

echo Clippy lint check
RUSTFLAGS="-Dwarnings" cargo clippy --locked --all-targets -- -D warnings

echo Check license headers 
cargo --config "${EXTRA_CARGO_CONFIG}" run -p caliptra-file-header-fix --locked -- --check

echo Build
cargo --config "${EXTRA_CARGO_CONFIG}" build --locked

echo Build firmware images
cargo --config "${EXTRA_CARGO_CONFIG}" run -p caliptra-builder  -- --all_elfs "${fw_dir}"

echo Run tests
if cargo nextest help > /dev/null 2>/dev/null; then
  CALIPTRA_PREBUILT_FW_DIR="${fw_dir}" cargo nextest run --config "${EXTRA_CARGO_CONFIG}" --locked
else
  CALIPTRA_PREBUILT_FW_DIR="${fw_dir}" cargo --config "${EXTRA_CARGO_CONFIG}" test --locked
fi
