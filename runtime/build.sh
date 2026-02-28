#!/bin/bash
# Licensed under the Apache-2.0 license

cd "$(dirname "${BASH_SOURCE[0]}")"

cargo build \
  --locked \
  --target riscv32imc-unknown-none-elf \
  --profile=firmware \
  --no-default-features \
  --features riscv,cfi \
  --bin=caliptra-runtime
