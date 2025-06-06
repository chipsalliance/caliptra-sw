#!/bin/bash
# Licensed under the Apache-2.0 license

cd "$(dirname "${BASH_SOURCE[0]}")"

cargo bloat \
  --locked \
  --target riscv32imc-unknown-none-elf \
  --profile=firmware \
  --no-default-features \
  --features=emu,fips_self_test,riscv \
  -p caliptra-runtime \
  -n 200 \
  --bin=caliptra-runtime
  # Uncomment this line to see code size by crate
  #--crates \
