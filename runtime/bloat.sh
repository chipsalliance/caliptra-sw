# Licensed under the Apache-2.0 license

#!/bin/bash

cd "$(dirname "${BASH_SOURCE[0]}")"

cargo bloat \
  --locked \
  --target riscv32imc-unknown-none-elf \
  --profile=firmware \
  --no-default-features \
  --features=emu,fips_self_test,riscv \
  -p caliptra-runtime \
  -n 200 \
  # Uncomment this line to see code size by crate
  #--crates \
  --bin=caliptra-runtime
