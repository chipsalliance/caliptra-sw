# Licensed under the Apache-2.0 license

#!/bin/bash

cd "$(dirname "${BASH_SOURCE[0]}")"

ARBITRARY_MAX_HANDLES=24 cargo build \
 --features arbitrary_max_handles \
  --locked \
  --target riscv32imc-unknown-none-elf \
  --profile=firmware \
  --no-default-features \
  --bin=caliptra-runtime
