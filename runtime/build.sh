#!/bin/bash
# Licensed under the Apache-2.0 license

cd "$(dirname "${BASH_SOURCE[0]}")"

if [ -z $1 ]; then
    echo "Usage:"
    echo "./build.sh [revision]"
    echo "Where [revision] has to be one of the revisions under /hw (rev-latest, rev-2_1, ...)."
    exit 1
fi

cargo build \
  --locked \
  --target riscv32imc-unknown-none-elf \
  --profile=firmware \
  --no-default-features \
  --features riscv,cfi,$1 \
  --bin=caliptra-runtime
