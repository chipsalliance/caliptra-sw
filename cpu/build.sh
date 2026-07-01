# Licensed under the Apache-2.0 license

#!/bin/bash

cd "$(dirname "${BASH_SOURCE[0]}")"

if [ -z $1 ]; then
    echo "Usage:"
    echo "./build.sh [revision]"
    echo "Where [revision] has to be one of the revisions under /hw (rev-latest, rev-2_1, ...)."
    exit 1
fi

cargo build \
  --target riscv32imc-unknown-none-elf \
  --features=riscv,$1 \
  --profile=firmware \
