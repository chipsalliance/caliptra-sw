# Licensed under the Apache-2.0 license

#!/bin/bash
set -e

cd "$(dirname "${BASH_SOURCE[0]}")"

cargo build \
  --target riscv32imc-unknown-none-elf \
  --profile=firmware \
  --features emu,riscv

for i in "src/bin/"*".rs"; do
  basename="$(basename "$i")"
  filename="../../target/riscv32imc-unknown-none-elf/firmware/${basename%%_tests.*}"
  echo "$i"
  scripts/caliptra-test-runner.sh "${filename}"
done

