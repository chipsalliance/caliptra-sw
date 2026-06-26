#!/usr/bin/env bash
# Licensed under the Apache-2.0 license

# Run the per-command runtime cycle-cost measurement test and print only the
# resulting cycle table.
set -euo pipefail

cd "$(dirname "$0")"

cargo test -p caliptra-runtime --test runtime_integration_tests \
    test_command_timing::measure_runtime_command_timing -- --nocapture 2>&1 |
    awk '/^Runtime command cycle cost/{p=1} /^test /{p=0} p'
