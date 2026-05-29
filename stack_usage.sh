#!/usr/bin/env bash
# Run the per-command runtime stack-usage measurement test and print only the
# resulting usage table.
set -euo pipefail

cd "$(dirname "$0")"

cargo test -p caliptra-runtime --test runtime_integration_tests \
    test_stack_usage::measure_runtime_command_stack_usage -- --nocapture 2>&1 |
    awk '/^Runtime command peak stack usage/{p=1} /^test /{p=0} p'
