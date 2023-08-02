# Licensed under the Apache-2.0 license

#!/bin/bash
set -e
cd $(dirname "$0")
cd ..
cargo run -p caliptra-file-header-fix -- "$@"
