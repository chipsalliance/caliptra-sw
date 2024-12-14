#!/bin/bash
# Licensed under the Apache-2.0 license

cd "$(dirname "${BASH_SOURCE[0]}")"

if [[ ! -f "../hw/latest/rtl/.git" ]]; then
    echo "hw/*/rtl submodules are not populated"
    echo "Please run 'git submodule update --init'"
    exit 1
fi

cargo run --manifest-path bin/generator/Cargo.toml -- ../hw/latest/rtl bin/extra-rdl/ ../hw/latest/i3c-core-rtl ../hw/latest/registers/src/
