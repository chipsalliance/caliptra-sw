# Licensed under the Apache-2.0 license

cd "$(dirname "${BASH_SOURCE[0]}")"

if [[ ! -f "../hw/latest/rtl/.git" || ! -f "../hw/1.0/rtl/.git" ]]; then
    echo "hw/*/rtl submodules are not populated"
    echo "Please run 'git submodule update --init'"
    exit 1
fi

cargo run --manifest-path bin/generator/Cargo.toml -- ../hw/1.0/rtl bin/extra-rdl/ ../hw/1.0/registers/src/
cargo run --manifest-path bin/generator/Cargo.toml -- ../hw/latest/rtl bin/extra-rdl/ ../hw/latest/registers/src/
