#!/bin/bash
# Licensed under the Apache-2.0 license

cd "$(dirname "${BASH_SOURCE[0]}")"

if [ -z $1 ]; then
    echo "Usage:"
    echo "./update.sh [revision]"
    echo "Where [revision] has to be one of the revisions under /hw (latest, rev-2_1, ...)."
    exit 1
fi

echo $"Updating /hw/$1/"

if [[ ! -f $"../hw/$1/rtl/.git" ]]; then
    echo "/hw/$1/rtl submodules are not populated"
    echo "Please run 'git submodule update --init'"
    exit 1
fi


cargo run --manifest-path bin/generator/Cargo.toml -- ../hw/$1/rtl bin/extra-rdl/ ../hw/$1/i3c-core-rtl ../hw/$1/caliptra-ss ../hw/$1/registers/src/
