#!/bin/bash
# Licensed under the Apache-2.0 license

set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

if [[ $# -ne 1 ]]; then
    echo "Usage: registers/update.sh <revision>" >&2
    echo "Where <revision> is a hardware directory under hw (latest, rev-2_1, ...)." >&2
    exit 1
fi

revision="$1"
ss_dir="hw/$revision/caliptra-ss"
rtl_dir="$ss_dir/third_party/caliptra-rtl"
i3c_dir="$ss_dir/third_party/i3c-core"
dest_dir="hw/$revision/registers/src"

if [[ "$revision" == */* || ! -d "$dest_dir" ]]; then
    echo "Unsupported hardware revision: $revision" >&2
    exit 1
fi

echo "Updating $dest_dir from $ss_dir and its pinned dependencies"

if [[ ! -e "$ss_dir/.git" ]]; then
    git submodule update --init -- "$ss_dir"
fi
git -C "$ss_dir" submodule update --init --recursive

cargo run --locked --manifest-path registers/bin/generator/Cargo.toml -- \
    "$rtl_dir" registers/bin/extra-rdl "$i3c_dir" "$ss_dir" "$dest_dir"
