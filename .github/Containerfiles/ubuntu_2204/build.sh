#!/usr/bin/env bash
#
# Licensed under the Apache-2.0 license
#

set -e

cd /build
git clone https://github.com/chipsalliance/caliptra-sw \
    --config submodule.recurse=true \
    --recurse-submodules=dpe

cd caliptra-sw
./ci.sh check_frozen_images
