#!/bin/bash

# Licensed under the Apache-2.0 license

set -e

is_firmware="false"
for arg in "$@"; do
    if [[ ${last_arg} == "--target" ]] && [[ ${arg} == "riscv32imc-unknown-none-elf" ]]; then
      is_firmware="true"
    fi
    last_arg="${arg}"
done

if [[ $is_firmware == "false" ]]; then
  # Don't do anything special for non-firmware targets.
  exec "$@"
  exit $?
fi

# rustc accepts a "-C metadata=<DATA>" flag, which is use to feed entropy into the
# name mangling hash. This is useful in complex Rust software that imports
# multiple versions of the same crate, as the hash prevents symbol collisions.
# Unfortunately, Cargo mixes the identity of non-firmware dependencies like
# openssl used by build.rs into this hash.  There is no way to opt out other
# than rewriting the rustc arguments with a RUSTC_WRAPPER script (this
# solution), or using a build system other than Cargo.
#
# We can't allow the name mangling hash to change, as that can cause some
# symbols to be re-ordered by the linker when otherwise
# non-firmware-binary-affecting build-time deps like openssl are upgraded (for
# security fixes and whatnot).
#
# See https://doc.rust-lang.org/rustc/codegen-options/index.html#metadata for
# more information
args=()
for arg in "$@"; do
    if [[ ${#args[@]} -gt 0 ]] && [[ ${args[-1]} == "-C" ]] && [[ ${arg} == metadata=* ]]; then
        # Remove -C
        unset args[-1]
    else
        args+=("${arg}")
    fi
done

exec "${args[@]}"
