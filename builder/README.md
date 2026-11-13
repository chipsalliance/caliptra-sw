# image_gen

**Caliptra Firmware Image Builder**

`image_gen` is a command-line utility for building and customizing firmware image bundles for Caliptra.

## Building

Run `cargo build -p caliptra-builder --bin image` from the root repository directory. The binary will be created as `target/debug/image`.

### Hardware-targeted firmware builds

Select `CALIPTRA_HW_REV=2.1` for the frozen hardware bindings or
`CALIPTRA_HW_REV=latest` for the current development hardware (currently 2.2).
The ROM/FMC Makefiles default to `2.1`; explicit `latest` selection is supported.
Raw Cargo, builder and xtask invocations retain their existing `latest` fallback.
The literal value `2.2` is not a supported source-build selector. Select the
revision before invoking Cargo so host tests, firmware and the default hardware
model agree.

The builder's child Cargo invocations, `cargo xtask build`, and the ROM/FMC
Makefiles share `caliptra_builder::firmware_features`. This function preserves
requested features, adds `riscv` once, and includes the existing `default_features`
collector's RTL-dependent defaults for the selected firmware package. New
hardware-specific features belong in that collector, not a second feature table.
The collector currently enables no RTL-specific flags; this wiring does not
enable any new 2.2-specific behavior.

From the repository root, build and test each target in separate directories:

```sh
(
    set -e
    unset CALIPTRA_PREBUILT_FW_DIR CPTRA_CI_ROM_VERSION
    for rev in 2.1 latest; do
        export CALIPTRA_HW_REV="$rev"
        export CARGO_TARGET_DIR="$PWD/target-$rev"
        mkdir -p "out/$rev"
        cargo run --locked -p caliptra-builder -- \
            --rom-no-log "out/$rev/rom.bin" \
            --rom-with-log "out/$rev/rom-with-log.bin" \
            --fw "out/$rev/fw.bin"
        cargo test --locked
    done
)
```

The firmware bundle uses the builder's default development signing configuration.
For ROM, FMC, Runtime and driver-test ELFs, use `cargo xtask build all` under the
same environment. The test command runs the default emulator suite for the
selected hardware revision. To run it without packaging images:

```sh
CALIPTRA_HW_REV=2.1 CARGO_TARGET_DIR="$PWD/target-2.1" cargo test --locked
CALIPTRA_HW_REV=latest CARGO_TARGET_DIR="$PWD/target-latest" cargo test --locked
```

These commands select the hardware, not every optional Cargo feature. Feature
PRs must add their firmware defaults to the existing collector. Host-side tests gated
by `#[cfg(feature = "...")]` still require the corresponding Cargo `--features`
argument; the firmware resolver does not change the parent test build's features.

Prebuilt firmware directories must also be kept separate per hardware revision;
`CALIPTRA_PREBUILT_FW_DIR` bypasses firmware compilation. Do not change the
hardware selection within a running test/builder process. A different worktree
should use its own Cargo target directories.

For direct firmware Cargo commands, resolve features through the same policy:

```sh
features="$(cargo xtask build features --package caliptra-rom --features cfi)" &&
cargo build --locked -p caliptra-rom --bin caliptra-rom \
    --target riscv32imc-unknown-none-elf --profile firmware \
    --no-default-features --features "$features"
```

Raw Cargo commands that supply their own feature list do not consult the
resolver automatically. When using the standalone emulator, pass a matching
`--hw-version`; the ROM/FMC Makefiles do this automatically.

CI retains main's setup-driven hardware selection. PR runs use both `2.1` and
`latest`; manual workflow runs can choose `all`, `2.1`, or `latest`. Lint, builds,
workspace/emulator tests, ROM tests and integration tests use that selection.
Generic feature-policy and CLI tests run in the existing workspace test job;
no additional workflow step is needed. Feature-specific behavioral tests belong
to the PR that introduces the feature. This wiring does not change CI or the
separate release/nightly and Verilator workflow policies.

## Options

| Flag                    | Argument    | Description |
|-------------------------|-------------|-------------|
| `--fw`                  | `[FILE]`    | Firmware bundle image. |
| `--fw-svn`              | `[integer]` | Security Version Number of the firmware image. |
| `--all_elfs`            | `[DIR]`     | Directory to build all firmware ELF files. |
| `--fake-fw`             | `[FILE]`    | Fake firmware bundle image for testing. |
| `--hashes`              | `[FILE]`    | File path for output JSON file containing image bundle header hashes for external signing tools. |
| `--zeros`               |             | Build an image bundle with zeroed FMC and RT. This will NMI immediately. |
| `--owner-sig-override`  | `[FILE]`    | Manually overwrite the owner_sigs of the FW bundle image with the contents of binary [FILE]. The signature should be an ECC signature concatenated with an LMS signature. |
| `--vendor-sig-override` | `[FILE]`    | Manually overwrite the vendor_sigs of the FW bundle image with the contents of binary [FILE]. The signature should be an ECC signature concatenated with an LMS signature. |
| `--pqc-key-type`        | `[integer]` | PQC key type to use: `1` for MLDSA, `3` for LMS. (Default: 1) |
| `--image-options`       | `[FILE]`    | Override the `ImageOptions` struct for the image bundle with the given TOML file. |
