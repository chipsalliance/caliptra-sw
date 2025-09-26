# Caliptra bitstream downloader

A utility for downloading Caliptra bitstreams from a TOML manifest file.

## Usage

### Download latest core bitstream

``bash
$ # This example should be run from the `caliptra-sw` root directory.
$ cargo r --manifest-path ci-tools/bitstream-downloader/Cargo.toml -- --bitstream-manifest hw/fpga/bitstream_manifests/core.toml
```

## Future Work

Currently this tool is used in the FPGA CI to provision bitstreams to the CI FPGA. Eventually it will converted to a library and used by the `xtask` tool located in `caliptra-mcu-sw`.

