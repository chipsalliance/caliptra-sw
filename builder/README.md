# image_gen

**Caliptra Firmware Image Builder**

`image_gen` is a command-line utility for building and customizing firmware image bundles for Caliptra.

## Building

Run `cargo build` from the `builder` directory. The binary will be created as `target/debug/image`.

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
