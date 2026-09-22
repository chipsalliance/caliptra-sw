# Caliptra 2.x Branch Strategy Sample

This branch demonstrates building Caliptra 2.1 and 2.2 from one source tree.
The dedicated PCR quote signing-key change from PR #4064 is enabled only for
2.2.

## Version Selection

The production firmware crates expose mutually exclusive Cargo features named
`2.1` and `2.2`. Their normal default is `2.2`. Commands that use
`--no-default-features` must select a version explicitly.

Examples:

```text
cargo check -p caliptra-rom --no-default-features --features std,cfi,2.1
cargo check -p caliptra-rom --no-default-features --features std,cfi,2.2
```

`caliptra-builder` forwards its selected version to every ROM, FMC, Runtime,
and version-aware test-firmware Cargo invocation. It also adds a `--2.1` suffix
to cached 2.1 ELF names to prevent cross-version artifact reuse. Existing 2.2
artifact names remain unchanged.

The C API uses `CALIPTRA_VERSION_2_1` and `CALIPTRA_VERSION_2_2`. If neither is
defined, the header defaults to 2.2. Defining both is an error.

## Version Boundaries

The sample selects version-specific behavior at the narrowest practical
boundary:

* Complete generated FMC Alias certificate templates are selected per version.
  The 2.1 templates are under `x509/build/2_1`; the root templates are 2.2.
* Mailbox PCR quote response layouts omit the dedicated public keys in 2.1.
* 2.1 retains the FMC Alias signing keys in Key Vault slots 7 and 8. 2.2 uses
  dedicated PCR signing keys in slots 7 and 8 and moves FMC Alias keys to slots
  13 and 14.
* ROM persistent-data version 1.1 and its original layout are used for 2.1.
  Version 1.2 exposes the dedicated ECC PCR signing public key for 2.2 while
  preserving subsequent offsets.
* Dedicated-key derivation, certificate binding, reset locking, and quote-key
  persistence are compiled only for 2.2.

## Template Generation

Generate and test each certificate-template set independently:

```text
cargo run -p caliptra-x509-gen --no-default-features --features 2.1
cargo test -p caliptra-x509 --no-default-features --features std,2.1

cargo run -p caliptra-x509-gen --no-default-features --features 2.2
cargo test -p caliptra-x509 --no-default-features --features std,2.2
```

## Validation

At minimum, CI for this sample must compile ROM, FMC, Runtime, their integration
tests, and the public API in both configurations. Version-specific behavioral
tests must also run in the matching configuration; compiling a 2.1 host test
against 2.2 firmware is not a valid result.
