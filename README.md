
# Caliptra Firmware/Software

This repository contains firmware, libraries, and tools related to the
[Caliptra Project](https://github.com/chipsalliance/caliptra).

## [fmc](/fmc/)

"First Mutable Code", the code that the boot ROM measures and jumps to after
validation succeeds.

## [hw-model](/hw-model/)

A high-level testing library for instantiating and manipulating models of the
hardware. Intended to target multiple backends, including sw-emulator,
verilator, and (hopefully) a future FPGA implementation.

## [sw-emulator](/sw-emulator/)

Fast software-based simulation of the Caliptra hardware. This is the fastest and
easiest way to test changes to firmware, but fidelity may not be perfect.

## [drivers](/drivers/)

A rust library containing drivers for the Caliptra hardware, intended to be
used by firmware running on Caliptra's RISC-V cpu.

# Building / Testing

To build Caliptra firmware or tools, you need a Linux installation with a recent
Rust toolchain. See [Getting started with
Rust](https://www.rust-lang.org/learn/get-started) for more information on
installing an up-to-date Rust toolchain.

## Build and test

```
$ git clone https://github.com/chipsalliance/caliptra-sw --config submodule.recurse=true
$ cd caliptra-sw
$ cargo build
$ cargo test
```

## Testing firmware images with sw-emulator

```
$ cargo install --path sw-emulator/app
$ drivers/test-fw/test.sh
```