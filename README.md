
# Caliptra firmware and software

This repository contains firmware, libraries, and tools related to the
[Caliptra Project](https://github.com/chipsalliance/caliptra).

## Documentation

- [Caliptra ROM Module Specification](/rom/dev/README.md)
- [Caliptra FMC Module Specification](/fmc/README.md)
- [Caliptra Runtime Module Specification](/runtime/README.md)
- [libcaliptra Guide](/libcaliptra/README.md)
- [Caliptra GitHub GCP Runner Infrastructure](/ci-tools/github-runner/README.md)

## Directory structure

### [api](/api)

Definitions for the Caliptra mailbox and other basic firmware interfaces.

### [builder](/builder)

Tool for building the Caliptra firmware bundle.

### [cfi](/cfi)

Library containing Control-Flow Integrity attack countermeasure implementations.

### [ci-tools](/ci-tools)

Various tools used for Continuous Integration flows.

### [common](/common)

Common code shared across multiple other code modules.

### [coverage](/coverage)

Tool for collecting code coverage metrics from Caliptra tests.

### [cpu](/cpu)

Implementations of CPU-specific features such as NMI and Trap handlers.

### [dpe](/dpe)

DICE Protection Environment submodule (reference to its own repository).

### [drivers](/drivers)

A rust library containing drivers for the Caliptra hardware, intended to be
used by firmware running on Caliptra's RISC-V CPU.

### [error](/error)

Comprehensive list of all Caliptra error codes.

### [fmc](/fmc/)

"First Mutable Code", the code that the boot ROM measures and jumps to after
validation succeeds.

## [hw](/hw/)

Caliptra RTL submodule location and implementations of RTL based test environments for [verilator](/hw/verilated/README.md) and [fpga](/hw/fpga/README.md).

## [hw-model](/hw-model/)

A high-level testing library for instantiating and manipulating models of the
hardware. Intended to target multiple backends, including sw-emulator,
verilator, and FPGA.

### [image](/image)

Libraries for generating and verifying Caliptra firmware images.

### [kat](/kat)

Known Answer Tests for all cryptographic operations supported by Caliptra.

### [libcaliptra](/libcaliptra)

C-API library and example code for accessing Caliptra from its external interfaces.

### [lms-types](/lms-types)

Type definitions for the Leighton-Micali Hash-Based Signatures algorithm.

### [registers](/registers)

Register definitions for the caliptra hardware peripherals, generated from the RDL
files in the `caliptra-rtl` repo.

### [rom](/rom/dev)

"Read Only Memory", the code that is first executed when the chip is powered on.
Normally the ROM is part of the silicon.

### [runtime](/runtime)

Caliptra runtime environment that is responsible for all Caliptra functionality
after the boot process. This module is jumped to from FMC.

### [sw-emulator](/sw-emulator/)

Fast software-based simulation of the Caliptra hardware. This is the fastest and
easiest way to test changes to firmware, but fidelity may not be perfect.

### [systemrdl](/systemrdl)

RDL parser used in the creation of register definitions.

### [test](/test)

Test suites for various portions of the Caliptra implementation.

### [test-harness](/test-harness)

A library for building self-contained test firmware binaries. This sets up minimal infrastructure for panic-handling and provides macros for defining test cases in firmware.

### [ureg](/ureg)

Register abstraction and code generator to create register libraries. The `registers` directory has a binary that creates the register code that includes ureg.

### [x509](/x509)

Code used to build and verify the various X509-formatted certificates produced
by Caliptra.

## Building / Testing

To build Caliptra firmware or tools, you need a Linux installation with a recent
Rust toolchain. See [Getting started with
Rust](https://www.rust-lang.org/learn/get-started) for more information on
installing an up-to-date Rust toolchain. We use version 1.70 of the Rust
toolchain for all continuous integration.

### Checkout and build

```shell
git clone https://github.com/chipsalliance/caliptra-sw \
    --config submodule.recurse=true \
    --recurse-submodules=dpe
cd caliptra-sw
cargo build
```

### Testing in a hurry

To run all unit tests on the host CPU, and run all integration tests against the
sw-emulator:

```shell
# (from caliptra-sw/)
cargo test
```

To run a single emulator test:

```shell
cargo test -p caliptra-drivers test_doe
```

You may wish to get a primitive trace from the sw-emulator while running the
test:

```console
$ CPTRA_TRACE_PATH=/tmp/trace.txt cargo test -p caliptra-drivers test_doe
$ cat /tmp/trace.txt
<snip>
pc=0xf6
pc=0xf8
UC write4 *0x50002290 <- 0xffffffff
pc=0xfa
pc=0xb2
pc=0xb6
UC read1 *0x500022b5 -> 0xff
pc=0xba
<snip>
```

### Testing against Verilator

We use [Verilator](https://www.veripool.org/verilator/) to provides a
high-fidelity simulation based on
[Caliptra's RTL](https://github.com/chipsalliance/caliptra-sw). Running tests in
this environment can reveal bugs in the firmware, hardware, and the integration
between the two.

If you don't have verilator 5.004 or later installed, follow [these directions](/hw/verilated).

To run all the tests in verilator (this will take several hours):

```shell
cargo test --features=verilator --release
```

Sometimes you may only want to run a single test, like this
[pcrbank driver test](/drivers/test-fw/src/bin/pcrbank_tests.rs)
(hosted by the [driver integration tests](/drivers/tests/integration_tests.rs))
that can run in seconds:

```shell
cargo test --features=verilator -p caliptra-drivers test_pcrbank
```

To get a VCD dump of ALL waveforms while running the test:

```shell
CPTRA_TRACE_PATH=/tmp/trace.vcd cargo test --features=verilator -p caliptra-drivers test_pcrbank
```

You can open the vcd file with a tool like
[GTKWave](https://gtkwave.sourceforge.net/) to debug the hardware/firmware.

## Testing against FPGA

FPGA provides a fast environment for development with Caliptra RTL.
FPGA build directions and further details are available in
[this README](/hw/fpga/README.md)

Download caliptra-fpga-bitstream from the
[latest fpga builds of main](https://github.com/chipsalliance/caliptra-sw/actions/workflows/fpga.yml?query=branch%3Amain)

Load the FPGA image and run a test:

```shell
sudo ./hw/fpga/setup_fpga.sh caliptra_fpga.bin

CPTRA_UIO_NUM=4 cargo test --features=fpga_realtime,itrng -p caliptra-test smoke_test::smoke_test
```
