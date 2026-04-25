
# Caliptra firmware and software

This repository contains firmware, libraries, and tools related to the
[Caliptra Project](https://github.com/chipsalliance/caliptra).

## Documentation

- [Caliptra ROM Module Specification](/rom/dev/README.md)
- [Caliptra FMC Module Specification](/fmc/README.md)
- [Caliptra Runtime Module Specification](/runtime/README.md)
- [libcaliptra Guide](/libcaliptra/README.md)
- [Caliptra GitHub GCP Runner Infrastructure](/ci-tools/github-runner/README.md)

## Release history

The tables below list all official ROM and FMC+Runtime firmware releases. For
ROM releases the SHA256 is the digest embedded inside each ROM binary (it
covers all ROM bytes before the `RomInfo` struct, using the builder's
word-reversed hashing convention), and the SHA384 is computed over the entire
raw ROM binary. Both the no-log (`caliptra-rom.bin`) and with-log
(`caliptra-rom-with-log.bin`) variants are included. For FW releases the
SHA384 hashes are the digests stored inside the firmware image manifest's TOC
entries for the FMC and Runtime images — they are **not** hashes of the
firmware bundle file itself. The `rom-1.0.3` entry was built from source
because its GitHub release does not contain pre-built binary artifacts. The
`RTL` column indicates which [caliptra-rtl](https://github.com/chipsalliance/caliptra-rtl)
release(s) each ROM or firmware binary is known to be compatible with.

These tables can be regenerated or extended by running:

```shell
cargo xtask release info --markdown --build
```

### ROM Releases

| Version | RTL | SHA256 (no log) | SHA256 (with log) | SHA384 (no log) | SHA384 (with log) | Git Commit | SVN |
|---------|-----|-----------------|--------------------|-----------------|--------------------|------------|-----|
| [rom-1.0.0](https://github.com/chipsalliance/caliptra-sw/releases/tag/rom-1.0.0) | 1.0 | `6bbe42fcda193d19b371ba39d41f515bbb06d1e7381b2aa8f41057cb27d6e286` | `60f31e3c65577e5dbaac05bd5d754ab927af05557844bebb3affbca88d59b483` | `73bf24f7285b08137e03a8d6dbaca3bf03f8651eb319c4409ac8767be62fd90724aa8545261a4994d93c21f5ab1a904a` | `70348fa78230ebff9cffbc98c120d22f876b7cd41f630bbf740e7f0e99aeb7676a37699889c35ef3842c5622d3287f80` | [`e61eb66`](https://github.com/chipsalliance/caliptra-sw/commit/e61eb66bfcd42e56438c1548272c7b568ce9f8d0) | 0 |
| [rom-1.0.1](https://github.com/chipsalliance/caliptra-sw/releases/tag/rom-1.0.1) | 1.0 | `5c509ab7299c20e10cb2c4d32341f039ed77fa29ce36e8baeafa0c79feef4642` | `67e538ca65e0c690e8c3f955c3f19a052c8ea347ddb90a6cbf226e73f1c8e4fc` | `b364341552d08e63b3294914a319e697cf8b8b937604bcd28bc3e15bd6e32315cd403ba69f064bfd3c447baad012864e` | `4da8decde59f3bebd8d7a31db7c8d7f4596da29ea0db44dcbf3848430d57b1155c8da3e6b1a9d9ab08391c89c4351799` | [`9342687`](https://github.com/chipsalliance/caliptra-sw/commit/9342687085d98201ea8b1e62cae6fdf6e0b816d9) | 0 |
| [rom-1.0.2](https://github.com/chipsalliance/caliptra-sw/releases/tag/release_v20240522_1) | 1.0 | `604dd02bba786bba5d9e7284bcd99f42d314ccb5d3b9ff080aca7477b2d5bcb7` | `f69d4fba7f1bdbc2cbd3682f807e0d144ad227a0eaf0afd455f7d6931453a10c` | `7b3b83b569a5a4e1fc6f49be988aa5ac49ed579ad166708c022b330e6bbc02bcb19067debbe3bb944a3e9a5441794817` | `f51fdcf0fc460f005f37e908229851fd1fd3dfc21d54ad6fdab132844974a4264a4524b75bb82ab039e0b52b55768630` | [`30887b7`](https://github.com/chipsalliance/caliptra-sw/commit/30887b76d9e315022448eb9fd734779d63901d6b) | 0 |
| [rom-1.0.3](https://github.com/chipsalliance/caliptra-sw/releases/tag/rom-1.0.3) | 1.0 | `6d02fb958125550a641546c1dde5a31a6e4ac8f9c54cdb38da4815295b533add` | `13ea3613a6803431146b6974f1fb3587bd56c8ea0238f3c30b0819270ca848cb` | `e18a393e604230509d468205972185fe1b55e6a39a088a40ecc46c7e82749110e3c0287de565cd735aaf0e3bcf19e003` | `94851338e4ab00ce6ea7e3d0bdd568791545b9b92936a8fd0741a8efced4c79fe75ae98dfbf29014b46b8d566607698b` | [`e8e23d9`](https://github.com/chipsalliance/caliptra-sw/commit/e8e23d91448b5a16114cd8654ff7d3156bf3afcd) | 0 |
| [rom-1.1.0](https://github.com/chipsalliance/caliptra-sw/releases/tag/release_v20240807_0) | 1.1 | `875d30a2e26d55c35ad9cbc0affc3db057d40cebdd6f3e31c7c39b5ae34d4491` | `34e015d6d8c44109576aee80cd8428bea27286d34af3704a48c395c1fc32a424` | `b92ed17a39ce58d5b58c697aa6b7959d51282219ea14d7a9eafaed9bd78bfb94138bc5dd6c48b760990165094abc7e01` | `ff37afba4b438f306da48885b87badd9506c5cf6cbef3bacdf013d148878dad889f688fcaa46bc19ed14b0ca25068fe8` | [`51ff0a8`](https://github.com/chipsalliance/caliptra-sw/commit/51ff0a89f169bbf8e06acb49b31db555e99fefb6) | 0 |
| [rom-1.1.1](https://github.com/chipsalliance/caliptra-sw/releases/tag/release_v20250107_0) | 1.1 | `37f8f863a2b563757db9caec87b5c901765515e0ac61fe6f8da766b262638702` | `0212785561da4479f3a14aa516c8a6db0a887b428a3a9053bf5f2ea529a5d6bd` | `7af29db7dca485a6ede47cf78330973b97eaba1bb3c0eb7482c73cde8d128d7a151a54d5ecd8b2cc3b1e73bea0910ebd` | `71f54d7806a0a4c5055cf50a78f4286c484fd1bd548443e291722ea6b52ec17e7c10a90380da24a6a6167db88b13fc77` | [`d6713db`](https://github.com/chipsalliance/caliptra-sw/commit/d6713db2a9d7d36409ff4c92e35f4ba7f56169df) | 0 |
| [rom-1.2.0](https://github.com/chipsalliance/caliptra-sw/releases/tag/release_v20241202_0) | 1.1 | `de1a164d2431459cd61b80f989c9b59a22fc132dc664e6cbd4eddca734b93c3b` | `af44c1c1a7763c7197a9497112e3f3ad3224fe895c8713510543282330407484` | `6759cb95de60d8f58e44f9b8a0b5512d9e8aa6c5cef450484b887cb7d8d6d8ad4fedb0c646bdd30852b6a85f6aa84d95` | `64da5237e2412bcbd203db756136e474e2d8d078d8752b68bddd5b9717563abeecd27874ac0eead1bc777a4f01f5fc24` | [`3b50c6a`](https://github.com/chipsalliance/caliptra-sw/commit/3b50c6ab227bba973da2e6ca33a0a5012fde7146) | 0 |
| [rom-2.0.0](https://github.com/chipsalliance/caliptra-sw/releases/tag/rom-2.0.0) | 2.0.2+ | `34340911bda1d1e162a4ce74e6b00b79ef14fd0625f39d0420fc882a8f865a04` | `58505d9ca0b7d35607ef737c14d1b860a6140548ec655d68b3b08761f9518011` | `fe713cc28b370457ba16041e7f9a0f72de8249b6cd958b077cef9bc53e734bcff98368dbe33417e4aaa9f914192709c2` | `721e9dd57ef1738c3bbc49f8f9461395f30c448a5ba16240eaac986893fd2fd94c67be603008779a8e58e797f73dac07` | [`62c8009`](https://github.com/chipsalliance/caliptra-sw/commit/62c8009df12bb5e6d63479e82b8335aaa8ba84c6) | 0 |
| [rom-2.0.1](https://github.com/chipsalliance/caliptra-sw/releases/tag/rom-2.0.1) | 2.0.2+ | `c59fb3d1577c9390060ad23d0e1a3d657b38d3f3d0f995102c0cd76718792260` | `d97d8a56581419143f6eb75d922bba845eb9887e48f38aabd060e386e57efb6d` | `c19abd419720eeb5dad7beb20e587185bf0aa61546cbbc6514f56edc041730d6c9831175156c8d19e087f733ebbb382e` | `4f718dcda9ca6d4237db7f7fdcb9903ce629354ecae5605622fadb0575a4c1066902102085122d4c3b860bb66c2c64b7` | [`3824083`](https://github.com/chipsalliance/caliptra-sw/commit/3824083e4632ecbdff50aa2e723e89fa42d9dcf6) | 0 |
| [rom-2.0.2](https://github.com/chipsalliance/caliptra-sw/releases/tag/rom-2.0.2) | 2.0.2+ | `87422a3bbfabb277fa3c5cd3ea1118d7aae9a7c9483125b48b03eb29e8c12a4c` | `e977291bf7662327a45d2db252f420b930a0480c2f40a112c334ddea41f14d1a` | `a2a76fe0ef50fb1076a02f35c174ae01aec49816f86693438301807874274d0a4a1fc56b9aaaf6cb7bffcf0ad441f09c` | `516dc77518b344ae9c4eddda195ee7a0a4503a0ea8854ab1ab9e18abc725425550b501a95decc31bda97541442436e58` | [`473ae25`](https://github.com/chipsalliance/caliptra-sw/commit/473ae25561881ab9eca8b84e0ea14e43d18e1993) | 0 |
| [rom-2.1.0](https://github.com/chipsalliance/caliptra-sw/releases/tag/rom-2.1.0) | 2.1 | `d4cfdc9e413adc37c0079e1db7e88c1d4d049e0f19480d00e1f9898b6d2c21a7` | `99ba0ba9b4c5961a4749129458483f7b4b5222c3e5b33af092d991ae1eeb25ff` | `0d59b814c836b721f41bdd62cd46df5cf412e3ce673c6004f90f4cdb9645e57082cc0a6615aa26744eefd9629c189cca` | `4a7b5c2005562b1624f12ebdb771c2ba4b99ce0afc5ebadad0f520e6e25bab5b4c59c4f320f075608f97b93574242a86` | [`a72a76f`](https://github.com/chipsalliance/caliptra-sw/commit/a72a76f234d9f7069ddd1e8b8ebef30a9c3fa326) | 0 |
| [rom-2.1.1](https://github.com/chipsalliance/caliptra-sw/releases/tag/rom-2.1.1) | 2.1 | `028268971f9514409caa4846dfa3e82faf20e8efec69123da97e00a3cdb04e1d` | `512c69c828f0cca54b858937003dfd72fc799abd8078534f3cef27fc03302aeb` | `721657be76a4ac343cd3141d4d3a52ca9623590a40dace54dd022e321fcdab1b2050f5c2e9ca868c0a9786723695db69` | `4583491bd505f1b7d01e43376362741086ace56073e20096fac8bff04f73128a85ef11d5bbbb806dacca04fb298c692d` | [`510a23a`](https://github.com/chipsalliance/caliptra-sw/commit/510a23adbc911e8e72708799daba964ec045ef25) | 0 |

### FMC+Runtime FW Releases

| Version | RTL | FMC SHA384 | Runtime SHA384 | Git Commit | SVN |
|---------|-----|------------|----------------|------------|-----|
| [fmc-1.0.0 / rt-1.0.0](https://github.com/chipsalliance/caliptra-sw/releases/tag/rt-1.0.0) | 1.0 | `eaf02f44f961460ef4cfa984962db3ece8c69808af9f8c97196e7baaecf7539fc5a415caef6a0b281a94b2d7f1dcfa31` | `34460eafccc3a399b6a2f0f9c7cfb8f8cf5c07d46858420f0e62105bc8143e76727db9b356135eef78c61e005657a920` | [`cddb376`](https://github.com/chipsalliance/caliptra-sw/commit/cddb376171e1e39f16484b44965a68e93fcb461a) | 0 |
| [fmc-1.0.2 / rt-1.0.2](https://github.com/chipsalliance/caliptra-sw/releases/tag/release_v20240522_1) | 1.0 | `b9fa25d71df82ec07432c36fc369c543de087670523d18364b78cb36fb0ad7d5be1336252cf7fd59b1de0d5d0749fd34` | `c057f092d01dcff4e43f43262065219a4fed6e912d16227559223f90141e37048c133e41a6bc3982d7e2c04793fe4e81` | [`30887b7`](https://github.com/chipsalliance/caliptra-sw/commit/30887b76d9e315022448eb9fd734779d63901d6b) | 0 |
| [fmc-1.1.0 / rt-1.1.0](https://github.com/chipsalliance/caliptra-sw/releases/tag/release_v20240807_0) | 1.0, 1.1 | `92973f497917a082da7e3b7814e1f0a6962fb1b75f4e513eb0cf7d6e4675622bfcb1d0d5e6ebfefcaede09daf60f205d` | `df57fcad90a2d8ea2ba971bbd61713abc1f8a0cc0a4db7e236011e18c0835786ca8c15f6a2c62cbfa271406c3f1fd250` | [`51ff0a8`](https://github.com/chipsalliance/caliptra-sw/commit/51ff0a89f169bbf8e06acb49b31db555e99fefb6) | 0 |
| [rt-1.2.0](https://github.com/chipsalliance/caliptra-sw/releases/tag/release_v20250205_1) | 1.0, 1.1 | `8056203c9d6e3c006d45647090c6f3e1ad686a25f49f7329a6465c0ee72ed8777fbd44d0d44226327c2a6edfcf3be6af` | `d7092800c60b7f389ee016ce055d581f7055a7c08625c58376c55fd99a9925a7ad9b229ec7c2edfda5b4ee8a1b47a3e9` | [`951209a`](https://github.com/chipsalliance/caliptra-sw/commit/951209a31c4373658f89e4b1211f3a557731c7d9) | 0 |
| [rt-1.2.1](https://github.com/chipsalliance/caliptra-sw/releases/tag/release_v20250327_0) | 1.0, 1.1 | `cefdc6454ee254661d35f2ecc7a973aadc1c1c8a4e702376171ef10385d624360df5f79779d2ab30edc82805784c3dd5` | `d48f83b629378d32ac2547b31799794e353e1460ae773048f902723ab95efffb142cc7e51c7f4580a7ec89f22ea531c1` | [`98df57b`](https://github.com/chipsalliance/caliptra-sw/commit/98df57bbb7bb5746c4282ca0505fea3b0fa64ec4) | 0 |
| [rt-1.2.2](https://github.com/chipsalliance/caliptra-sw/releases/tag/rt-1.2.2) | 1.0, 1.1 | `2f51374b62e3970696608bd92a61da99d7df27d0e715638b83ff6c1a6c71fb3dca09c84a530edc4cd9e0f068a2cc1d4c` | `5a91ce09d7e8c976912a5f72885d1322da23c66b7c1755a69d3d557f4375ccbf96486d2eef7ec12149dc84c1b76254ab` | [`cccf641`](https://github.com/chipsalliance/caliptra-sw/commit/cccf6419a5952f89c3aa270102edd5da9a11c5ac) | 0 |
| [rt-1.2.3](https://github.com/chipsalliance/caliptra-sw/releases/tag/release_v20251105_0) | 1.0, 1.1 | `a761cd21a8ce9b657bffb9b9ee1b18d9c971464cd624aae7df7b727b9b14ae1c44e18398d3f86a98f9ef9571519e9aba` | `075e8689ec47154989a96dfac0d1df7e43811aa828962d46e6f3acc57a85b79649821af3b6e1512ad0244a7384d46115` | [`1551253`](https://github.com/chipsalliance/caliptra-sw/commit/15512531781016c126dcb9ee6963410b6a9200b0) | 0 |
| [rt-1.2.4](https://github.com/chipsalliance/caliptra-sw/releases/tag/release_v20260312_0) | 1.0, 1.1 | `e87dcc2e4e93dee0c81f336c7b7abce8237a24c4175dcbf66a3c88d52b631ad90b07b74e1451ad90e5f2c9fea9e80f07` | `bf73ac4a99096de4eef2458425142e865a4fa240f952a3a60d0307772fc1b8ae0d7d8e9a6410238ae2ff384c0dfd651a` | [`84ca1a1`](https://github.com/chipsalliance/caliptra-sw/commit/84ca1a1edfd5c6fa72a44e0e3354bb40b166ffde) | 0 |
| [fw-2.0.0](https://github.com/chipsalliance/caliptra-sw/releases/tag/fw-2.0.0) | 2.0.2+ | `e930214737e163130bd23f0c9c7e8bc2157d175fc43ef746640088ba78a3bce40af4402c673012841f01e677d1decde8` | `2a60aed198319336b8029742b2c9eb756675f621d686f966f3fb89ab2be0fa419f12f88a894c2b0fc96b8c51e3d72c61` | [`8efce03`](https://github.com/chipsalliance/caliptra-sw/commit/8efce0337cc5501274694e9b7c3a0df077cafdde) | 0 |
| [fw-2.0.1](https://github.com/chipsalliance/caliptra-sw/releases/tag/fw-2.0.1) | 2.0.2+ | `71759a4d23c0db30f987816d35696258886c56b56726fe69772ad524886183a7dc40e14ea2c9b939b2b211d2f2b52183` | `a49918f3cc4be9ed8caf6e1626119246912b4437a97c4979475931fd532d68c1024b99271dc1930bd0036248ee1f0228` | [`1a77f86`](https://github.com/chipsalliance/caliptra-sw/commit/1a77f868342fc604add6a9e1a0811c7c7962fa9c) | 0 |
| [fw-2.1.0](https://github.com/chipsalliance/caliptra-sw/releases/tag/fw-2.1.0) | 2.1 | `59b94ca315ac3bb3754277caa33207f1b11b107ff65feb598ae88f90954615803fa2f234423f6ccc1cd72bd737d75569` | `af3c4c67b034e8f5829e61446d2c3f4da2341d04a0bd049d4f9d448106e0d1f24eacb838f59a38c3a594180a2f459f79` | [`7da3b01`](https://github.com/chipsalliance/caliptra-sw/commit/7da3b01b8b1806af0ec491c5e3e3e7cac91a3561) | 0 |

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

### [caliptra-ureg](/ureg)

Register abstraction and code generator to create register libraries. The `registers` directory has a binary that creates the register code that includes caliptra-ureg.

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
[this README](/hw/fpga/README.md).

For a streamlined development experience, use the [xtask FPGA flow](/xtask/README.md), which automates building, programming, and testing:

```shell
# Setup once per power cycle
cargo xtask fpga bootstrap

# Build and run tests
cargo xtask fpga build
cargo xtask fpga build-test
cargo xtask fpga test
```
