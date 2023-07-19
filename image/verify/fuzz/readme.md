# Brief setup notes
- Fuzzer attempts ptrace attach, permit this: `sudo sysctl kernel.yama.ptrace_scope=0`

# Building/Testing
- *Cleanup*: `rm -rf fuzz-*.log corpus/fuzz_target_{coldreset,updatereset} artifacts/fuzz_target_{coldreset,updatereset} coverage target`
  - `mkdir -p corpus/fuzz_target_{coldreset,updatereset} artifacts/fuzz_target_{coldreset,updatereset}`

**Fuzz**: `cargo +nightly fuzz run -s address,leak,memory fuzz_target_coldreset -- -max_len=23692 -jobs=8` -- **NOTE WELL**: Only one sanitiser can be used at a time.
- `max_len` seems stable now

**Coverage**: `cargo +nightly fuzz coverage -s address,leak,memory fuzz_target_coldreset -- -max_len=23692` -- **NOTE WELL**: Only one sanitiser can be used at a time.
- Visualisation: `~/.rustup/toolchains/nightly-x86_64-unknown-linux-gnu/lib/rustlib/x86_64-unknown-linux-gnu/bin/llvm-cov show target/x86_64-unknown-linux-gnu/coverage/x86_64-unknown-linux-gnu/release/fuzz_target_coldreset --format=html -instr-profile=coverage/fuzz_target_coldreset/coverage.profdata > index.html`

NOTE: Fuzzing the UpdateReset path is the same. But generate a different corpus?

## Seed corpus (optional)
Optionally, to generate a seed corpus first, I've been running:
- `for x in $(seq 001 016); do cargo run -j16 --manifest-path=builder/Cargo.toml --release --bin image -- --rom elf2rom_built.rom --fw caliptra-builder_built_fw.bundle; mv caliptra-builder_built_fw.bundle image/verify/fuzz/corpus/fuzz_target_coldreset/${x}; rm elf2rom_built.rom; cargo clean; done`
- TODO: Check impact.

**Open question**: - How could a dictionary help?

# Minimisation
- `mkdir -p corpus_new/fuzz_target_{coldreset,updatereset}`
- `cargo +nightly fuzz run -s address,leak,memory fuzz_target_coldreset corpus_new/fuzz_target_coldreset corpus/fuzz_target_coldreset -- -merge=1`
- (optionally repeat on the UpdateReset corpus)
- `rm -rf corpus && mv corpus_new corpus`
