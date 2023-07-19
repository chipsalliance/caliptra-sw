# Brief setup notes
- Fuzzer requires coredumps, provide these: `sudo sysctl kernel.core_uses_pid=0 && sudo sysctl kernel.core_pattern=core`
- Performance optimisation: `sudo sysctl kernel.sched_child_runs_first=1`

# Building/Testing
*Cleanup*: `rm -rf corpus/fuzz_target_{coldreset,updatereset} artifacts/fuzz_target_{coldreset,updatereset} standard cmplog`
  - `mkdir -p corpus/fuzz_target_{coldreset,updatereset} artifacts/fuzz_target_{coldreset,updatereset}`

**Fuzz**: `~/.local/share/afl.rs/rustc-1.73.0-nightly-da6b55c/afl.rs-0.13.3/afl/bin/afl-whatsup artifacts/fuzz_target_coldreset` useful to retrieve all statuses
Initialise base options:
- Note: `-G` seems stable now; `-L` is apparently acceptable
```
export CARGO_AFL_BUILD_STANDARD="cargo +nightly afl build" && \
export CARGO_AFL_RUN_A_STANDARD="cargo +nightly afl fuzz -i corpus/fuzz_target_coldreset -o artifacts/fuzz_target_coldreset -G 23692 -p fast -L 1 -l 2ATR"
```

Workers (TODO: Parallelisation):
- Standard:
```
$CARGO_AFL_BUILD_STANDARD && \
cp target/debug/fuzz_target_coldreset standard; \
$CARGO_AFL_RUN_A_STANDARD -M node01 ./standard
```
- CmpLog:
```
AFL_LLVM_CMPLOG=1 $CARGO_AFL_BUILD_STANDARD && \
cp target/debug/fuzz_target_coldreset cmplog; \
$CARGO_AFL_RUN_A_STANDARD -c ./cmplog -S node02 ./standard
```

**Coverage**: Also `afl-plot`?
- `~/.local/share/afl.rs/rustc-1.73.0-nightly-da6b55c/afl.rs-0.13.3/afl/bin/afl-showmap -C -i artifacts/fuzz_target_coldreset/ -o coverage -- ./standard`

NOTE: Fuzzing the UpdateReset path is the same. But generate a different corpus?

## Seed corpus
Generate a seed corpus first. I've been running:
- `for x in $(seq 001 016); do cargo run -j16 --manifest-path=builder/Cargo.toml --release --bin image -- --rom elf2rom_built.rom --fw caliptra-builder_built_fw.bundle; mv caliptra-builder_built_fw.bundle image/verify/afl/corpus/fuzz_target_coldreset/${x}; rm elf2rom_built.rom; cargo clean; done`
- TODO: Check impact.

**Open question**: - How could a dictionary help?

# Minimisation
- TODO
