# caliptra-drivers-acvp-bin

ACVP (Automated Cryptographic Validation Protocol) test firmware for Caliptra drivers.

Each algorithm is a separate firmware binary that reads a single test vector from
`stimulus/current.txt` and reports the result over UART. The host-side runner
rewrites that file once per test case, rebuilds, and scrapes the output.

## Running a test

Update `stimulus/current.txt` with the vector for the algorithm you want to run,
then execute:

```bash
cargo test -p caliptra-drivers --features acvp-tests test_acvp_<algorithm>
```

The firmware reads `stimulus/current.txt` at **compile time** via `include_str!`, so
the file must be updated before running `cargo test`. Cargo detects the change and
recompiles automatically.

These tests are `#[ignore]`d unless the `acvp-tests` feature is enabled, so normal
CI runs do not execute them against the placeholder stimulus checked into the tree.

---

## stimulus/current.txt formats

### SHA-1 (`test_acvp_sha1`)

```
<test type: AFT or MCT>
<hex-encoded message or seed>
```

**AFT** (Algorithm Functional Test) — digest of a single message, up to 5000 bytes:

```
AFT
616263
```

**MCT** (Monte Carlo Test) — 20-byte seed driving 100 outer x 1000 inner iterations:

```
MCT
<hex seed, 20 bytes>
```

Output: one `SHA1:XX` line per digest byte (20 lines per digest). AFT emits a single
digest; MCT emits one digest per outer iteration (100 total), interleaved with
`MCT ol:<n>` and `il:<n>` progress lines that the runner ignores.
