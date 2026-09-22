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

---

### HMAC-384 KDF (`test_acvp_hmac`)

SP 800-108 key derivation. Note there is **no test-type line** for this algorithm:

```
<hex-encoded key, 48 bytes>
<hex-encoded label>
```

Example:

```
b57dc52354afee11edb4c9052a528344348b2c6b6c39f32133ed3bb72035a4ab55d6648c1529ef7a9170fec9ef26a81e
17E641909DEDFE4968BB95D7F770E455
```

The label is fixed input data chosen by the implementation, not supplied by the ACVP
vector set — the vector file provides only the key. The runner generates a fresh 16-byte
label per test case and records it next to the response, since the lab needs to know
which value was used. No context is applied.

Output: one `HMAC384KDF:XX` line per derived-key byte (48 lines). The runner's response
pattern matches exactly two hex characters per line, so the bytes must be printed
individually rather than as a single concatenated string.

---

### SHA-384 / SHA-512 Accelerator (`test_acvp_sha2_512_384acc`)

The accelerator digests data staged in the mailbox, so each test streams the message
through a mailbox transaction (command `0x1c`) before starting the digest.

```
<algorithm: SHA384ACC or SHA512ACC>
<test type: AFT or MCT>
<hex-encoded message or seed>
```

**AFT** — single message digest, up to 5900 bytes:

```
SHA384ACC
AFT
616263
```

**MCT** — seed for 100-outer x 1000-inner iterations. The seed is 48 bytes for
`SHA384ACC` and 64 bytes for `SHA512ACC`:

```
SHA512ACC
MCT
<hex seed, 64 bytes>
```

Output: one `SHA384ACC:XX` or `SHA512ACC:XX` line per digest byte (48 or 64 lines per
digest). AFT emits a single digest; MCT emits one per outer iteration (100 total), which
the runner chunks back apart by digest size.

The 2.1 production vector sets (1024 AFT + 1 MCT each) top out at 5884 bytes per message,
which is why the message buffer is sized 5900. Note those vector files use CRLF line
endings; the runner strips them before writing the stimulus.

---

### LMS-24 Signature Verification (`test_acvp_lms_24`)

LMS over SHA256/192 with N=6, P=51, H=15.

```
LMS_SIGVER
<hex-encoded message>
<hex-encoded public key, 48 bytes>
<hex-encoded signature, 1620 bytes>
```

The public key and signature must be exactly 48 and 1620 bytes: they are converted with
`zerocopy::FromBytes::ref_from_bytes`, which rejects any other length. Those sizes are
fixed by the type parameters:

```
LmsPublicKey<6>       = 4 + 4 + 16 + 6*4                     =   48
LmsSignature<6,51,15> = 4 + (4 + 6*4 + 51*6*4) + 4 + 15*6*4  = 1620
```

Output:
- `LMS_SIGVER:01` — signature valid
- `LMS_SIGVER:00` — signature invalid

The runner maps these to `true` / `false` in the response file.

---

### ML-DSA-87 (`test_acvp_mldsa87`)

The operation is selected by the first line of the stimulus.

**KEYGEN** — derive a key pair from a seed:

```
MLDSA_KEYGEN
<hex seed, 32 bytes>
```

Output: `MLDSA_PUBKEY:<hex>` (2592 bytes) then `MLDSA_PRIVKEY:<hex>` (4896 bytes).

**SIGGEN** — sign a message with a private key, skipping the post-sign verification
that the driver normally performs (the ACVP vector set supplies no public key):

```
MLDSA_SIGGEN
<hex private key, 4896 bytes>
<hex message>
```

Output: `MLDSA_SIGGEN:<hex>` (4627 bytes).

**SIGVER** — verify a signature:

```
MLDSA_SIGVER
<hex public key, 2592 bytes>
<hex message>
<hex signature, 4627 bytes>
```

Output: `MLDSA_SIGVER:01` (valid) or `MLDSA_SIGVER:00` (invalid).

Notes:

- Keys and signatures are emitted as a **single uppercase hex string**. The runner
  scrapes them with `[0-9A-F]+`, so lowercase output would silently match nothing.
- The signature is 4627 bytes per FIPS 204, but the driver stores it in `[u32; 1157]`
  = 4628 bytes; the trailing padding byte is excluded from the output.
- Deterministic signing is used (`sign_rnd` all zeros) and contextLength is always 0,
  matching the vector sets, which carry no context field.
- `SIGGEN` uses `sign_var_no_verify`, which requires the `cavp-test-harness` feature on
  `caliptra-drivers`. That is already enabled in this crate's `Cargo.toml`.
- `test_mldsa_name` runs first because it performs the `CfiCounter::reset` that the
  CFI-instrumented verification path depends on.
