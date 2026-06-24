# caliptra-drivers-acvp-bin

ACVP (Automated Cryptographic Validation Protocol) test firmware for Caliptra drivers.

## Running a test

Update `stimulus/current.txt` with the test vector for the algorithm you want to run,
then execute:

```bash
cargo test -p caliptra-drivers --features acvp-tests test_acvp_<algorithm>
```

The firmware reads `stimulus/current.txt` at **compile time** via `include_str!`, so the
file must be updated before running `cargo test`. Cargo detects the file change and
recompiles automatically.

---

## stimulus/current.txt formats

### SHA1 (`test_acvp_sha1`)

```
<test type: AFT or MCT>
<hex-encoded message or seed>
```

**AFT** (Algorithm Functional Test) — single message digest:
```
AFT
616263
```

**MCT** (Monte Carlo Test) — seed for 100-outer × 1000-inner iterations:
```
MCT
<hex seed, 20 bytes>
```

Output: one `SHA1:XX` line per digest byte (20 lines).

---

### HMAC-384 KDF (`test_acvp_hmac`)

```
<hex-encoded key, 48 bytes>
<hex-encoded label>
```

Example:
```
b57dc52354afee11edb4c9052a528344348b2c6b6c39f32133ed3bb72035a4ab55d6648c1529ef7a9170fec9ef26a81e
17e641909dedfe4968bb95d7f770e4557ca347a46614cb371423f0d91df3b58b536ed54531fd2a2eb0b8b2a1634c23c88fad9706c45db4411a23b89
```

Output: one `HMAC384KDF:XX` line per output byte (48 lines).

---

### LMS-24 Signature Verification (`test_acvp_lms_24`)

```
LMS_SIGVER
<hex-encoded message>
<hex-encoded public key, 48 bytes>
<hex-encoded signature>
```

Example:
```
LMS_SIGVER
<hex message>
<hex pubkey>
<hex sig>
```

Output:
- `LMS_SIGVER:01` — signature valid
- `LMS_SIGVER:00` — signature invalid

---

### ML-DSA-87 (`test_acvp_mldsa87`)

The test type is determined by the first line of `stimulus/current.txt`.

**KEYGEN** — generate public/private key pair from a seed:
```
MLDSA_KEYGEN
<hex seed, 32 bytes>
```
Output: `MLDSA_PUBKEY:<hex>` (2592 bytes) then `MLDSA_PRIVKEY:<hex>` (4896 bytes).

**SIGGEN** — sign a message with a private key (no post-sign verification):
```
MLDSA_SIGGEN
<hex private key, 4896 bytes>
<hex message, up to 512 bytes>
```
Output: `MLDSA_SIGGEN:<hex>` (4627-byte signature).

**SIGVER** — verify a signature against a public key and message:
```
MLDSA_SIGVER
<hex public key, 2592 bytes>
<hex message, up to 512 bytes>
<hex signature, 4627 bytes>
```
Output:
- `MLDSA_SIGVER:01` — signature valid
- `MLDSA_SIGVER:00` — signature invalid

> **Note:** SIGGEN uses `sign_var_no_verify` which requires the `cavp-test-harness`
> feature in `caliptra-drivers`. This is already enabled in `test-acvp/Cargo.toml`.
