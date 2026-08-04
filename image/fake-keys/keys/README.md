# Caliptra Test Keys

This directory contains test key pairs in standard SubjectPublicKeyInfo (SPKI)
and PKCS#8 PrivateKeyInfo PEM formats. These keys correspond to the test
key constants defined in `caliptra-image-fake-keys`.

## Key Types and OpenSSL Commands

### 1. ECC P-384 Keys (`secp384r1`)

To generate a new ECC P-384 private key with OpenSSL:

```bash
openssl ecparam -name secp384r1 -genkey -noout -out vendor_ecc_0_key.pem
```

To extract the corresponding SPKI public key PEM:

```bash
openssl ec -in vendor_ecc_0_key.pem -pubout -out vendor_ecc_0_pub.pem
```

### 2. LMS Keys (RFC 8554)

LMS/HSS keys use SubjectPublicKeyInfo / PKCS#8 ASN.1 structures with the
`id-alg-hss-lms` OID (`1.2.840.113549.1.9.16.3.17`).

To generate an LMS key pair with OpenSSL 3.x (with LMS provider):

```bash
openssl genpkey -algorithm LMS -pkeyopt lms_parm:LMS_SHA256_M24_H15 \
  -out vendor_lms_0_key.pem
```

To extract the public key PEM:

```bash
openssl pkey -in vendor_lms_0_key.pem -pubout -out vendor_lms_0_pub.pem
```

### 3. ML-DSA-87 Keys (FIPS 204)

ML-DSA-87 keys use SubjectPublicKeyInfo / PKCS#8 ASN.1 structures with the
`id-ml-dsa-87` OID (`2.16.840.1.101.3.4.3.31`).

To generate an ML-DSA-87 key pair with OpenSSL 3.5+ (or OpenSSL OQS provider):

```bash
openssl genpkey -algorithm mldsa87 -out vendor_mldsa_0_key.pem
```

To extract the public key PEM:

```bash
openssl pkey -in vendor_mldsa_0_key.pem -pubout -out vendor_mldsa_0_pub.pem
```

## Regenerating Test Keys from Rust Constants

To regenerate the checked-in `.pem` files directly from the hardcoded Rust
constants in `caliptra-image-fake-keys`, run:

```bash
cargo test -p caliptra-image-fake-keys -- --ignored test_write_lms_keys
```
