# Lifecycle Keys

This directory contains fake ECC P384 and ML-DSA-87 key pairs for testing.
The keys in this file were generated with OpenSSL using the following commands:

## ECC P384 Keypair

```
openssl ecparam -name secp384r1 -genkey -noout -out hw-model/src/keys/ecc_p384_private_key.pem
```

## ML-DSA-87 Keypair

```
openssl genpkey -algorithm ml-dsa-87 -out hw-model/src/keys/mldsa87_private.pem
```
