# Introduction

This directory contains test vectors for the HPKE implementation used by the test suite to communicate with Caliptra.

## Checked in test vectors

* **hpke-pq.json**: This is the test vectors distributed with the [hpke-pq ietf draft](https://datatracker.ietf.org/doc/draft-ietf-hpke-pq/03/).
* **hpke-p384.json**: This is a hand crafted test vector for "DH(P-384,SHA-384)-HKDF-SHA-384-AES-256-GCM". See more in [p384-test-vector](#p384_test_vector).

# p384-test-vector

This test vector is hand crafted because the [hpke-02 ietf draft](https://datatracker.ietf.org/doc/html/draft-ietf-hpke-hpke-02) does not include a test vector for this ciphersuite.

## Vector Generation Methology

### Generate seed

```python
import os
import binascii
from pyhpke import AEADId, KDFId, KEMId, CipherSuite

def generate_hpke_vectors():
    suite = CipherSuite.new(
        KEMId.DHKEM_P384_HKDF_SHA384,
        KDFId.HKDF_SHA384,
        AEADId.AES256_GCM
    )

    # For DHKEM(P-384), Nsk = 48 bytes.
    ikm = os.urandom(48)
    kp = suite.kem.derive_key_pair(ikm)

    pk = kp.public_key
    sk = kp.private_key

    pk_bytes = pk.to_public_bytes()
    # pyhpke workaround: it returns key_size (bits) as length in bytes.
    # Just grab the 48 bytes that make the private key. The rest is padding
    sk_bytes = sk.to_private_bytes()[-48:]

    info = b"test_info_string"
    aad = b"test_aad_string"
    plaintext = b"Hello, HPKE World!"

    enc, sender_context = suite.create_sender_context(pk, info)
    ciphertext = sender_context.seal(plaintext, aad)
    receiver_context = suite.create_recipient_context(enc, sk, info)
    decrypted = receiver_context.open(ciphertext, aad)

    assert decrypted == plaintext

    print("HPKE Test Vector (using pyhpke)")
    print("===============================")
    print(f"Suite: KEM=DHKEM(P-384, HKDF-SHA384), KDF=HKDF-SHA384, AEAD=AES-256-GCM")
    print(f"IKM (hex): {binascii.hexlify(ikm).decode()}")
    print(f"SK (hex): {binascii.hexlify(sk_bytes).decode()}")
    print(f"PK (hex): {binascii.hexlify(pk_bytes).decode()}")
    print(f"Info (hex): {binascii.hexlify(info).decode()}")
    print(f"AAD (hex): {binascii.hexlify(aad).decode()}")
    print(f"Plaintext (hex): {binascii.hexlify(plaintext).decode()}")
    print(f"Enc (Ephemeral PK) (hex): {binascii.hexlify(enc).decode()}")
    print(f"Ciphertext (hex): {binascii.hexlify(ciphertext).decode()}")
    print("\nVerification Successful: Decrypted text matches plaintext.")

if __name__ == "__main__":
    generate_hpke_vectors()

```

### Generate test vector JSON

```python
import json
import binascii
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec

def hex_to_bytes(h):
    return binascii.unhexlify(h)

def bytes_to_hex(b):
    return binascii.hexlify(b).decode()

def i2osp(val, length):
    return val.to_bytes(length, 'big')

ikmR_hex = "466ad52290edbefe36c99ff0ab5978c0511e498d2ed42e655f5d9e1f2d6555fc4896ad967370d5da5c2b2431138999fa"
skR_hex = "28e9d73133fd107428befffce0edbe064925027d1fa390afe5a66ff7725ad8744a74721d85420e60fac3c906b5a50654"
pkR_hex = "04a8bbc248b2c2b56f43de52b5f0d82ff5bcbc008302f094e9628723e02b1239cdb263c19c7863ba35e1f647a777b52d3d2711fa5616e557461d86c371cc6a1c2a157c6db9ff5bc4708079b2ed95fa617b568cb2ca61d0bf2a75f4198b5f406212"
enc_hex = "0408a4adffefc93f98395af7a97257a79ff116ee1b65e648845a6051e374c200d6e253fc79dca8dca7ca3da613dd758a54665bc85cdfc819d3459ed94e1d670a60606b0dcfb972bd702ea0a590e67fb3ad051f48af71b51c5d134a43bc1708f15b"
info_hex = "746573745f696e666f5f737472696e67"
aad_hex = "746573745f6161645f737472696e67"
pt_hex = "48656c6c6f2c2048504b4520576f726c6421"
ct_hex = "e2218f096501e87da83838b3045885c80699777e7b5a5f55c7911cc063a82e3d08cb"

KEM_ID = 0x0011
KDF_ID = 0x0002
AEAD_ID = 0x0002

hpke_suite_id = b"HPKE" + i2osp(KEM_ID, 2) + i2osp(KDF_ID, 2) + i2osp(AEAD_ID, 2)
kem_suite_id = b"KEM" + i2osp(KEM_ID, 2)

def hkdf_extract(salt, ikm):
    if salt is None:
        salt = b"\x00" * 48
    h = hmac.HMAC(salt, hashes.SHA384(), backend=default_backend())
    h.update(ikm)
    return h.finalize()

def hkdf_expand(prk, info, length):
    return HKDFExpand(
        algorithm=hashes.SHA384(),
        length=length,
        info=info,
        backend=default_backend()
    ).derive(prk)

def labeled_extract(salt, label, ikm, suite_id):
    labeled_ikm = b"HPKE-v1" + suite_id + label + ikm
    return hkdf_extract(salt, labeled_ikm)

def labeled_expand(prk, label, info, length, suite_id):
    labeled_info = i2osp(length, 2) + b"HPKE-v1" + suite_id + label + info
    return hkdf_expand(prk, labeled_info, length)

# Raw ECDH
sk_int = int(skR_hex, 16)
sk = ec.derive_private_key(sk_int, ec.SECP384R1(), default_backend())
enc_bytes = hex_to_bytes(enc_hex)
peer_public_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP384R1(), enc_bytes)
dh = sk.exchange(ec.ECDH(), peer_public_key)

# ExtractAndExpand (DHKEM) to get Shared Secret
pkR_bytes = hex_to_bytes(pkR_hex)
kem_context = enc_bytes + pkR_bytes

# eae_prk = LabeledExtract(nil, "eae_prk", dh, kem_suite_id)
eae_prk = labeled_extract(None, b"eae_prk", dh, kem_suite_id)

# shared_secret = LabeledExpand(eae_prk, "shared_secret", kem_context, Nsecret, kem_suite_id)
shared_secret = labeled_expand(eae_prk, b"shared_secret", kem_context, 48, kem_suite_id)


# Key Schedule
mode = 0
psk = b""
psk_id = b""
info = hex_to_bytes(info_hex)

psk_id_hash = labeled_extract(None, b"psk_id_hash", psk_id, hpke_suite_id)
info_hash = labeled_extract(None, b"info_hash", info, hpke_suite_id)

# key_schedule_context = mode || psk_id_hash || info_hash
key_schedule_context = i2osp(mode, 1) + psk_id_hash + info_hash

secret = labeled_extract(shared_secret, b"secret", psk, hpke_suite_id)
key = labeled_expand(secret, b"key", key_schedule_context, 32, hpke_suite_id)
base_nonce = labeled_expand(secret, b"base_nonce", key_schedule_context, 12, hpke_suite_id)
exporter_secret = labeled_expand(secret, b"exp", key_schedule_context, 48, hpke_suite_id)

vector = {
    "mode": 0,
    "kem_id": KEM_ID,
    "kdf_id": KDF_ID,
    "aead_id": AEAD_ID,
    "info": info_hex,
    "ikmR": ikmR_hex,
    "ikmE": None,
    "skR": skR_hex,
    "pkR": pkR_hex,
    "enc": enc_hex,
    "shared_secret": bytes_to_hex(shared_secret),
    "key_schedule_context": bytes_to_hex(key_schedule_context),
    "secret": bytes_to_hex(secret),
    "key": bytes_to_hex(key),
    "base_nonce": bytes_to_hex(base_nonce),
    "exporter_secret": bytes_to_hex(exporter_secret),
    "encryptions": [
        {
            "plaintext": pt_hex,
            "aad": aad_hex,
            "nonce": bytes_to_hex(base_nonce),
            "ciphertext": ct_hex
        }
    ]
}
```

### Verify Test Vector with Go library

```go
package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"

	"filippo.io/hpke"
)

type Encryption struct {
	Plaintext  string `json:"plaintext"`
	AAD        string `json:"aad"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

type TestVector struct {
	Mode        int          `json:"mode"`
	KemID       uint16       `json:"kem_id"`
	KdfID       uint16       `json:"kdf_id"`
	AeadID      uint16       `json:"aead_id"`
	Info        string       `json:"info"`
	SkR         string       `json:"skR"`
	PkR         string       `json:"pkR"`
	Enc         string       `json:"enc"`
	Encryptions []Encryption `json:"encryptions"`
}

func main() {
	jsonFile, err := os.Open("test_vector.json")
	if err != nil {
		log.Fatalf("Failed to open test_vector.json: %v", err)
	}
	defer jsonFile.Close()

	byteValue, _ := io.ReadAll(jsonFile)

	var vectors []TestVector
	if err := json.Unmarshal(byteValue, &vectors); err != nil {
		log.Fatalf("Failed to parse JSON: %v", err)
	}

	for i, v := range vectors {
		fmt.Printf("Verifying Vector #%d (Mode %d, KEM %d, KDF %d, AEAD %d)...\n", i, v.Mode, v.KemID, v.KdfID, v.AeadID)

		skBytes, err := hex.DecodeString(v.SkR)
		if err != nil {
			log.Fatalf("Invalid SkR hex: %v", err)
		}
		encBytes, err := hex.DecodeString(v.Enc)
		if err != nil {
			log.Fatalf("Invalid Enc hex: %v", err)
		}
		infoBytes, err := hex.DecodeString(v.Info)
		if err != nil {
			log.Fatalf("Invalid Info hex: %v", err)
		}

		kem, err := hpke.NewKEM(v.KemID)
		if err != nil {
			log.Fatalf("Unsupported KEM ID %d: %v", v.KemID, err)
		}
		kdf, err := hpke.NewKDF(v.KdfID)
		if err != nil {
			log.Fatalf("Unsupported KDF ID %d: %v", v.KdfID, err)
		}
		aead, err := hpke.NewAEAD(v.AeadID)
		if err != nil {
			log.Fatalf("Unsupported AEAD ID %d: %v", v.AeadID, err)
		}

		priv, err := kem.NewPrivateKey(skBytes)
		if err != nil {
			log.Fatalf("Failed to parse private key: %v", err)
		}

		receiver, err := hpke.NewRecipient(encBytes, priv, kdf, aead, infoBytes)
		if err != nil {
			log.Fatalf("Failed to create receiver: %v", err)
		}

		for j, enc := range v.Encryptions {
			aadBytes, _ := hex.DecodeString(enc.AAD)
			ctBytes, _ := hex.DecodeString(enc.Ciphertext)
			expectedPtBytes, _ := hex.DecodeString(enc.Plaintext)

			plaintext, err := receiver.Open(aadBytes, ctBytes)
			if err != nil {
				log.Fatalf("Encryption #%d failed to decrypt: %v", j, err)
			}

			if string(plaintext) != string(expectedPtBytes) {
				log.Fatalf("Encryption #%d mismatch!\nGot: %x\nWant: %x", j, plaintext, expectedPtBytes)
			}
			fmt.Printf("  Encryption #%d: OK\n", j)
		}
		fmt.Println("Vector Verified Successfully.")
	}
}
```

