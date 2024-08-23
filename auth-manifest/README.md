## SOC Manifest

The Caliptra SOC manifest has two main components:

- ### **Preamble**
 The Preamble section contains the authorization manifest ECC and LMS public keys of the vendor and the owner. These public keys correspond to the private keys that sign the Image Metadata Collection (IMC) section. These signatures are included in the Preamble. The Caliptra firmware’s ECC and LMS private keys endorse the manifest’s public keys, and these endorsements (signatures) are part of the Preamble as well.

 *Note: All fields are little endian unless specified*

| Field | Size (bytes) | Description|
|-------|--------|------------|
| Manifest Marker | 4 | Magic Number marking the start of the manifest. The value must be 0x41544D4E (‘ATMN’ in ASCII)|
| Manifest Size | 4 | Size of the full manifest structure |
| Version | 4 | Manifest version |
| Flags | 4 | Feature flags. <br> **Bit0:** - Vendor Signature Required. If set, verify the vendor IMC signature(s) <br>**Bit1-Bit31:** Reserved |
| Vendor ECC Public Key | 96 | ECC P-384 public key used to verify the IMC Signature. <br> **X-Coordinate:** Public Key X-Coordinate (48 bytes) <br> **Y-Coordinate:** Public Key Y-Coordinate (48 bytes) |
| Vendor LMS Public Key | 48 | LMS public key used to verify the IMC Signature. <br> **tree_type:** LMS Algorithm Type (4 bytes) <br> **otstype:** LMS Ots Algorithm Type (4 bytes) <br> **id:**  (16 bytes) <br> **digest:**  (24 bytes) <br> Note: If LMS validation is not required, this should field should be zeroed out.|
| Vendor ECC Signature | 96 | Vendor ECDSA P-384 signature of the Version, Flags, Vendor ECC and LMS public keys, hashed using SHA2-384. <br> **R-Coordinate:** Random Point (48 bytes) <br> **S-Coordinate:** Proof (48 bytes) |
| Vendor LMS Signature | 1620 | Vendor LMS signature of the Version, Flags, Vendor ECC and LMS public keys, hashed using SHA2-384. <br> **q:** Leaf of the Merkle tree where the OTS public key appears (4 bytes) <br> **ots:** Lmots Signature (1252 bytes) <br> **tree_type:** Lms Algorithm Type (4 bytes) <br> **tree_path:** Path through the tree from the leaf associated with the LM-OTS signature to the root. (360 bytes) <br> Note: If LMS validation is not required, this should field should be zeroed out.|
| Owner ECC Public Key | 96 | ECC P-384 public key used to verify the IMC Signature. <br> **X-Coordinate:** Public Key X-Coordinate (48 bytes) <br> **Y-Coordinate:** Public Key Y-Coordinate (48 bytes) |
| Owner LMS Public Key | 48 | LMS public key used to verify the IMC Signature. <br> **tree_type:** LMS Algorithm Type (4 bytes) <br> **otstype:** LMS Ots Algorithm Type (4 bytes) <br> **id:**  (16 bytes) <br> **digest:**  (24 bytes) <br> Note: If LMS validation is not required, this should field should be zeroed out.|
| Owner ECC Signature | 96 | Owner ECDSA P-384 signature of the Version, Flags, Owner ECC and LMS public keys, hashed using SHA2-384. <br> **R-Coordinate:** Random Point (48 bytes) <br> **S-Coordinate:** Proof (48 bytes) |
| Owner LMS Signature | 1620 | Owner LMS signature of the Version, Flags, Owner ECC and LMS public keys, hashed using SHA2-384. <br> **q:** Leaf of the Merkle tree where the OTS public key appears (4 bytes) <br> **ots:** Lmots Signature (1252 bytes) <br> **tree_type:** Lms Algorithm Type (4 bytes) <br> **tree_path:** Path through the tree from the leaf associated with the LM-OTS signature to the root. (360 bytes) <br> Note: If LMS validation is not required, this should field should be zeroed out.|

- ### **Image Metadata Entry**
| Field | Size (bytes) | Description|
|-------|--------|------------|
| Image Hash | 48 | SHA2-384 hash of a SOC image |
| Image Source | 4 | <TBD> |

- ### **Image Metadata Collection**
The Image Metadata Collection (IMC) is a collection of Image Metadata entries (IME). Each IME has a hash that matches a SOC images. The manifest vendor and owner private keys sign the IMC. The Preamble holds the IMC signatures. The manifest IMC vendor signatures are optional and are validated only if the FLAGS field Bit 0 = 1. Up to sixteen image hashes are supported.

| Field | Size (bytes) | Description|
|-------|--------|------------|
| Revision | 4 | Version of the IMC structure |
| Reserved | 4 | Reserved |
| Image Metadata Entry (IME) Count | 4 | Number of IME(s) in the IMC |
| Image Metadata Entry (N) | Variable | List of Image Metadata Entry structures |