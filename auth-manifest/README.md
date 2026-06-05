## SOC Manifest

The Caliptra SOC manifest has two main components: [Preamble](#preamble) and [Image Metadata Collection](#image-metadata-collection)

### **Preamble**

  The Preamble section contains the authorization manifest **ECC** and **PQC (LMS or MLDSA)** public keys of the vendor and the owner.
  These public keys correspond to the private keys that sign the [Image Metadata Collection (IMC)](#image-metadata-collection) section.
  Those signatures are also stored in the Preamble.
  The Caliptra firmware's ECC and PQC private keys endorse the manifest's public keys, and these endorsements (signatures) are part of the Preamble as well.

  *Note: Do not treat the entire manifest as little endian. Scalar `u32` fields use little-endian layout. ECC key and signature fields are stored as big-endian `u32` words. Raw byte-array fields, such as image hashes, use the exact byte sequence produced by standard tools like OpenSSL unless a field description explicitly says otherwise.*

| Field                              | Size (bytes) | Description |
| ---------------------------------- | ------------ | ----------- |
| **Manifest Marker**                | 4            | Magic number marking the start of the manifest. The value must be `0x324D5441` (`'ATM2'` in ASCII). |
| **Manifest Size**                  | 4            | Size of the full manifest structure in bytes. |
| **Version**                        | 4            | Manifest version. The current version is `0x00000002`. |
| **SVN**                            | 4            | Security Version Number used for anti-rollback. The maximum value is vendor-defined and is limited by the maximum size of the Caliptra fuse allocated for anti-rollback. |
| **Flags**                          | 4            | Manifest feature flags.<br/>**Bit 0** – Vendor Signature Required. If set, the vendor public keys (ECC and PQC) will be used to verify signatures signed with the vendor private keys. If clear, vendor signatures are not used for verification.<br/>**Bits 1–31** – Reserved. |
| **Vendor ECC Public Key**         | 96           | Vendor ECC P-384 public key used to verify the IMC signature and endorse PQC keys.<br/>**X-Coordinate:** 48 bytes<br/>**Y-Coordinate:** 48 bytes. |
| **Vendor PQC Public Key (LMS or MLDSA)** | 2592         | Vendor **PQC** public key used to verify the IMC signature and to endorse the vendor measurement keys.<br/>This field is sized to support **MLDSA87** (2592-byte public key).<br/>When:<br/>• **MLDSA87** is used, the field holds the full 2592-byte MLDSA87 public key.<br/>• **LMS** (e.g., LMS-SHA192-H15) is used, the LMS public key (e.g., 48 bytes) is stored at the beginning of the field and the remaining bytes **must be zeroed**. |
| **Vendor ECC Signature**          | 96           | Vendor ECDSA P-384 signature over the Preamble fields that are covered by policy, typically including Version, SVN, Flags, and vendor ECC/PQC public keys, hashed using SHA2-384.<br/>**R-Coordinate:** 48 bytes<br/>**S-Coordinate:** 48 bytes. |
| **Vendor PQC Signature (LMS or MLDSA)** | 4628         | Vendor PQC signature over the same Preamble fields as the ECC signature.<br/>This field is sized to support the **MLDSA87** signature (4628 bytes).<br/>When:<br/>• **MLDSA87** is used, the entire field holds the MLDSA87 signature (per FIPS-204 definition, up to 4628 bytes).<br/>• **LMS** (e.g., LMS-SHA192-H15 / LMOTS-SHA192-W4) is used, the LMS signature (e.g., ~1620 bytes) is stored at the beginning and the remaining bytes **must be zeroed**.<br/>If PQC validation is not required, this field **must be zeroed**. |
| **Owner ECC Public Key**          | 96           | Owner ECC P-384 public key used to verify the IMC signature and endorse PQC keys on behalf of the platform owner.<br/>**X-Coordinate:** 48 bytes<br/>**Y-Coordinate:** 48 bytes. |
| **Owner PQC Public Key (LMS or MLDSA)** | 2592         | Owner **PQC** public key used to verify the IMC signature and to endorse owner measurement keys.<br/>Same encoding rules as **Vendor PQC Public Key (LMS or MLDSA)**: MLDSA87 fills the field; LMS occupies the beginning and zero-pads the rest. |
| **Owner ECC Signature**           | 96           | Owner ECDSA P-384 signature over the Preamble fields that are covered by policy for the owner (Version, SVN, Flags, owner ECC/PQC keys, etc.), hashed using SHA2-384.<br/>**R-Coordinate:** 48 bytes<br/>**S-Coordinate:** 48 bytes. |
| **Owner PQC Signature (LMS or MLDSA)**  | 4628         | Owner PQC signature over the same Preamble fields as the Owner ECC signature.<br/>Same layout rules as **Vendor PQC Signature (LMS or MLDSA)** (MLDSA87 uses full field; LMS uses prefix + zero padding).<br/>If PQC validation is not required, this field **must be zeroed**. |
| **IMC Vendor ECC Signature**      | 96           | Vendor ECDSA P-384 signature over the **Image Metadata Collection (IMC)**, hashed using SHA2-384.<br/>**R-Coordinate:** 48 bytes<br/>**S-Coordinate:** 48 bytes. |
| **IMC Vendor PQC Signature (LMS or MLDSA)** | 4628         | Vendor PQC signature over the **IMC**.<br/>Uses the same encoding as **Vendor PQC Signature (LMS or MLDSA)**, but the signed message is the serialized IMC instead of the Preamble.<br/>If PQC validation is not required, this field **must be zeroed**. |
| **IMC Owner ECC Signature**       | 96           | Owner ECDSA P-384 signature over the **IMC**, hashed using SHA2-384.<br/>**R-Coordinate:** 48 bytes<br/>**S-Coordinate:** 48 bytes. |
| **IMC Owner PQC Signature (LMS or MLDSA)** | 4628         | Owner PQC signature over the **IMC**.<br/>Same encoding rules as the other PQC signature fields (LMS or MLDSA; unused bytes zero-padded).<br/>If PQC validation is not required, this field **must be zeroed**. |

### **Image Metadata Collection**

The Image Metadata Collection (IMC) is a collection of Image Metadata Entries (IMEs).
Each IME has a digest that matches a SOC image.
The manifest vendor and owner private keys sign the IMC.
The Preamble holds the IMC signatures.
The manifest IMC vendor signatures are optional and are validated only if the **Flags Bit 0 = 1**.
Up to 127 image metadata entries are supported.

| Field                            | Size (bytes) | Description                             |
| -------------------------------- | ------------ | --------------------------------------- |
| **Image Metadata Entry (IME) Count** | 4        | Number of IME(s) in the IMC.            |
| **Image Metadata Entry (N)**     | Variable     | List of 80-byte Image Metadata Entry structures |
#### **Image Metadata Entry**

The serialized IME layout follows `AuthManifestImageMetadata` in
`auth-manifest/types/src/lib.rs`. Multi-word addresses are encoded as the low
32-bit word followed by the high 32-bit word.

| Field                   | Size (bytes) | Description |
| ----------------------- | ------------ | ----------- |
| **Firmware ID (`fw_id`)** | 4           | Unique value selected by the vendor to distinguish between firmware images. |
| **Component ID (`component_id`)** | 4   | Identifies the image component to be loaded. This corresponds to the `ComponentIdentifier` field defined in the DMTF PLDM Firmware Update Specification (DSP0267). |
| **Classification (`classification`)** | 4 | Component classification value associated with the image. |
| **Flags (`flags`)**     | 4            | Image-specific flags.<br/>**Bits 1:0:** Image source.<br/>**Bit 2:** If set, the image digest will **not** be verified; otherwise, the metadata image digest will be compared against the calculated digest of the image.<br/>**Bits 8–14:** Firmware execution control bit mapped to this image.<br/>Other bits: reserved. |
| **Image Load Address Low (`image_load_address.lo`)** | 4 | Low 4 bytes of the 64-bit AXI address where the image will be loaded for verification and execution. |
| **Image Load Address High (`image_load_address.hi`)** | 4 | High 4 bytes of the 64-bit AXI address where the image will be loaded for verification and execution. |
| **Image Staging Address Low (`image_staging_address.lo`)** | 4 | Low 4 bytes of the 64-bit AXI address where the image will be temporarily written during firmware update download and verification. |
| **Image Staging Address High (`image_staging_address.hi`)** | 4 | High 4 bytes of the 64-bit AXI address where the image will be temporarily written during firmware update download and verification. |
| **Image Digest (`digest`)** | 48       | SHA2-384 digest of the SOC image. |

## Owner Authorization Manifest

The owner authorization manifest is a smaller owner-only manifest loaded with
`SET_OWNER_AUTH_MANIFEST`. It carries owner public keys, owner signatures, and an
owner-only Image Metadata Collection. Runtime stores these entries separately
from the vendor + owner collection loaded by `SET_AUTH_MANIFEST`.

Generate one with the authorization manifest app:

```bash
cargo run -p caliptra-auth-manifest-app -- create-owner-auth-man \
  --version 1 \
  --svn 0 \
  --flags 0 \
  --pqc-key-type 3 \
  --key-dir path/to/key-files \
  --config auth-manifest/app/src/auth-man.toml \
  --out owner-auth-man.bin
```

The command uses `owner_fw_key_config`, `owner_man_key_config`, and
`image_metadata_list` from the TOML configuration. Vendor key sections are ignored
for owner-only manifest generation. `--flags` uses `OwnerAuthManifestFlags`; bit 0
sets `APPEND_IMAGE_METADATA`.
