## SOC Manifest

The Caliptra SOC manifest has two main components: [Preamble](#preamble) and [Image Metadata Collection](#image-metadata-collection)

### **Preamble**

  The Preamble section contains the authorization manifest **ECC** and **PQC (LMS or MLDSA)** public keys of the vendor and the owner.
  These public keys correspond to the private keys that sign the [Image Metadata Collection (IMC)](#image-metadata-collection) section.
  Those signatures are also stored in the Preamble.
  The Caliptra firmware's ECC and PQC private keys endorse the manifest's public keys, and these endorsements (signatures) are part of the Preamble as well.

  *Note: All fields are little endian unless specified*

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
Each IME has a hash that matches a SOC image.
The manifest vendor and owner private keys sign the IMC.
The Preamble holds the IMC signatures.
The manifest IMC vendor signatures are optional and are validated only if the **Flags Bit 0 = 1**.
Up to 127 image hashes are supported.

| Field                            | Size (bytes) | Description                             |
| -------------------------------- | ------------ | --------------------------------------- |
| **Image Metadata Entry (IME) Count** | 4        | Number of IME(s) in the IMC.            |
| **Image Metadata Entry (N)**     | Variable     | List of Image Metadata Entry structures |
#### **Image Metadata Entry**

| Field                   | Size (bytes) | Description |
| ----------------------- | ------------ | ----------- |
| **Image Hash**          | 48           | SHA2-384 hash of a SOC image. |
| **Image Identifier**    | 4            | Unique value selected by the vendor to distinguish between images. |
| **Component Id**        | 4            | Identifies the image component to be loaded. This corresponds to the `ComponentIdentifier` field defined in the DMTF PLDM Firmware Update Specification (DSP0267). |
| **Flags**               | 4            | Image-specific flags.<br/>**Bit 0:** If set, the image hash will **not** be verified; otherwise, the metadata image hash will be compared against the calculated hash of the image.<br/>**Bit 1:** If set, indicates that the image is an MCU Runtime image; otherwise, it indicates a SOC image.<br/>**Bits 8–14:** Firmware execution control bit mapped to this image.<br/>Other bits: reserved. |
| **Image Load Address High** | 4       | High 4 bytes of the 64-bit AXI address where the image will be loaded for verification and execution. |
| **Image Load Address Low**  | 4       | Low 4 bytes of the 64-bit AXI address where the image will be loaded for verification and execution. |
| **Staging Address High**   | 4       | High 4 bytes of the 64-bit AXI address where the image will be temporarily written during firmware update download and verification. |
| **Staging Address Low**    | 4       | Low 4 bytes of the 64-bit AXI address where the image will be temporarily written during firmware update download and verification. |
