
# Caliptra - ROM Specification v2.0

*Spec Version: 1.0*

## Scope

Caliptra is an open-source Hardware Root of Trust for Measurement (RTM). This document is the architecture specification
for Caliptra Read Only Memory Code (ROM). As an architecture specification for ROM, this document describes the
following topics:

1. Provide high level architecture
2. Describe ROM DICE Layering Architecture
3. Describe ROM functionality
4. Define ROM boot flows

   - Cold Reset Flow
   - Warm Reset Flow
   - Update Reset Flow
   - Unknown/Spurious Reset Flow

5. Cryptographic Derivations

## Spec Opens
- Describe in-memory logs

## Glossary

| Term                | Description                                                               |
| :------------------ | :------------------------------------------------------------------------ |
| CDI                 | Compound Device Identity                                                  |
| CSR                 | Certificate Signing Request                                               |
| DCCM                | Data Closely Coupled Memory                                               |
| DICE                | Device Identifier Composition Engine                                      |
| ECC                 | Elliptic Curve Cryptography                                               |
| FHT                 | Firmware Handoff Table                                                    |
| FMC                 | First Mutable Code                                                        |
| FW                  | Firmware                                                                  |
| ICCM                | Instruction Closely Coupled Memory                                        |
| IDEVID              | Initial Device ID DICE Layer                                              |
| MLDSA               | Module-Lattice-Based Digital Signature Algorithm                          |
| RoT                 | Root of Trust                                                             |
| RT                  | Runtime                                                                   |
| RTM                 | Root of Trust for Measurement                                             |
| TCI                 | Trusted Component Identifier                                              |
| UDS                 | Unique Device Secret                                                      |
| SVN                 | Security Version Number                                                   |
| X509                | Digital Certificate Standard                                              |

## Fuse and architectural registers

Following are the main FUSE & Architectural Registers used by the Caliptra ROM for DICE Derivations:

### Fuse Registers
| Register                        | Width (bits) | Description                                             |
| :------------------------------ | :------------|  :----------------------------------------------------- |
| FUSE_UDS_SEED                   | 512          | Obfuscated UDS                                          |
| FUSE_FIELD_ENTROPY              | 256          | Obfuscated Field Entropy                                |
| FUSE_VENDOR_PK_HASH             | 384          | Hash of the ECC and LMS or MLDSA Manufacturer Public Key Descriptors   |
| FUSE_ECC_REVOCATION             | 4            | Manufacturer ECC Public Key Revocation Mask             |
| FUSE_LMS_REVOCATION             | 32           | Manufacturer LMS Public Key Revocation Mask             |
| FUSE_MLDSA_REVOCATION           | 4            | Manufacturer MLDSA Public Key Revocation Mask           |
| FUSE_FIRMWARE_SVN               | 128          | Firmware Security Version Number                        |
| FUSE_ANTI_ROLLBACK_DISABLE      | 1            | Disable SVN checking for firmware when bit is set       |
| FUSE_IDEVID_CERT_ATTR           | 768          | FUSE containing information for generating IDEVID CSR  <br> **Word 0:bits[0-2]**: ECDSA X509 Key Id Algorithm (3 bits) 0: SHA1, 1: SHA256, 2: SHA384, 3: SHA512, 4: Fuse <br> **Word 0:bits[3-5]**: MLDSA X509 Key Id Algorithm (3 bits) 0: SHA1, 1: SHA256, 2: SHA384, 3: SHA512, 4: Fuse <br> **Word 1,2,3,4,5**: ECDSA Subject Key Id <br> **Word 6,7,8,9,10**: MLDSA Subject Key Id <br> **Words 11**: UEID type as defined in [IETF RATS specification](https://www.ietf.org/archive/id/draft-ietf-rats-eat-21.html#section-4.2.1.1) <br> **Words 12,13,14,15**: Manufacturer Serial Number |
| FUSE_MANUF_DEBUG_UNLOCK_TOKEN    | 512           | SHA-512 digest of secret value for manufacturing debug unlock authorization |
| FUSE_PQC_KEY_TYPE                | 2             | One-hot encoded selection of PQC key type for firmware validation. <br> **Bit 0**: MLDSA <br> **Bit 1**: LMS |

### Architectural Registers
| Register                        | Width (bits) | Description                                             |
| :------------------------------ | :------------|  :----------------------------------------------------- |
| CPTRA_OWNER_PK_HASH             | 384          | Owner ECC and LMS or MLDSA Public Key Hash              |

For a comprehensive overview of the SOC interface registers, please refer to the following link::
https://chipsalliance.github.io/caliptra-rtl/main/external-regs/?p=caliptra_top_reg.generic_and_fuse_reg

## Firmware image bundle

The Caliptra Firmware image has two main components:

- **Firmware manifest**

- **Firmware images**

The firmware manifest is a combination of preamble and a signed header. It has
public keys, public key hashes, signatures and table of contents which refer to the various
firmware images contained in the bundle.

![Firmware Image Bundle](doc/svg/fw-img-bundle.svg)

### Firmware manifest

Firmware manifest consists of preamble, header and table of contents.

#### Preamble

It is the unsigned portion of the manifest. Preamble contains the signing public keys and signatures. ROM is responsible for parsing the preamble. ROM performs the following steps:

- Loads the preamble from the mailbox.
- Calculates the hash of ECC and LMS or MLDSA [Public Key Descriptors](#Public-Key-Descriptor) in the preamble and compares it against the hash in the fuse (FUSE_VENDOR_PK_HASH). If the hashes do not match, the boot fails.
- Verifies the active Manufacturer Public Key(s) based on fuse (FUSE_ECC_REVOCATION for ECC public key, FUSE_LMS_REVOCATION for LMS public key or FUSE_MLDSA_REVOCATION for MLDSA public key)

*Note: All fields are little endian unless specified*

*Preamble*

| Field | Size (bytes) | Description|
|-------|--------|------------|
| Firmware Manifest Marker | 4 | Magic Number marking the start of the package manifest. The value must be 0x434D4E32 (‘CMN2’ in ASCII)|
| Firmware Manifest Size | 4 | Size of the full manifest structure |
| Firmware Manifest Type | 4 |  **Byte0:** - Type <br> 0x1 – ECC & MLDSA Keys <br> 0x3 – ECC & LMS Keys <br> **Byte1-Byte3:** Reserved |
| Manufacturer ECC Key Descriptor | 196 | Public Key Descriptor for ECC keys |
| Manufacturer LMS or MLDSA Key Descriptor | 1540 | Public Key Descriptor for LMS (1540 bytes) or MLDSA (196 bytes + 1344 unused bytes) keys |
| Active ECC Key Index | 4 | Public Key Hash Index for the active ECC key |
| Active ECC Key | 96 | ECC P-384 public key used to verify the Firmware Manifest Header Signature <br> **X-Coordinate:** Public Key X-Coordinate (48 bytes, big endian) <br> **Y-Coordinate:** Public Key Y-Coordinate (48 bytes, big endian) |
| Active LMS or MLDSA Key Index | 4 | Public Key Hash Index for the active LMS or MLDSA key |
| Active LMS or MLDSA Key | 2592 | LMS public key (48 bytes + 2544 unused bytes) used to verify the Firmware Manifest Header Signature. <br> **tree_type:** LMS Algorithm Type (4 bytes, big endian) Must equal 12. <br> **otstype:** LM-OTS Algorithm Type (4 bytes, big endian) Must equal 7. <br> **id:**  (16 bytes) <br> **digest:**  (24 bytes) <br><br>**OR**<br><br>MLDSA-87 public key used to verify the Firmware Manifest Header Signature. <br> (2592 bytes, little endian)|
| Manufacturer ECC Signature | 96 | Manufacturer ECC P-384 signature of the Firmware Manifest header hashed using SHA2-384. <br> **R-Coordinate:** Random Point (48 bytes) <br> **S-Coordinate:** Proof (48 bytes) |
| Manufacturer LMS or MLDSA Signature | 4628 | Manufacturer LMS signature (1620 bytes + 3008 unused bytes) of the Firmware Manifest header hashed using SHA2-384. <br> **q:** Leaf of the Merkle tree where the OTS public key appears (4 bytes) <br> **ots:** Lmots Signature (1252 bytes) <br> **tree_type:** Lms Algorithm Type (4 bytes) <br> **tree_path:** Path through the tree from the leaf associated with the LM-OTS signature to the root. (360 bytes) <br><br>**OR**<br><br> Vendor MLDSA-87 signature of the Firmware Manifest header hashed using SHA2-512 (4627 bytes + 1 Reserved byte, little endian)|
| Owner ECC Public Key | 96 | ECC P-384 public key used to verify the Firmware Manifest Header Signature. <br> **X-Coordinate:** Public Key X-Coordinate (48 bytes) <br> **Y-Coordinate:** Public Key Y-Coordinate (48 bytes)|
| Owner LMS or MLDSA Public Key | 2592 | LMS public key (48 bytes + 2544 unused bytes) used to verify the Firmware Manifest Header Signature. <br> **tree_type:** LMS Algorithm Type (4 bytes) <br> **otstype:** LMS Ots Algorithm Type (4 bytes) <br> **id:**  (16 bytes) <br> **digest:**  (24 bytes) <br><br>**OR**<br><br>MLDSA-87 public key used to verify the Firmware Manifest Header Signature. <br> (2592 bytes, little endian)|
| Owner ECC Signature | 96 | Manufacturer ECC P-384 signature of the Firmware Manifest header hashed using SHA2-384. <br> **R-Coordinate:** Random Point (48 bytes) <br> **S-Coordinate:** Proof (48 bytes) |
| Owner LMS or MLDSA Signature | 4628 | Owner LMS signature (1620 bytes + 3008 unused bytes) of the Firmware Manifest header hashed using SHA2-384. <br> **q:** Leaf of the Merkle tree where the OTS public key appears (4 bytes) <br> **ots:** Lmots Signature (1252 bytes) <br> **tree_type:** Lms Algorithm Type (4 bytes) <br> **tree_path:** Path through the tree from the leaf associated with the LM-OTS signature to the root. (360 bytes) <br><br>**OR**<br><br> Owner MLDSA-87 signature of the Firmware Manifest header hashed using SHA2-512 (4627 bytes + 1 Reserved byte, little endian) |
| Reserved | 8 | Reserved 8 bytes |
<br>

#### ECC Manufacturer Public Key Descriptor

| Field | Size (bytes) | Description|
|-------|--------|------------|
| Key Descriptor Version | 2 | Version of the Key Descriptor. The value must be 0x1 for Caliptra 2.x |
| Reserved | 1 | Reserved  |
| Key Hash Count | 1 | Number of valid public key hashes  |
| Public Key Hash(es) | 48 * n | List of valid and invalid (if any) SHA2-384 public key hashes. ECDSA: n = 4 |

#### PQC Manufacturer Public Key Descriptor

| Field | Size (bytes) | Description|
|-------|--------|------------|
| Key Descriptor Version | 2 | Version of the Key Descriptor. The value must be 0x1 for Caliptra 2.x |
| Key Type | 1 | Type of the key in the descriptor <br>  0x1 - MLDSA <br> 0x3 - LMS |
| Key Hash Count | 1 | Number of valid public key hashes  |
| Public Key Hash(es) | 48 * n | List of valid and invalid (if any) SHA2-384 public key hashes. LMS: n = 32, MLDSA: n = 4 |

#### Header

The header contains the security version and SHA2-384 hash of the table of contents. Header is the only signed component in the image. Signing the header is enough as the table of contents contains the hashes of the individual firmware images. This technique reduces the number of signature verifications required to be performed during boot.

| Field | Size (bytes) | Description|
|-------|--------|------------|
| Revision | 8 | 8-byte version of the firmware image bundle |
| Vendor ECC public key hash index | 4 | The hint to ROM to indicate which ECC public key hash it should use to validate the active ECC public key. |
| Vendor LMS or MLDSA public key hash index | 4 | The hint to ROM to indicate which LMS or MLDSA public key hash it should use to validate the active public key. |
| Flags | 4 | Feature flags. <br> **Bit0:** - Interpret the pl0_pauser field. If not set, all PAUSERs are PL1 <br>**Bit1-Bit31:** Reserved |
| TOC Entry Count | 4 | Number of entries in TOC. |
| PL0 PAUSER | 4 | The PAUSER with PL0 privileges. |
| TOC Digest | 48 | SHA2-384 Digest of table of contents. |
| Vendor Data | 40 | Vendor Data. <br> **Not Before:** Vendor Start Date [ASN1 Time Format] For Alias FMC and Alias RT certificates (15 bytes) <br> **Not After:** Vendor End Date [ASN1 Time Format] For Alias FMC and Alias RT certificates (15 bytes) <br> **Reserved:** (10 bytes) |
| Owner Data | 40 | Owner Data. <br> **Not Before:** Owner Start Date [ASN1 Time Format] For Alias FMC and Alias RT certificates. Takes preference over vendor start date (15 bytes) <br> **Not After:** Owner End Date [ASN1 Time Format] For Alias FMC and Alias RT certificates. Takes preference over vendor end date (15 bytes) <br> **Reserved:** (10 bytes) |

#### Table of contents

It contains the image information and SHA-384 hash of individual firmware images.
| Field | Size (bytes) | Description|
|-------|--------|------------|
| TOC Entry Id | 4 | TOC Entry Id. The fields can have following values: <br> **0x0000_0001:** FMC  <br> **0x0000_0002:** Runtime |
| Image Type | 4 | Image Type that defines format of the image section <br> **0x0000_0001:** Executable |
| Image Revision | 20 | Git Commit hash of the build |
| Image Version | 4 | Firmware release number |
| Image SVN | 4 | Security Version Number for the image. It is compared to FW SVN fuses. FMC TOC entry's SVN field is ignored. |
| Reserved | 4 | Reserved field |
| Image Load Address | 4 | Load address |
| Image Entry Point | 4 | Entry point to start the execution from  |
| Image Offset | 4 | Offset from beginning of the image |
| Image Size | 4 | Image Size |
| Image Hash | 48 | SHA2-384 hash of image |

### Image

| Field | Size (bytes) | Description   |
|-------|--------------|---------------|
| Data  | N            | Image content |

## Cryptographic primitives

The following sections define the various cryptographic primitives used by Caliptra ROM:
| Group | Operation |Description |
|-------|--------|------------|
| Deobfuscation Engine | `doe_decrypt_uds(kv_slot, iv)` | Decrypt UDS to the specified key vault slot with specified initialization vector<br>**Input**:<br> ***kv_slot*** - key vault slot to decrypt the uds to<br>***iv*** - initialization vector |
|   | `doe_decrypt_fe(kv_slot, iv)` | Decrypt Field Entropy to the specified key vault slot with specified initialization vector <br>**Input**:<br>***kv_slot*** - key vault slot to decrypt the field entropy to<br>***iv*** - initialization vector |
|   | `doe_clear_secrets()` | Clear UDS Fuse Register, Field Entropy Fuse Register and Obfuscation key |
| Hashed Message Authentication Code | `hmac_mac(key,data,mac_kv_slot,mode)` | Calculate the MAC using a caller provided key and data. The resultant MAC is stored in key vault slot<br>**Input**:<br>***key*** - caller specified key<br>data - data<br>***mac_kv_slot*** - key vault slot to store the MAC to<br>***mode*** - HMAC384 or HMAC512 |
|   | `hmac_mac(kv_slot,data,mac_kv_slot)` | Calculate the MAC using a caller provided key and data. The resultant MAC is stored in key vault slot <br>**Input**: <br>***kv_slot*** - key vault slot to use the key from<br>***data*** - data<br>***mac_kv_slot*** - key vault slot to store the MAC to<br>***mode*** - HMAC384 or HMAC512 |
| | `hmac512_mac(key,data,mac_kv_slot)` | Calculate the MAC using a caller provided key and data. The resultant MAC is stored in key vault slot<br>**Input**:<br>***key*** - caller specified key<br>data - data<br>***mac_kv_slot*** - key vault slot to store the MAC to |
|   | `hmac512_mac(kv_slot,data,mac_kv_slot)` | Calculate the MAC using a caller provided key and data. The resultant MAC is stored in key vault slot <br>**Input**: <br>***kv_slot*** - key vault slot to use the key from<br>***data*** - data<br>***mac_kv_slot*** - key vault slot to store the MAC to |
| Elliptic Curve Cryptography | `ecc384_keygen(seed_kv_slot, priv_kv_slot) -> pub_key` | Generate ECC384 Key Pair.<br>**Input**:<br>***seed_key_slot*** - key vault slot to use as seed for key generation<br>***priv_kv_slot*** - key vault slot to store the private key to<br>**Output**:<br>***pub-key*** - public key associated with the private key |
|   | `ecc384_sign(priv_kv_slot, data) -> sig` | ECC384 signing operation<br>**Input**:<br>***priv_kv_slot*** - key vault slot to use a private key from<br>***data*** - data to sign<br>**Output**:<br>***sig*** - signature |
| | `ecc384_verify(pub_key, data, sig) -> CaliptraResult<Array4xN<12, 48>>` | ECC384 verify operation<br>**Input**:<br>***pub-key*** -public key<br>data - data to verify<br>sig - signature<br>**Output**:<br>***Ecc384Result*** - verify.r value on success, else an error |
| Module-Lattice-Based Digital Signature Algorithm | `mldsa87_keygen(seed_kv_slot) -> pub_key` | Generate Mldsa87 Key Pair.<br>**Input**:<br>***seed_key_slot*** - key vault slot to use as seed for key generation<br>**Output**:<br>***pub-key*** - public key associated with the private key |
|   | `mldsa87_sign(seed_kv_slot, data) -> sig` | Mldsa87 signing operation<br>**Input**:<br>***seed_kv_slot*** - key vault slot to use as seed for key generation for signing<br>***data*** - data to sign<br>**Output**:<br>***sig*** - signature |
| | `mldsa87_verify(pub_key, data, sig) -> Mldsa87Result` | Mldsa87 verify operation<br>**Input**:<br>***pub-key*** -public key<br>data - data to verify<br>sig - signature<br>**Output**:<br>***Mldsa87Result*** - '0xAAAAAAAA' value on success, '0x55555555' on error |
| Secure Hash Algorithm | `sha384_digest(data) -> digest` | Calculate the digest of the data<br>**Input**:<br>***data*** - data to verify<br>**Output**:<br>***digest*** - digest of the data |
| Key Vault | `kv_clear(kv_slot)` | Key Vault slot to clear<br>**Input**:<br>***kv_slot*** - key vault slot to clear |
| Data Vault | `dv48_store(data, dv_slot)` | Store the 48-byte data in the specified data vault slot<br>**Input**:<br>***data*** - data to store<br>***dv_slot*** - data vault slot |
| | `dv48_lock_wr(dv_slot)` | Write Lock the 48-byte data vault slot<br>Input<br>***dv_slot*** - data vault slot |
| | `dv4_store(data, dv_slot)` | Store the 4- byte data in the specified data vault slot<br>Input<br>***data*** - data to store<br>***dv_slot*** - data vault slot |
| | `dv4_lock_wr(dv_slot)` | Write Lock the 4-byte data vault slot<br>Input<br>***dv_slot*** - data vault slot |
| Platform Configuration Registers | `pcr_extend(pcr_slot, data)` | Perform PCR extend operation on a PCR with specified data<br>**Input**:<br>***pcr_slot*** - PCR slot to hash extend<br>***data*** – data |
| | `pcr_read(pcr_slot) -> measurement` | Read the PCR slot<br>**Input**:<br>***pcr_slot*** - PCR slot to read<br>**Output**:<br>***measurement*** - Accumulated measurement |
| | `pcr_lock_clear(pcr_slot)` | Lock for Clear PCR slot<br>**Input**:<br>***pcr_slot*** - pcr slot |
| | `pcr_clear(pcr_slot)` | Clear PCR slot<br>**Input**:<br>***pcr_slot*** - pcr slot |
| X509 | `gen_tbs(type, pub_key) -> tbs` | Generate X509 Certificate or CSR `To Be Signed` portion<br>**Input**:<br>***type*** - Can be IDEVID_CSR, LDEVID_CERT or ALIAS_FMC_CERT<br>pub-key -public key<br>**Output**:<br>***tbs*** - DER encoded `To Be Signed` portion |
<br>

## Well known cryptographic constants

| Constant | Size (bytes) | Description |
|----------|--------------|-------------|
| DOE_IV | 16 | Initialization vector specified by the ROM for deobfuscating the UDS and Field Entropy. |
<br>

## Cold reset flow

![COLD RESET](doc/svg/cold-reset.svg)

ROM performs all the necessary crypto derivations on cold reset. No crypto derivations are performed during warm reset or update reset.

Note that KvSlot3 is generally used as a temporary location for derived keying material during ECC keygen.

### Initialization

The initialization step involves a traditional startup script for microcontroller. The initialization script performs following:

- Resets instruction counter
- Disables interrupts
- Clears all general purpose registers
- Sets up memory region attributes (Cacheable & Side effects)
- Sets up stack pointer
- Sets up NMI and Exception handler
- Zeros ICCM & DCCM memories (to initialize ECC)
- Jumps to Rust entry point

The following flows are conducted exclusively when the ROM is operating in SUBSYSTEM mode.

### Manufacturing Flows:
The following flows are conducted when the ROM is operating in the manufacturing mode, indicated by a value of `DEVICE_MANUFACTURING` (0x1) in the `CPTRA_SECURITY_STATE` register `device_lifecycle` bits.

#### UDS Provisioning
1. On reset, the ROM checks if the `UDS_PROGRAM_REQ` bit in the `SS_DBG_MANUF_SERVICE_REG_REQ` register is set. If the bit is set, ROM initiates the UDS seed programming flow by setting the `UDS_PROGRAM_IN_PROGRESS` bit in the `SS_DBG_MANUF_SERVICE_REG_RSP` register. If the flow fails at some point past reading the REQ bits, the flow will be aborted and an error returned.

2. ROM then retrieves the following values:
    - A 512-bit value from the iTRNG.
    - The UDS Seed programming base address from the `SS_UDS_SEED_BASE_ADDR_L` and `SS_UDS_SEED_BASE_ADDR_H` registers.
    - The Fuse Controller's base address from the `SS_OTP_FC_BASE_ADDR_L` and `SS_OTP_FC_BASE_ADDR_H` registers.

3. ROM then retrieves the UDS granularity from the `CPTRA_GENERIC_INPUT_WIRES` register0 Bit31 to learn if the fuse row is accessible with 32-bit or 64-bit granularity.  If the bit is reset, it indicates 64-bit granularity; otherwise, it indicates 32-bit granularity.

4. ROM computes the following values:
    - DAI_IDLE bit offset: (`SS_STRAP_GENERIC` register0 >> 16) & 0xFFFF
    - `DIRECT_ACCESS_CMD` offset: (`SS_STRAP_GENERIC` register1) & 0xFFFF + Fuse Controller's base address.

4. ROM then performs the following steps until all the 512 bits of the UDS seed are programmed:
    1. The ROM verifies the idle state of the DAI by reading the `STATUS` register `DAI_IDLE` bit (offset retrieved above) of the Fuse Controller, located at offset 0x10 from the Fuse Controller's base address.
    2. If the granularity is 32-bit, the ROM writes the next word from the UDS seed to the `DIRECT_ACCESS_WDATA_0` register. If the granularity is 64-bit, the ROM writes the next two words to `the DIRECT_ACCESS_WDATA_0` and `DIRECT_ACCESS_WDATA_1` registers, located at offsets 0x8 and 0xC respectively from the `DIRECT_ACCESS_CMD` register.
    3. The ROM writes the lower 32 bits of the UDS Seed programming base address to the `DIRECT_ACCESS_ADDRESS` register, located at offset 0x4 from the `DIRECT_ACCESS_CMD` register.
    4. The ROM triggers the UDS seed write command by writing 0x2 to the `DIRECT_ACCESS_CMD` register..
    5. The ROM increments the `DIRECT_ACCESS_ADDRESS` register by 4 for 32-bit granularity or 8 for 64-bit granularity and repeats the process for the remaining words of the UDS seed.

5. The ROM continuously polls the Fuse Controller's `STATUS` register until the DAI state returns to idle.

6. After completing the write operation, ROM triggers the partition  digest operation performing the following steps:
    1. The ROM writes the lower 32 bits of the UDS Seed programming base address to the `DIRECT_ACCESS_ADDRESS` register.
    2. The ROM triggers the digest calculation command by writing 0x4 to the `DIRECT_ACCESS_CMD` register.
    3. The ROM continuously polls the Fuse Controller's `STATUS` register until the DAI state returns to idle.

7. ROM updates the `UDS_PROGRAM_SUCCESS` or the `UDS_PROGRAM_FAIL` bit in the `SS_DBG_MANUF_SERVICE_REG_RSP` register to indicate the outcome of the operation.

8. ROM then resets the `UDS_PROGRAM_IN_PROGRESS` bit in the `SS_DBG_MANUF_SERVICE_REG_RSP` register to indicate completion of the programming.

9. The manufacturing process then polls this bit and continues with the fuse burning flow as outlined by the fuse controller specifications and SOC-specific VR methodologies.

#### Debug Unlock

**Note:** All mailbox command requests start with a 4-byte `MailboxReqHeader` (containing a checksum field), while response payloads start with an 8-byte `MailboxRespHeader` (containing checksum and FIPS status fields).

1. On reset, the ROM checks if the `MANUF_DBG_UNLOCK_REQ` bit in the `SS_DBG_MANUF_SERVICE_REG_REQ` register and the `DEBUG_INTENT` bit in `SS_DEBUG_INTENT` register are set.

2. If they are set, the ROM sets the `TAP_MAILBOX_AVAILABLE` & `MANUF_DBG_UNLOCK_IN_PROGRESS` bits in the `SS_DBG_MANUF_SERVICE_REG_RSP` register, then enters a loop, awaiting a `TOKEN` command on the mailbox. The payload of this command is a 256-bit value.

3. The ROM performs a SHA-512 operation on the token to generate the input token digest.

4. The ROM compares the `FUSE_MANUF_DBG_UNLOCK_TOKEN` fuse register with the input token digest.

5. The ROM completes the mailbox command.

6. If the input token digest and fuse token digests match, the ROM authorizes the debug unlock by setting the `SS_DBG_MANUF_SERVICE_REG_RSP` register `MANUF_DBG_UNLOCK_SUCCESS` bit to 1.

7. If the token digests do not match, the ROM blocks the debug unlock by setting the the `SS_DBG_MANUF_SERVICE_REG_RSP` register `MANUF_DBG_UNLOCK_FAIL` bit to 1.

8. The ROM sets the `SS_DBG_MANUF_SERVICE_REG_RSP` register `MANUF_DBG_UNLOCK_IN_PROGRESS` and `TAP_MAILBOX_AVAILABLE` bits to 0.


### Production Flows
The following flows are conducted when the ROM is operating in the production mode, indicated by a value of `DEVICE_PRODUCTION` (0x3) in the `CPTRA_SECURITY_STATE` register `device_lifecycle` bits.

#### Debug Unlock

**Note:** All mailbox command requests start with a 4-byte `MailboxReqHeader` (containing a checksum field), while response payloads start with an 8-byte `MailboxRespHeader` (containing checksum and FIPS status fields).

1. On reset, the ROM checks if the `PROD_DEBUG_UNLOCK_REQ` bit in the `SS_DBG_MANUF_SERVICE_REG_REQ` register and the `DEBUG_INTENT` in `SS_DEBUG_INTENT` register are set.

2. If they are set, the ROM sets the `TAP_MAILBOX_AVAILABLE` & `PROD_DBG_UNLOCK_IN_PROGRESS` bits in the `SS_DBG_MANUF_SERVICE_REG_RSP` register.

3. ROM enters a polling loop, awaiting a `AUTH_DEBUG_UNLOCK_REQ` command (Id: 0x50445552) on the mailbox. The payload for this command is of the following format:

| Field            | Size (bytes) | Description                                        |
|------------------|--------------|----------------------------------------------------|
| Length           | 4            | Length of the message in DWORDs. This should be 2. |
| Unlock Level     | 1            | Debug unlock Level (Number 1-8).                   |
| Reserved         | 3            | Reserved field.                                    |

3. On failure, ROM does the following:
      - `PROD_DBG_UNLOCK_FAIL` bit in `SS_DBG_MANUF_SERVICE_REG_RSP` register to 1.
      - `PROD_DBG_UNLOCK_IN_PROGRESS` bit in `SS_DBG_MANUF_SERVICE_REG_RSP` register to 0.

4. The ROM validates the payload and on successful validation sends the following payload as the response:

| Field                    | Size (bytes) | Description                                        |
|--------------------------|--------------|----------------------------------------------------|
| Length                   | 4            | Reserved.                                          |
| Unique Device Identifier | 32           | Device identifier of the Caliptra Device.          |
| Challenge                | 48           | Random number.                                     |

5. On failure, ROM sets the registers outlined in step 3.

6. The SOC then sends the following payload via the `AUTH_DEBUG_UNLOCK_TOKEN` mailbox command (0x50445554):

| Field                    | Size (bytes) | Description                                                                           |
|--------------------------|--------------|---------------------------------------------------------------------------------------|
| Length                   | 4            | Length of the message in DWORDs. This should be 0x753.                                |
| Unique Device Identifier | 32           | Device identifier sent in `AUTH_DEBUG_UNLOCK_CHALLENGE` mailbox command payload.      |
| Unlock Level             | 1            | Debug unlock Level (Number 1-8).                                                      |
| Reserved                 | 3            | Reserved field.                                                                       |
| Challenge                | 48           | Random number sent in `AUTH_DEBUG_UNLOCK_CHALLENGE` mailbox command payload.          |
| ECC Public Key           | 96           | ECC P-384 public key used to verify the Message Signature <br> **X-Coordinate:** Public Key X-Coordinate (48 bytes, big endian) <br> **Y-Coordinate:** Public Key Y-Coordinate (48 bytes, big endian)                         |
| MLDSA Public Key         | 2592         | MLDSA-87 public key used to verify the Message Signature.                             |
| ECC Signature            |  96          | ECC P-384 signature of the Message hashed using SHA2-384. <br> **R-Coordinate:** Random Point (48 bytes) <br> **S-Coordinate:** Proof (48 bytes).                                                                                   |
| MLDSA Signature          | 4628         | MLDSA signature of the Message hashed using SHA2-512. (4627 bytes + 1 Reserved byte). |

7. On receiving this payload, ROM performs the following validations:
    - Ensures the value in the `Length` field matches the size of the payload.
    - Confirms that the `Debug unlock level` is not zero and does not exceed the value specified in the `SS_NUM_OF_PROD_DEBUG_UNLOCK_AUTH_PK_HASHES` register.
    - Calculates the address of the public key hash fuse as follows: <br>
        **SS_PROD_DEBUG_UNLOCK_AUTH_PK_HASH_REG_BANK_OFFSET register value + ( (Debug Unlock Level - 1) * SHA2-384 hash size (48 bytes) )**
    - Retrieves the SHA2-384 hash (48 bytes) from the calculated address using DMA assist.
    - Computes the SHA2-384 hash of the message formed by concatenating the ECC and MLDSA public keys in the payload.
    - Compares the retrieved and computed hashes. It the comparison fails, the ROM blocks the debug unlock request by setting the registers outlined in step 3.
    - Upon hash comparison failure, the ROM exits the payload validation flow and completes the mailbox command.

4. The ROM proceeds with payload validation by verifying the ECC and MLDSA signatures over the `Challenge`, `Device Identifier`, `Reserved` and `Unlock Category` fields within the payload. Should the validation fail, the ROM blocks the debug unlock by setting the registers outlined in item 3. Conversely, if the signature validation succeeds, the ROM authorizes the debug unlock by configuring the following settings:

      - `PROD_DBG_UNLOCK_SUCCESS` bit in `SS_DBG_MANUF_SERVICE_REG_RSP` register to 1.
      - Setting the Debug unlock level in the `SS_SOC_DBG_UNLOCK_LEVEL` register as one hot encoded value (1 << (Level - 1))
      - `PROD_DBG_UNLOCK_IN_PROGRESS` bit in `SS_DBG_MANUF_SERVICE_REG_RSP` register to 0.

5. ROM then completes the mailbox command with success.

6. The ROM sets the `SS_DBG_MANUF_SERVICE_REG_RSP` register `PROD_DBG_UNLOCK_IN_PROGRESS` and `TAP_MAILBOX_AVAILABLE` bits to 0.

### Known Answer Test (KAT)

To certify a cryptographic module, pre-operational self-tests must be performed when the system is booted. Implementing KATs is required for FIPS certification. However, regardless of FIPS certification, it is considered a security best practice to ensure that the supported cryptographic algorithms are functioning properly to guarantee correct security posture.

KAT execution is described as two types:

* Pre-operational Self-Test (POST)
* Conditional Algorithm Self-Test (CAST)

ROM performs the following POST tests to ensure that needed cryptographic modules are functioning correctly and are operational before any cryptographic operations are performed:

 - SHA1
 - SHA2-256
 - SHA2-384
 - SHA2-512
 - SHA2-512-ACC
 - ECC-384
 - ECDH
 - HMAC-384Kdf
 - HMAC-512Kdf
 - HKDF-384
 - HKDF-512
 - KDF-CMAC
 - LMS
 - MLDSA-87
 - AES-256-ECB
 - AES-256-CBC
 - AES-256-CMAC
 - AES-256-CTR
 - AES-256-GCM

### DICE Flow

![DICE Flow](doc/svg/dice-diagram.svg)

### Decrypt secrets

DICE Unique Device Secret (UDS) is stored in an SOC backed fuse (or derived from PUF). The raw UDS is not directly used. UDS is deobfuscated using Deobfuscation Engine. UDS is provisioned by the Silicon Vendor.

Field Entropy is used to mitigate certain classes of supply chain attacks.  Field Entropy is programmed by the owner of the device in a secure environment in the owner’s facility. Field Entropy programmed in fuses is not directly used. Field Entropy is put through the deobfuscation engine to randomize it.

Both UDS and Field Entropy are available only during cold reset of Caliptra.

**Pre-conditions:**

- Caliptra subsystem is being cold reset
- Obfuscation Key loaded in deobfuscation engine
- UDS and Field Entropy loaded in Caliptra Fuse Registers
- Keys Slot 0 - 23 are empty and Usage Bits are all cleared
- PCR 0 - 31 are all cleared
- DCCM datavault is cleared

**Actions:**

1. Decrypt UDS to Key Vault Slot 0

    `doe_decrypt_uds(KvSlot0, DOE_IV)`

2. Decrypt Field Entropy to Key Vault Slot 1

    `doe_decrypt_fe(KvSlot1, DOE_IV)`

3. Clear class secrets (Clears UDS, Field Entropy and Obfuscation Key cleared)

    `doe_clear_secrets()`

**Post-conditions:**

- UDS Fuse Register and Field Entropy Fuse register cleared
- Obfuscation Key cleared from Deobfuscation Engine
- Vault State is as follows:

| Slot | Key Vault                |
|------|-----------------------   |
| 0    | UDS (64 bytes)           |
| 1    | Field Entropy (32 bytes) |

### Initial Device ID DICE layer

Initial Device ID Layer is used to generate Manufacturer CDI & Private Keys. This layer represents the manufacturer or silicon vendor DICE Identity. During manufacturing, ROM can be requested to create Certificate Signing Request (CSR) via JTAG.

**Pre-conditions:**

- UDS is in Key Vault Slot 0

**Actions:**

1. Derive the CDI using ROM specified label and UDS in Key Vault Slot 0 as data and store the resultant MAC in Key Vault Slot 6.

    `hmac512_kdf(KvSlot0, b"idevid_cdi", KvSlot6)`

2. Clear the UDS in the key vault.

    `kv_clear(KvSlot0)`

3. Derive ECC Key Pair using CDI in Key Vault Slot 6 and store the generated private key in Key Vault Slot 7.

    `IDevIDSeedEcdsa = hmac512_kdf(KvSlot6, b"idevid_ecc_key", KvSlot3)`

    `IDevIdPubKeyEcdsa = ecc384_keygen(KvSlot3, KvSlot7)`

    `kv_clear(KvSlot3)`

    Derive the MLDSA Key Pair using CDI in Key Vault Slot 6 and store the key generation seed in Key Vault Slot 8.

    `IDevIDSeedMldsa = hmac512_kdf(KvSlot6, b"idevid_mldsa_key", KvSlot8)`

    `IDevIdPubKeyMldsa = mldsa87_keygen(KvSlot8)`

*(Note: Steps 4-12 are performed if CSR download is requested via CPTRA_DBG_MANUF_SERVICE_REG register)*

4. Generate the `To Be Signed` DER Blob of the IDevId CSR with the ECDSA public key.

    `IDevIdTbsEcdsa = gen_tbs(IDEVID_CSR, IDevIdPubKeyEcdsa)`

5. Sign the IDevID `To Be Signed` DER Blob with IDevId ECDSA Private Key in Key Vault Slot 7.

    `IDevIdTbsDigestEcdsa = sha384_digest(IDevIdTbsEcdsa)`

    `IDevIdCertSigEcdsa = ecc384_sign(KvSlot7, IDevIdTbsDigestEcdsa)`

6. Verify the signature of IDevID `To Be Signed` Blob.

    `Result = ecc384_verify(IDevIdPubKeyEcdsa, IDevIdTbsDigestEcdsa, IDevIdCertSigEcdsa)`

7. Generate the `To Be Signed` DER Blob of the IDevId CSR with the MLDSA public key.

    `IDevIdTbsMldsa = gen_tbs(IDEVID_CSR, IDevIdPubKeyMldsa)`

8. Sign the IDevID `To Be Signed` DER Blob with IDevId MLDSA Private Key generated from the seed in Key Vault Slot 8.

    `IDevIdTbsDigestMldsa = sha512_digest(IDevIdTbsMldsa)`

    `IDevIdCertSigMldsa = mldsa87_sign(KvSlot8, IDevIdTbsDigestMldsa)`

9. Verify the signature of IDevID `To Be Signed` Blob.

    `Result = mldsa87_verify(IDevIdPubKeyMldsa, IDevIdTbsDigestMldsa, IDevIdCertSigMldsa)`

10. Generate the MACs over the tbs digests as follows:

    `IDevIdTbsEcdsaMac = hmac_mac(VendorSecretKvSlot, b"idevid_ecc_csr", IDevIdTbsDigestEcdsa, HmacMode::Hmac384)`

    `IDevIdTbsMldsaMac = hmac512_mac(VendorSecretKvSlot, b"idevid_mldsa_csr",IDevIdTbsDigestMldsa, HmacMode::Hmac512)`

11. Upload the CSR(s) to mailbox and wait for JTAG to read the CSR out of the mailbox. Format of the CSR payload is documented below:

#### IDevID CSR Format

*Note: All fields are little endian unless specified*

| Field          | Size (bytes) | Description                                                                                     |
|----------------|--------------|-------------------------------------------------------------------------------------------------|
| Marker         | 4            | Magic Number marking the start of the CSR payload. The value must be 0x435352 (‘CSR’ in ASCII). |
| Size           | 4            | Size of the entire CSR payload.                                                                 |
| ECC CSR Size   | 4            | Size of the ECC CSR in bytes.                                                                   |
| ECC CSR        | 512          | ECC CSR buffer. Actual CSR size is indicated by 'ECC CSR Size'.                                 |
| MLDSA CSR Size | 4            | Size of the MLDSA CSR in bytes.                                                                 |
| MLDSA CSR      | 7680         | MLDSA CSR bytes. Actual CSR size is indicated by 'MLDSA CSR Size'.                              |
| CSR MAC        | 64           | HMAC-512 MAC, computed over the envelope bytes up to but not including this field.       |

**Post-conditions:**

- Vault state is as follows:

| Slot | Key Vault                             |
|------|---------------------------------------|
| 1    | Field Entropy (32 bytes)              |
| 6    | IDevID CDI (64 bytes)                 |
| 7    | IDevID ECDSA Private Key (48 bytes)   |
| 8    | IDevID MLDSA Key Pair Seed (32 bytes) |

 | DCCM Datavault                 |
 |--------------------------------|
 | 🔒IDevID Cert ECDSA Signature |
 | 🔒IDevID ECDSA Pub Key        |
 | 🔒IDevID Cert MLDSA Signature |
 | 🔒IDevID MLDSA Pub Key        |

### Local Device ID DICE layer

Local Device ID Layer derives the Owner CDI, ECC and MLDSA Keys. This layer represents the owner DICE Identity as it is mixed with the Field Entropy programmed by the Owner.

**Pre-conditions:**

- Field Entropy is loaded in Key Vault Slot 1
- IDevID CDI is stored in Key Vault Slot 6
- IDevID Private Key is stored in Key Vault Slot 7
- IDevID MLDSA Key Generation Seed is stored in Key Vault Slot 8

**Actions:**

1. Derive the stable identity root secret from IDevID and store the resultant MAC in Key Vault Slot 0.

    `hmac512_mac(KvSlot0, b"stable_identity_root_idev", KvSlot6)`

2. Derive the LDevID CDI using IDevID CDI in Key Vault Slot 6 as HMAC Key and Field Entropy stored in Key Vault Slot 1 as data. The resultant MAC is stored back in Key Vault Slot 6.

    `hmac512_mac(KvSlot6, b"ldevid_cdi", KvSlot6)`

    `hmac512_mac(KvSlot6, KvSlot1, KvSlot6)`

*(Note: this uses a pair of HMACs to incorporate the diversification label, rather than a single KDF invocation, due to hardware limitations when passing KV data to the HMAC hardware as a message.)*

3. Clear the Field Entropy in Key Vault Slot 1.

    `kv_clear(KvSlot1)`

4. Derive the stable identity root secret from LDevID and store the resultant MAC in Key Vault Slot 1.

    `hmac512_mac(KvSlot1, b"stable_identity_root_ldev", KvSlot6)`

5. Derive ECDSA Key Pair using CDI in Key Vault Slot 6 and store the generated private key in Key Vault Slot 5.

    `LDevIDSeed = hmac512_kdf(KvSlot6, b"ldevid_ecc_key", KvSlot3)`

    `LDevIdPubKeyEcdsa = ecc384_keygen(KvSlot3, KvSlot5)`

    `kv_clear(KvSlot3)`

6. Derive the MLDSA Key Pair using CDI in Key Vault Slot 6 and store the key generation seed in Key Vault Slot 4.

    `LDevIDSeed = hmac512_kdf(KvSlot6, b"ldevid_mldsa_key", KvSlot4)`

    `LDevIdPubKeyMldsa = mldsa87_keygen(KvSlot4)`

7. Store and lock (for write) the LDevID ECDSA and MLDSA Public Keys in the DCCM datavault.

8. Generate the `To Be Signed` DER Blob of the ECDSA LDevId Certificate.

    `LDevIdTbsEcdsa = gen_cert_tbs(LDEVID_CERT, IDevIdPubKeyEcdsa, LDevIdPubKeyEcdsa)`

9. Sign the LDevID `To Be Signed` DER Blob with IDevId ECDSA Private Key in Key Vault Slot 7.

    `LDevIdTbsDigestEcdsa = sha384_digest(LDevIdTbsEcdsa)`

    `LDevIdCertSigEcdsa = ecc384_sign(KvSlot7, LDevIdTbsDigestEcdsa)`

10. Clear the IDevId ECDSA Private Key in Key Vault Slot 7.

    `kv_clear(KvSlot7)`

11. Verify the signature of LDevID `To Be Signed` Blob.

    `Result = ecc384_verify(IDevIdPubKeyEcdsa, LDevIdTbsDigestEcdsa, LDevIdCertSigEcdsa)`

12. Generate the `To Be Signed` DER Blob of the MLDSA LDevId Certificate.

    `LDevIdTbsMldsa = gen_cert_tbs(LDEVID_CERT, IDevIdPubKeyMldsa, LDevIdPubKeyMldsa)`

13. Sign the LDevID `To Be Signed` DER Blob with the IDevId MLDSA Private Key derived from the seed in Key Vault Slot 8.

    `LDevIdTbsDigestMldsa = sha512_digest(LDevIdTbsMldsa)`

    `LDevIdCertSigMldsa = mldsa87_sign(KvSlot8, LDevIdTbsDigestMldsa)`

14. Clear the IDevId Mldsa seed in Key Vault Slot 8.

    `kv_clear(KvSlot8)`

15. Verify the signature of LDevID `To Be Signed` Blob.

    `Result = mldsa87_verify(IDevIdPubKeyMldsa, LDevIdTbsDigestMldsa, LDevIdCertSigMldsa)`

16. Store and lock (for write) the LDevID Certificate ECDSA and MLDSA Signatures in the DCCM datavault.


**Post-conditions:**

- Vault state is as follows:

 | Slot | Key Vault                                     |
 |------|-----------------------------------------------|
 | 0    | Stable identity root IDevID secret (64 bytes) |
 | 1    | Stable identity root LDevID secret (64 bytes) |
 | 4    | LDevID Key Pair Seed - MLDSA (32 bytes)       |
 | 5    | LDevID Private Key - ECDSA (48 bytes)         |
 | 6    | LDevID CDI (64 bytes)                         |

 | DCCM Datavault                 |
 |--------------------------------|
 | 🔒IDevID Cert ECDSA Signature |
 | 🔒IDevID ECDSA Pub Key        |
 | 🔒IDevID Cert MLDSA Signature |
 | 🔒IDevID MLDSA Pub Key        |
 | 🔒LDevID Cert ECDSA Signature |
 | 🔒LDevID ECDSA Pub Key        |
 | 🔒LDevID Cert MLDSA Signature |
 | 🔒LDevID MLDSA Pub Key        |

### Firmware Processor Stage
During this phase, the ROM executes specific mailbox commands. Based on the operational mode (SUBSYSTEM versus PASSIVE), the ROM also initiates the download of the firmware image. This download is conducted either through a mailbox command or via the Recovery Register Interface.

#### Handling commands from mailbox

ROM supports the following set of commands before handling the FW_DOWNLOAD command in PASSIVE mode (described in section 9.6) or RI_DOWNLOAD_FIRMWARE/RI_DOWNLOAD_ENCRYPTED_FIRMWARE command in SUBSYSTEM mode. Once the FW_DOWNLOAD, RI_DOWNLOAD_FIRMWARE, or RI_DOWNLOAD_ENCRYPTED_FIRMWARE is issued, ROM stops processing any additional mailbox commands.

1. **STASH_MEASUREMENT**: Up to eight measurements can be sent to the ROM for recording. Sending more than eight measurements will result in an FW_PROC_MAILBOX_STASH_MEASUREMENT_MAX_LIMIT fatal error. Format of a measurement is documented at [Stash Measurement command](https://github.com/chipsalliance/caliptra-sw/blob/main-2.x/runtime/README.md#stash_measurement).
2. **VERSION**: Get version info about the module. [Version command](https://github.com/chipsalliance/caliptra-sw/blob/main-2.x/runtime/README.md#version).
3. **SELF_TEST_START**: This command is used to invoke the FIPS Known-Answer-Tests (aka KAT) on demand. [Self Test Start command](https://github.com/chipsalliance/caliptra-sw/blob/main-2.x/runtime/README.md#self_test_start).
4. **SELF_TEST_GET_RESULTS**: This command is used to check if a SELF_TEST command is in progress. [Self Test Get Results command](https://github.com/chipsalliance/caliptra-sw/blob/main-2.x/runtime/README.md#self_test_get_results).
5. **SHUTDOWN**: This command is used clear the hardware crypto blocks including the keyvault. [Shutdown command](https://github.com/chipsalliance/caliptra-sw/blob/main-2.x/runtime/README.md#shutdown).
6. **CAPABILITIES**: This command is used to query the ROM capabilities. Capabilities is a 128-bit value with individual bits indicating a specific capability. Capabilities are documented in the [Capabilities command](https://github.com/chipsalliance/caliptra-sw/blob/main-2.x/runtime/README.md#capabilities).
7. **GET_IDEVID_CSR**: This command is used to fetch the IDevID CSR from ROM. [Fetch IDevIDCSR command](https://github.com/chipsalliance/caliptra-sw/blob/main-2.x/runtime/README.md#get_idevid_csr).
8. **CM_DERIVE_STABLE_KEY**: This command is used to derive a stable key for Device Ownership Transfer or other flows. [CM_DERIVE_STABLE_KEY](https://github.com/chipsalliance/caliptra-sw/blob/main-2.x/runtime/README.md#cm_derive_stable_key)
9. **CM_HMAC**: This command uses derived stable keys for Device Ownership Transfer or other flows. [CM_HMAC](https://github.com/chipsalliance/caliptra-sw/blob/main-2.x/runtime/README.md#cm_hmac)
10. **ECDSA384_SIGNATURE_VERIFY**: This command verifies ECDSA384 signatures for Device Ownership Transfer or other flows. [ECDSA384_SIGNATURE_VERIFY](https://github.com/chipsalliance/caliptra-sw/blob/main-2.x/runtime/README.md#ecdsa384_signature_verify)
11. **MLDSA87_SIGNATURE_VERIFY**: This command verifies MLDSA87 signatures for Device Ownership Transfer or other flows. [MLDSA87_SIGNATURE_VERIFY](https://github.com/chipsalliance/caliptra-sw/blob/main-2.x/runtime/README.md#mldsa87_signature_verify)
12. **CM_RANDOM_GENERATE**: This command returns random numbers from Caliptra's RNG for Device Ownership Transfer or other flows. [CM_RANDOM_GENERATE](https://github.com/chipsalliance/caliptra-sw/blob/main-2.x/runtime/README.md#cm_random_generate)
13. **GET_LDEV_ECC384_CERT**: This command fetches an LDevID ECC384 certificate signed by the ECC384 IDevID private key. [GET_LDEV_ECC384_CERT](https://github.com/chipsalliance/caliptra-sw/blob/main-2.x/runtime#get_ldev_ecc384_cert)
14. **GET_LDEV_MLDSA87_CERT**: This command fetches an LDevID MLDSA87 certificate signed by the MLDSA87 IDevID private key. [GET_LDEV_MLDSA87_CERT](https://github.com/chipsalliance/caliptra-sw/blob/main-2.x/runtime#get_ldev_mldsa87_cert)
15. **INSTALL_OWNER_PK_HASH**: This command saves the owner public key hash to persistent data. [INSTALL_OWNER_PK_HASH](https://github.com/chipsalliance/caliptra-sw/blob/main-2.x/runtime#install_owner_pk_hash)

16. **ZEROIZE_UDS_FE**

Zeroizes (sets to 0xFFFFFFFF) the UDS (Unique Device Secret) and/or FE (Field Entropy) partitions in the OTP fuse controller. This command is typically used during device decommissioning or ownership transfer flows.

The command accepts a flags field where each bit controls a specific partition. Multiple partitions can be zeroized in a single command by setting multiple flag bits.

The zeroization process follows these steps for each partition:
1. Clears the zeroization marker first to mask potential ECC errors during power failures
2. Zeroizes the seed data
3. Clears the partition digest

All operations are verified to return 0xFFFFFFFF before proceeding.

Command Code: `0x5A45_5546` ("ZEUF")

*Table: `ZEROIZE_UDS_FE` input arguments*

| **Name**  | **Type** | **Description**
| --------  | -------- | ---------------
| chksum    | u32      | Checksum over other input arguments, computed by the caller. Little endian.
| flags     | u32      | Partition flags. See ZEROIZE_UDS_FE_FLAGS below.

*Table: `ZEROIZE_UDS_FE_FLAGS` input flags*

| **Name**           | **Value** | **Description**
| ------------------ | --------- | ---------------
| ZEROIZE_UDS_FLAG   | 1 << 0    | Zeroize UDS partition
| ZEROIZE_FE0_FLAG   | 1 << 1    | Zeroize FE partition 0
| ZEROIZE_FE1_FLAG   | 1 << 2    | Zeroize FE partition 1
| ZEROIZE_FE2_FLAG   | 1 << 3    | Zeroize FE partition 2
| ZEROIZE_FE3_FLAG   | 1 << 4    | Zeroize FE partition 3

*Table: `ZEROIZE_UDS_FE` output arguments*

| **Name**      | **Type** | **Description**
| --------      | -------- | ---------------
| chksum        | u32      | Checksum over other output arguments, computed by Caliptra. Little endian.
| dpe_result    | u32      | Result code, 0 on success.

#### Downloading firmware image from mailbox

There are two modes in which the ROM executes: PASSIVE mode or SUBSYSTEM mode. Following is the sequence of the steps that are performed to download the firmware image from mailbox in PASSIVE mode.

- ROM asserts READY_FOR_FIRMWARE signal.
- Poll for the execute bit to be set. This bit is set as the last step to transfer the control of the command to the Caliptra ROM.
- Read the command register and ensure the command is FW_DOWNLOAD.
- Read the data length register and validate the value in it.
- Read N dwords from the mailbox DATAOUT register.  Execute the command.
- Once the entire data is processed, clear the execute bit.
  - This should be the last step. Clearing this bit transfers the control back to the originator of the command.
- On failure, a non-zero status code will be reported in the `CPTRA_FW_ERROR_NON_FATAL` register

![DATA FROM MBOX FLOW](doc/svg/data-from-mbox.svg)

Following is the sequence of steps that are performed to download the firmware image into the mailbox in SUBSYSTEM mode.

ROM supports two commands for firmware download in SUBSYSTEM mode:
- **RI_DOWNLOAD_FIRMWARE** (Command Code: `0x5249_4644` / "RIFD"): Standard firmware download. After downloading and validating the firmware, the runtime will activate the MCU firmware immediately.
- **RI_DOWNLOAD_ENCRYPTED_FIRMWARE** (Command Code: `0x5249_4645` / "RIFE"): Encrypted firmware download. Sets the boot mode to `EncryptedFirmware`, which signals to the runtime that the MCU firmware is encrypted and should not be activated until it has been decrypted using the `CM_AES_GCM_DECRYPT_DMA` command.

1. On receiving the RI_DOWNLOAD_FIRMWARE or RI_DOWNLOAD_ENCRYPTED_FIRMWARE mailbox command, set the RI PROT_CAP2 register version to 1.1 and the `Agent Capability` field bits:
    - `Device ID`
    - `Device Status`
    - `Push C-image support`
    - `Flashless boot`
    - `FIFO CMS support`
2. Set the RI DEVICE_STATUS_0 register, `Device Status` field  to 0x3 ('Recovery mode - ready to accept recovery image') and
`Recovery Reason Code` field to 0x12 ('Flashless/Streaming Boot (FSB)').
3. Set the RI RECOVERY_STATUS register, `Device Recovery Status` field to 0x1 ('Awaiting recovery image') and `Recovery Image Index` field to 0 (Firmware Image).
4. Loop on the `payload_available` bit in the `DMA Status0` register for the firmware image info to be available.
5. Read the image size from RI INDIRECT_FIFO_CTRL_1 register. Image size is in DWORDs.
6. Initiate image download from the recovery interface to the mailbox sram:
  a. Write the payload length to the DMA widget 'Byte Count' register.
  b. Write the block size with a value of 256 to the DMA widget 'Block Size' register.
  c. Write the source address to the DMA widget 'Source Address - Low' and 'Source Address - High' registers.
  d. Acquire the mailbox lock.
  e. Write DMA widget 'Control' register.
    - Set `Read Route` bits to 0x1 (AXI RD -> Mailbox)
    - Set `Read Addr fixed` bit.
    - Set Bit0 (GO)
  f. Read DMA widget `Status0` register in a loop if `Busy' bit is 0.
  g. Image is downloaded into mailbox sram.
7. Set RI `DEVICE_STATUS` register, `Device Status` field to 0x4 (`Recovery Pending (waiting for activation)`)
8. Loop on RI `RECOVERY_CTRL` register `Activate Recovery Image` field to wait for processing the image.
9. Set RI `RECOVERY_STATUS` register `Device Recovery Status` field to 0x2 (`Booting recovery image`).
10. Validate the image per the [Image Validation Process](#firmware-image-validation-process).
11. Reset the `RECOVERY_CTRL` register `Activate Recovery Image` field by writing 0x1.
12. If the validation is succesful, set the `DEVICE_STATUS` register `Device Status` field to 0x5 (`Running Recovery Image ( Recover Reason Code not populated)`)
13. If the validation fails, set the `RECOVERY_STATUS` register `Device Recovery Status` field to 0xc (`Recovery failed`) and `DEVICE_STATUS` register `Device Status` field to 0xF (`Fatal Error (Recover Reason Code not populated)`).
14. Release the mailbox lock.

#### Image validation

See Firmware [Image Validation Process](#firmware-image-validation-process).

### Derivation of the key ladder for Stable Identity

Stable Identity calls for a secret that remains stable across firmware updates, but which can ratchet forward when major firmware vulnerabilities are fixed. Caliptra ROM implements this feature in terms of a "key ladder".

The key ladder is initialized from the LDevID CDI during cold-boot. The key ladder length is inversely related to the firmware's SVN. Each step of the ladder is an SVN-unique key. The key for SVN X can be obtained by applying a one-way cryptographic operation to the key for SVN X+1. In this manner, firmware with a given SVN can wield keys bound to its SVN or older, but cannot wield keys bound to newer SVNs.

To comply with FIPS, the one-way cryptographic operation used to compute keys is an SP 800-108 KDF.

When the key ladder is initialized at cold-boot, it is bound to the lifecycle state and debug-locked. This ensures that the keys of the ladder will change across lifecycle or debug state transtions.

Across update-resets, ROM tracks the minimum SVN that has run since cold-boot. It ensures that the ladder's length always corresponds to that minimum SVN. The key ladder can only be shortened (and thereby give access to newer SVNs' keys) by cold-booting into firmware with a newer SVN and re-initializing the ladder.

#### Cold-boot

ROM initializes a key ladder for the firmware. LDevID CDI in Key Vault Slot6 is used as an HMAC Key, and the data is a fixed string. The resultant MAC is stored in Slot 2.

    KeyLadderContext = lifecycle state || debug_locked state

    hmac512_kdf(KvSlot6, label: b"si_init", context: KeyLadderContext, KvSlot2)

    Loop (MAX_FIRMWARE_SVN - (current firmware SVN)) times:

        hmac512_kdf(KvSlot2, label: b"si_extend", context: None, KvSlot2)

#### Update-reset

During update-reset, the key ladder initialized at cold boot is lengthened if necessary, such that its length always corresponds with the minimum SVN since cold boot.

    old_min_svn = [retrieved from data vault]
    new_min_svn = min(old_min_svn, new_fw_svn)
    [store new_min_svn in data vault]

    Loop (`old_min_svn` - `new_min_svn`) times:

        hmac512_kdf(KvSlot2, label: b"si_extend", context: None, KvSlot2)

### Alias FMC DICE layer & PCR extension

Alias FMC Layer includes the measurement of the FMC and other security states. This layer is used to assert a composite identity which includes the security state, FMC measurement along with the previous layer identities.

**Pre-conditions:**

- LDevID CDI is stored in Key Vault Slot 6
- LDevID MLDSA Key Pair Seed is stored in Key Vault Slot 4
- LDevID ECDSA Private Key is stored in Key Vault Slot 5
- Firmware Image Bundle is successfully loaded and verified from the Mailbox
- ROM has following information from Firmware Image Bundle
- FMC_DIGEST - Digest of the FMC
- FW_SVN - SVN for the firmware
- MANUFACTURER_PK - Manufacturer Public Key(s) used to verify the firmware image bundle
- MANUFACTURER_PK_INDEX - Index of the MANUFACTURER_PK in the firmware image bundle

**Actions:**

1. PCR0 is the Current PCR. PCR 1 is the Journey PCR. PCR0 is cleared by ROM upon each cold and update resets, before it is extended with FMC measurements. PCR0 and PCR1 are locked for clear by the ROM on every reset. Subsequent layers may continue to extend PCR0 as runtime updates are performed.

    ```text
    pcr_clear(Pcr0)
    pcr_extend(Pcr0 && Pcr1, [
        CPTRA_SECURITY_STATE.LIFECYCLE_STATE,
        CPTRA_SECURITY_STATE.DEBUG_ENABLED,
        FUSE_ANTI_ROLLBACK_DISABLE,
        VENDOR_ECC_PK_INDEX,
        FW_SVN,
        FW_FUSE_SVN (or 0 if `FUSE_ANTI_ROLLBACK_DISABLE`),
        VENDOR_PQC_PK_INDEX,
        PQC_KEY_TYPE,
        OWNER_PK_HASH_FROM_FUSES (0 or 1),
    ])
    pcr_extend(Pcr0 && Pcr1, MANUFACTURER_PK)
    pcr_extend(Pcr0 && Pcr1, OWNER_PK)
    pcr_extend(Pcr0 && Pcr1, FMC_TCI)
    pcr_lock_clear(Pcr0 && Pcr1)
    ```

2. CDI for Alias is derived from PCR0. For the Alias FMC CDI Derivation, LDevID CDI in Key Vault Slot6 is used as HMAC Key and contents of PCR0 are used as data. The resultant MAC is stored back in Slot 6.

    `Pcr0Measurement = pcr_read(Pcr0)`

    `hmac512_kdf(KvSlot6, label: b"alias_fmc_cdi", context: Pcr0Measurement, KvSlot6)`

3. Derive Alias FMC ECDSA Key Pair using CDI in Key Vault Slot 6 and store the generated private key in Key Vault Slot 7.

    `AliasFmcSeedEcdsa = hmac512_kdf(KvSlot6, b"fmc_alias_ecc_key", KvSlot3)`

    `AliasFmcPubKeyEcdsa = ecc384_keygen(KvSlot3, KvSlot7)`

    `kv_clear(KvSlot3)`

    Derive the Alias FMC MLDSA Key Pair using CDI in Key Vault Slot 6 and store the key pair generation seed in Key Vault Slot 8.

    `AliasFmcSeedMldsa = hmac512_kdf(KvSlot6, b"fmc_alias_mldsa_key", KvSlot8)`

    `AliasFmcPubKeyMldsa = mldsa87_keygen(KvSlot8)`

4. Store and lock (for write) the FMC ECDSA and MLDSA Public Keys in the DCCM datavault.

5. Generate the `To Be Signed` DER Blob of the ECDSA Alias FMC Certificate.

    `AliasFmcTbsEcdsa = gen_cert_tbs(ALIAS_FMC_CERT, LDevIdPubKeyEcdsa, AliasFmcPubKeyEcdsa)`

6. Sign the Alias FMC `To Be Signed` DER Blob with the LDevId ECDSA Private Key in Key Vault Slot 5.

    `AliasFmcTbsDigestEcdsa = sha384_digest(AliasFmcTbsEcdsa)`

    `AliasFmcTbsCertSigEcdsa = ecc384_sign(KvSlot5, AliasFmcTbsDigestEcdsa)`

7. Clear the LDevId Private Key in Key Vault Slot 5.

    `kv_clear(KvSlot5)`

8. Verify the signature of Alias FMC `To Be Signed` ECDSA Blob.

    `Result = ecc384_verify(LDevIdPubKeyEcdsa, AliasFmcDigestEcdsa, AliasFmcTbsCertSigEcdsa)`

9. Generate the `To Be Signed` DER Blob of the MLDSA Alias FMC Certificate.

    `AliasFmcTbsMldsa = gen_cert_tbs(ALIAS_FMC_CERT, LDevIdPubKeyMldsa, AliasFmcPubKeyMldsa)`

10. Sign the Alias FMC `To Be Signed` DER Blob with the LDevId MLDSA Private Key generated from the seed in Key Vault Slot 4.

    `AliasFmcTbsDigestMldsa = sha512_digest(AliasFmcTbsMldsa)`

    `AliasFmcTbsCertSigMldsa = mldsa87_sign(KvSlot4, AliasFmcTbsDigestMldsa)`

11. Clear the LDevId MLDSA key generation seed in Key Vault Slot 4.

    `kv_clear(KvSlot4)`

12. Verify the signature of Alias FMC `To Be Signed` MLDSA Blob.

    `Result = mldsa87_verify(LDevIdPubKeyMldsa, AliasFmcDigestMldsa, AliasFmcTbsCertSigMldsa)`

13. Store and lock (for write) the Alias FMC Certificate ECDSA and MLDSA Signatures in the DCCM datavault.

14. Lock critical state needed for warm and update reset in the DCCM datavault.

    `dccm_dv_store(FMC_DIGEST, lock_for_wr)`

    `dccm_dv_store(FW_SVN, lock_for_wr)`

    `dccm_dv_store(FUSE_OWNER_PK_HASH, lock_for_wr)`

    `dccm_dv_store(MANUFACTURER_ECC_PK_INDEX, lock_for_wr)`

    `dccm_dv_store(MANUFACTURER_PQC_PK_INDEX, lock_for_wr)`

    `dccm_dv_store(ROM_COLD_BOOT_STATUS, lock_for_wr)`

    **Note**: A value of 0x140 is stored on a successful cold boot.

**Post-conditions:**

- Vault state as follows:

 | Slot | Key Vault                                     |
 |------|-----------------------------------------------|
 | 0    | Stable identity root IDevID secret (64 bytes) |
 | 1    | Stable identity root LDevID secret (64 bytes) |
 | 6    | Alias FMC CDI (48 bytes)                      |
 | 7    | Alias FMC Private Key - ECDSA (48 bytes)      |
 | 8    | Alias FMC Key Pair Seed - MLDSA (32 bytes)    |

 | DCCM datavault                         |
 |----------------------------------------|
 | 🔒IDevID Cert ECDSA Signature         |
 | 🔒IDevID ECDSA Pub Key                |
 | 🔒IDevID Cert MLDSA Signature         |
 | 🔒IDevID MLDSA Pub Key                |
 | 🔒LDevID Cert ECDSA Signature R       |
 | 🔒LDevID Cert ECDSA Signature S       |
 | 🔒LDevID Cert MLDSA Signature         |
 | 🔒LDevID Pub Key ECDSA X              |
 | 🔒LDevID Pub Key ECDSA Y              |
 | 🔒LDevID Pub Key MLDSA                |
 | 🔒Alias FMC Cert ECDSA Signature R    |
 | 🔒Alias FMC Cert ECDSA Signature S    |
 | 🔒Alias FMC Cert MLDSA Signature      |
 | 🔒FW SVN                              |
 | 🔒ROM Cold Boot Status                |
 | 🔒FMC Entry Point                     |
 | 🔒Manufacturer ECDSA Public Key Index |
 | 🔒Manufacturer PQC Public Key Index   |
 | 🔒Alias FMC ECDSA Pub Key X           |
 | 🔒Alias FMC ECDSA Pub Key Y           |
 | 🔒Alias FMC MLDSA Pub Key             |
 | 🔒FMC Digest                          |
 | 🔒Owner PK Hash                       |

### Locking of memory regions and registers
 ROM locks the following entities to prevent any updates:

 - **Cold Reset Unlockable values:**
 These values are unlocked on a Cold Reset:
    - FMC TCI
    - FMC Entry Point
    - Owner Pub Key Hash
    - Ecc Vendor Pub Key Index
    - PQC Vendor Pub Key Index
    - ROM Cold Boot Status

 - **Warm Reset unlockable values:**
 These values are unlocked on a Warm or Cold Reset:
    - RT TCI
    - RT Entry Point
    - FW SVN
    - Manifest Addr
    - ROM Update Reset Status

 - **PCR values**
    - FMC_CURRENT
    - FMC_JOURNEY
    - STASH_MEASUREMENT

 - **ICCM**

### Launch FMC
The ROM initializes and populates the Firmware Handoff Table (FHT) to relay essential parameters to the FMC. The format of the FHT is documented [here](https://github.com/chipsalliance/caliptra-sw/blob/main-2.x/fmc/README.md#firmware-handoff-table). Upon successful population, the ROM transfers execution control to the FMC.

## Warm reset flow
ROM does not perform any DICE derivations or firmware validation during warm reset.

![WARM RESET](doc/svg/warm-reset.svg)

### Initialization
ROM performs the same initialization sequence as specified [here](#Initialization)

### Locking of memory regions and registers
ROM locks the following entities to prevent any updates:

 - **Warm Reset unlockable values:**
    - RT TCI
    - RT Entry Point
    - FW SVN
    - Manifest Addr
    - ROM Update Reset Status

 - **PCR values**
    - FMC_CURRENT
    - FMC_JOURNEY
    - STASH_MEASUREMENT

 - **ICCM**

## Update reset flow

![UPDATE RESET](doc/svg/update-reset.svg)
<br> *(Note: Please note that Image validation for the update reset flow has some differences as compared to the cold boot flow. Please refer to the Image Validation Section for further details.)

## Unknown/spurious reset flow

### Initialization
ROM performs the same initialization sequence as specified [here](#Initialization)

### Error handling
The ROM executes the following operations:
  - Updates the `cptra_fw_error_fatal` and `cptra_fw_error_non_fatal` registers with the error code ROM_UNKNOWN_RESET_FLOW (0x01040020) error code.
  - Zeroizes the following cryptographic hardware modules:
    - Ecc384
    - Hmac384
    - Sha256
    - Sha384
    - Sha2-512-384Acc
    - KeyVault
  - Stops the WatchDog Timer.
  - Enters an infinite loop, awaiting a reset.
<br><br>

![UNKNOWN RESET](doc/svg/unknown-reset.svg)

## Firmware image validation process

The basic flow for validating the firmware involves the following:

- Validating the manufacturer key descriptors in the preamble.
- Validating the active manufacturer keys with the corresponding hash in the key descriptors.
- Validating the owner key descriptors in the preamble.
- Validating the owner keys with the hash in the key descriptors.
- Validating the active manufacturer keys against the key revocation fuses.
- Validating the Manifest Header using the active manufacturer keys against the manufacturer signatures.
- Validating the Manifest Header using the owner keys against the owner signatures.
- On the completion of these validations, it is assured that the header portion is authentic.
- Loading the FMC and Rutime (RT) TOC entries from the mailbox.
- Validating the TOCs against the TOC hash in the header.
- On successful validation, it is assured that the TOCs are valid. The next step is to use the Hash entry in the TOCs to validate the image sections.
- Downloading the FMC Image portion of the firmware Image.
- Validating the FMC Image against the hash in the TOC entry for the FMC.
  - If this is a cold reset, the FMC version number should be stored in a register.
- Downloading the RT Image part of the firmware Image.
- Validating the RT Image against the hash in the TOC entry for the RT.
- On the successful completion of these validations, the entire image is validated.
- Indicating to the SOC of validation success by completing the mailbox command.
- On validation failure, reporting the appropriate error in the `CPTRA_FW_ERROR_FATAL` register and invoking the [error handler](#Error-handling)

### **Overall validation flow**

![Overall Validation Flow](doc/svg/overall-validation-flow.svg)

#### **Pre-conditions**

The following are the pre-conditions that should be satisfied:

- Caliptra has transitioned through the BOOTFSM and all the fuses that are required for the validation are already populated by SOC.
- The FUSES programmed by the soc are
  - fuse_vendor_pk_hash : This fuse contains the hash of the manufacturer key descriptors present in the preamble.
  - fuse_ecc_revocation : This is the bitmask of the ECC keys which are revoked.
  - fuse_lms_revocation : This is the bitmask of the LMS keys which are revoked.
  - fuse_mldsa_revocation : This is the bitmask of the MLDSA keys which are revoked.
  - fuse_owner_pk_hash : The hash of the owner public keys in preamble.
  - fuse_firmware_svn : Used in FW validation to make sure that the firmware image's SVN is good.
  - fuse_pqc_key_type: This bitmask specifies the enabled PQC key type for firmware validation, indicating either MLDSA or LMS.
- The SOC has written the data to the mailbox.
- The SOC has written the data length in the DLEN mailbox register.
- The SOC has put the FW_DOWNLOAD command in the command register.
- The SOC has set the execute bit in the mailbox execute register.
<br> *( NOTE: At this time the interrupts are not enabled. Writing a execute bit will not generate an interrupt. The validation and update flow will need to be invoked externally.)*

## Preamble validation: Validate the manufacturing keys

- Load the preamble bytes from the mailbox.
- Based on the firmware image type, the image includes an ECC key descriptor and either an LMS or MLDSA key descriptor within the preamble. The ECC descriptor encapsulates up to four ECC public key hashes, the LMS descriptor up to 32 public key hashes, and the MLDSA descriptor up to four MLDSA public key hashes.
- The firmware image, depending on its type, incorporates an ECC key and either an LMS or MLDSA manufacturing public key within the preamble. These constitute the active public keys.
- The fuse_vendor_pk_hash fuse holds the SHA2-384 hash of the ECC, and LMS or MLDSA manufacturing key descriptors.
- The key descriptors are validated by generating a SHA2-384 hash of the ECC and LMS or MLDSA key descriptors and comparing it against the hash stored in the fuse. If the hashes do not match, the image validation fails.
- Upon a successful hash match, the ECC, and LMS or MLDSA key descriptors are deemed valid.
- Subsequently, the active manufacturer public keys are validated against one of the hashes in the key descriptors. The specific hash for comparison is identified by the active key indices.

### Preamble validation: Manufacturing key validation

- fuse_ecc_revocation serves as the bitmask for revoking ECC keys.
  - If bit-n is set, the nth key is disabled. All other higher bits that are zeros indicate the keys are still enabled.
  - If all the bits are zeros, all ECC keys remain enabled.
- Ensure that the Active Key Index in the preamble is not disabled by the fuse_ecc_revocation fuse.
  - If the key is disabled, the validation process fails.
- Repeat the above procedure for LMS or MLDSA keys using the fuse_lms_revocation or fuse_mldsa_revocation fuses, respectively, for key revocation.

### Preamble validation: Validate the Owner key

- The preamble includes a designated slot for the owner ECC key and a slot for either LMS or MLDSA keys.
- The fuse_owner_pk_hash contains the hash of the owner public keys.
- The validation process for owner public keys involves generating a SHA2-384 hash from the owner public keys within the preamble and comparing it to the hash stored in the fuse_owner_pk_hash register.
- If the computed hash matches the value in fuse_owner_pk_hash, the owner public keys are deemed valid.
- If there is a hash mismatch, the image validation process fails.

## Preamble validation steps

![Preamble Validation Flow](doc/svg/preamble-validation.svg)

## Header validation

- Retrieve the header portion of the firmware image from the mailbox.
- Note that the header is the sole signed component, featuring two distinct signatures pairs.
- The first signature pair is generated using the active ECC and LMS or MLDSA manufacturing keys.
- The second signature pair is generated using the owner ECC and LMS or MLDSA public keys.
- To validate the header:
  - Compute the SHA2-384 hash of the header.
  - Verify the ECC manufacturer signature in the preamble against the computed hash.
  - If the ECC manufacturer signature is invalid, fail the validation process. If the ECC manufacturer signature is valid, apply the same procedure using the LMS or MLDSA manufacturer key.
  - Similarly, utilize the precomputed hash to verify the signature with the ECC owner public key. Repeat the process using the LMS or MLDSA owner key.

## Header validation steps

![Header Validation Flow](doc/svg/header-validation.svg)

## Table of contents validation

- At this point both the Preamble and the Header have been validated.
- Load the TOC entries (FMC TOC and RT TOC) from the mailbox.
- Compute the SHA2-384 hash of the complete TOC data.
- Compare the computed TOC hash with the hash embedded in the Header.
  - If the hashes match, the TOC data is validated.
- Ensure that Fw.Svn is greater than or equal to Fuse.Svn.

<br> *(Note: Same SVN Validation is done for the FMC and RT)

<br>

## Table of contents validation steps

![Toc Validation Flow](doc/svg/toc-validation.svg)

## Validating image sections

- Upon successful validation of the TOC, each image section corresponding to the TOC requires validation.
- The hash for each image section is encapsulated within the TOC data.
- Retrieve the FMC Image section. The offset and size of the section are specified in the TOC.
- Compute the SHA2-384 hash for the FMC image section.
- Compare the computed hash with the hash specified in the FMC TOC.
  - If the hashes match, the FMC image section is considered validated. If the hashes do not match, the image is rejected.
- Retrieve the RT Image section from the mailbox. The offset and size of the section are specified in the TOC.
- Compute the SHA2-384 hash for the RT image section.
Compare the computed hash with the hash specified in the RT TOC.
  - If the hashes match, the RT image section is considered validated. If the hashes do not match, the image is rejected.

## Image section validation steps

![Image Section Validation Flow](doc/svg/image-section-validation.svg)

## Differences in operating mode of the validation code

- The validation code operates in three modes.
  - Cold Boot Mode
  - Warm Boot Mode
  - Update Reset Mode
- Cold Boot Mode
  - Validation of the entire image is done using the steps described above.
  - Save the hash of the FMC portion of the image in a separate register.
  - Copy the FMC and RT image's text and data section in the appropriate ICCM and DCCM memory regions.
  - The data vault is saved with the following values:-
    - LDevId Dice ECDSA Signature.
    - LDevId Dice MLDSA Signature.
    - LDevId Dice ECDSA Public Key.
    - LDevId Dice MLDSA Public Key.
    - Alias FMC Dice ECDSA Signature.
    - Alias FMC Dice MLDSA Signature.
    - Alias FMC Public ECDSA Key.
    - Alias FMC Public MLDSA Key.
    - Digest of the FMC part of the image.
    - Digest of the ECC and LMS or MLDSA owner public keys portion of preamble.
    - FW SVN.
    - ROM Cold Boot Status.
    - FMC Entry Point.
    - ECC Vendor public key index.
    - LMS or MLDSA Vendor public key index.
- Warm Boot Mode
  - In this mode there is no validation or load required for any parts of the image.
  - All the contents of ICCM and DCCM are preserved.
- Update Reset Mode
  - The image is exactly the same as the initial image which was verified on the cold boot, except that the RT part of the image is changed.
  - We need to validate the entire image exactly as described in the cold boot flow. In addition to that, also validate the image to make sure that no other part (except the RT image section) is altered.
  - The validation flow will look like the following:
    - Validate the preamble exactly like in cold boot flow.
      - Validate the vendor public key indices from the values in data vault (value saved during cold boot). Fail the validation if there is a mismatch. This is done to make sure that the key being used is the same key that was used during cold boot.
      - Validate the owner public key digest against the owner public key digest in data vault (value saved during cold boot). This ensures that the owner keys have not changed since last cold boot.
    - Validate the header exactly like in cold boot.
    - Validate the toc exactly like in cold boot.
    - We still need to make sure that the digest of the FMC which was stored in the data vault register at cold boot
      still matches the FMC image section.
    - Store the minimum firmware SVN that has run since cold-boot in the data vault.
    - Ratchet the key ladder if necessary.
  - If validation fails during ROM boot, the new RT image will not be copied from
    the mailbox. ROM will boot the existing FMC/Runtime images. Validation
    errors will be reported via the CPTRA_FW_ERROR_NON_FATAL register.

## Fake ROM

Fake ROM is a variation of the ROM intended to be used in the verification/enabling stages of development. The purpose is to greatly reduce the boot time for pre-Si environments by eliminating certain steps from the boot flow. Outside of these omissions, the behavior is intended to be the same as normal ROM.

Fake ROM is only available in production mode if the enable bit is set in the CPTRA_DBG_MANUF_SERVICE_REG (see section above).

**Differences from normal ROM:**

Fake ROM reduces boot time by doing the following:

1. Skipping the DICE cert derivation and instead providing a static, "canned" cert chain for LDEV and FMC Alias
2. Skipping the known answer tests (KATs)
3. Skipping verification of the FW image received - This can optionally still be performed, see CPTRA_DBG_MANUF_SERVICE_REG

**How to use:**

- Fake ROM is provided in the release along with the normal collateral.
- The image builder exposes the argument "fake" that can be used to generate the fake versions

To fully boot to runtime, the fake version of FMC should also be used. Details can be found in the FMC readme.
