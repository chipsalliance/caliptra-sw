# Caliptra Runtime Firmware

## Runtime Firmware Environment

### Boot & Initialization

The Runtime Firmware main function SHALL perform the following on Cold Boot reset:

* Initialize DPE (see below for details)
* Initialize any SRAM structures used by Runtime Firmware

For behavior during other types of reset, see "Runtime Firmware Updates".

### Main Loop

After booting, Caliptra Runtime firmware is responsible for the following:

* Wait for mailbox interrupts
* On mailbox interrupt
    * Write lock mailbox and set busy register
    * Read command from mailbox
    * Execute command
    * Write response to mailbox and set necessary status register(s)
    * Sleep until next interrupt
* On panic
    * Save diagnostic information

Callers must wait until Caliptra is no longer busy to call a mailbox command.

### Drivers

Caliptra Runtime Firmware will share driver code with ROM and FMC where
possible, however it will have its own copies of all these drivers linked into
the Runtime Firmware binary.

## Maibox Commands

All mailbox command codes are little endian.

Table: Mailbox command "result" codes:

| **Name**         | **Value**              | Description
| -------          | -----                  | -----------
| `SUCCESS`        | `0x0000_0000`          | Mailbox command succeeded
| `BAD_VENDOR_SIG` | `0x5653_4947` ("VSIG") | Vendor signature check failed
| `BAD_OWNER_SIG`  | `0x4F53_4947` ("OSIG") | Owner signature check failed
| `BAD_SIG`        | `0x4253_4947` ("BSIG") | Generic signature check failure (for crypto offload)
| `BAD_IMAGE`      | `0x4249_4D47` ("BIMG") | Malformed input image
| `BAD_CRC`        | `0x4243_5243` ("BCRC") | CRC check failed on input arguments

Relevant Mailbox Registers:

* COMMAND: Command code to execute
* DLEN: Number of bytes written to mailbox

### CALIPTRA\_FW\_LOAD

The `CALIPTRA_FW_LOAD` command is handled by both ROM and Runtime Firmware.

#### ROM Behavior

On cold boot, ROM will expose the `CALIPTRA_FW_LOAD` mailbox command to accept
the firmware image that ROM will boot. This includes Manifest, FMC, and Runtime
firmware.

#### Runtime Firmware Behavior

Caliptra Runtime FW will also expose this mailbox command for loading
impactless updates. See “Runtime Firmware Updates” for details.

Command Code: `0x4657_4C44` ("FWLD")

Table: `CALIPTRA_FW_LOAD` input arguments

| **Name**  | **Type**      | **Description**
| --------  | --------      | ---------------
| data      | u8[...]       | Firmware image to load.

Table: `CALIPTRA_FW_LOAD` output arguments

| **Name** | **Type** | **Description**
| -------- | -------- | ---------------
| crc      | u32      | CRC over other output arguments, computed by Caliptra. Little endian.
| result   | u32      | Result code. Little endian.

### GET\_IDEV\_CSR

ROM exposes a command to get a self-signed IDEVID CSR.
GET\_IDEV\_CSR is not exposed by runtime firmware.

Command Code: `0x4944_4556` ("IDEV")

`GET_IDEV_CSR` takes no input arguments.

* When invoked via JTAG, ROM will write the CSR to the mailbox so it can
  be read out over JTAG

Table: `GET_IDEV_CSR` output arguments

| **Name**  | **Type**      | **Description**
| --------  | --------      | ---------------
| data      | u8[...]       | DER-encoded IDevID CSR

### GET\_LDEV\_CERT

ROM exposes a command to get a self-signed LDevID Certificate signed by IDevID.
GET\_LDEV\_CERT is not exposed by runtime firmware.

Command Code: `0x4C44_4556` ("LDEV")

`GET_LDEV_CERT` takes no input arguments.

* When invoked via JTAG, ROM will write the certificate to the mailbox so it can
  be read out over JTAG

Table: `GET_LDEV_CERT` output arguments

| **Name**  | **Type**      | **Description**
| --------  | --------      | ---------------
| data      | u8[...]       | DER-encoded LDevID Certificate

### ECDSA384\_SIGNATURE\_VERIFY

Command Code: `0x5349_4756` ("SIGV")

Table: `ECDSA384_SIGNATURE_VERIFY` input arguments

| **Name**     | **Type** | **Description**
| --------     | -------- | ---------------
| crc          | u32      | CRC over other input arguments, computed by the caller. Little endian.
| data         | u8[48]   | Signed hash to verify
| pub\_key\_x  | u8[48]   | X portion of ECDSA verification key
| pub\_key\_y  | u8[48]   | Y portion of ECDSA verification key
| signature\_r | u8[48]   | R portion of signature to verify
| signature\_s | u8[48]   | S portion of signature to verify


Table: `ECDSA384_SIGNATURE_VERIFY` output arguments

| **Name** | **Type** | **Description**
| -------- | -------- | ---------------
| crc      | u32      | CRC over other output arguments, computed by Caliptra. Little endian.
| result   | u32      | Result code. Little endian.

### STASH\_MEASUREMENT

Make a measurement into the DPE default context. This command is intendend for
callers who update infrequently and cannot tolerate a changing DPE API surface.

Internally, this will call the DPE DeriveChild command.

Command Code: `0x4D45_4153` ("MEAS")

Table: `STASH_MEASUREMENT` input arguments

| **Name**     | **Type** | **Description**
| --------     | -------- | ---------------
| crc          | u32      | CRC over other input arguments, computed by the caller. Little endian.
| metadata     | u8[4]    | 4-byte measurement identifier.
| measurement  | u8[48]   | Data to measure into DPE.


Table: `STASH_MEASUREMENT` output arguments

| **Name**    | **Type** | **Description**
| --------    | -------- | ---------------
| crc         | u32      | CRC over other output arguments, computed by Caliptra. Little endian.
| result      | u32      | Result code. Little endian.
| dpe\_result | u32      | Result code of DPE DeriveChild command. Little endian.

### INVOKE\_DPE\_COMMAND

Command Code: `0x4450_4543` ("DPEC")

Table: `INVOKE_DPE_COMMAND` input arguments

| **Name**     | **Type**      | **Description**
| --------     | --------      | ---------------
| crc          | u32           | CRC over other input arguments, computed by the caller. Little endian.
| data         | u8[...]       | DPE command structure as defined in the DPE iRoT profile


Table: `INVOKE_DPE_COMMAND` output arguments

| **Name**    | **Type**      | **Description**
| --------    | --------      | ---------------
| crc         | u32           | CRC over other output arguments, computed by Caliptra. Little endian.
| result      | u32           | Result code. Little endian.
| data        | u8[...]       | DPE response structure as defined in the DPE iRoT profile.

## CRC

For every command input/output arguments which have a "crc" field, the request
and response feature a checksum. This mitigates glitches between clients
and Caliptra.

The CRC is a little-endian 32-bit value, defined as:

```
0 - (SUM(command code bytes) + SUM(request/response bytes))
```

The sum of all bytes in a request/response body, and command code, should be
zero.

If Caliptra detects an invalid CRC in input parameters, it will return `BAD_CRC`
as the result.

Caliptra will also compute a CRC over all responses and write it to the crc
field.

## Runtime Firmware Updates

Caliptra Runtime firmware accepts impactless updates which will update
Caliptra’s firmware without resetting other cores in the SoC.

### Applying Updates

A Runtime Firmware update is triggered by the `CALIPTRA_FW_LOAD` command. Upon
receiving this command, Runtime Firmware will:

1. Write-lock mailbox
1. Verify firmware image signature
    1. Preserve hash for later steps
1. Update the “Latest TCI” field of the TCI Node which contains the Runtime
   Journey PCR (TYPE = RTJM, “Internal TCI” flag is set) with hash.
1. Invoke “Impactless Reset”

Once Impactless Reset has been invoked, FMC will load the hash of the image
from the verified Manifest into the necessary PCRs:

1. Runtime Journey PCR
1. Runtime Latest PCR

### Boot Process After Update

After an Impactless Update has been applied, the new Runtime Firmware will be
able to sample a register to determine it has undergone an Impactless Reset. In
this case, the new Runtime Firmware must:

1. Validate DPE state in SRAM
    1. Ensure TCI tree is well-formed
    1. All nodes chain to the root (TYPE = RTJM, “Internal TCI” flag is set)
1. Verify that the “Latest TCI” field of the TCI Node which contains the
   Runtime Journey PCR (TYPE = RTJM, “Internal TCI” flag is set) matches the
   “Latest” Runtime PCR value from PCRX
    1. Ensure `SHA384_HASH(0x00..00, TCI from SRAM) == PCR3 value`

## DICE Protection Environment (DPE)

Caliptra Runtime Firmware SHALL implement the
[iRoT Profile](https://github.com/TrustedComputingGroup/Server-Internal/blob/main/dpe-irot-profile/dpe-irot-profile-latest.pdf)
of the DICE Protection Environment (DPE) API.

### DPE Profile Implementation

The DPE iRoT Profile leaves some choices up to implementers. This section
details specific requirements for the Caliptra DPE implementation.

| Name                       | Value                          | Description
| ----                       | -----                          | -----------
| Profile Variant            | `DPE_PROFILE_IROT_P384_SHA384` | The profile variant that Caliptra implements.
| KDF                        | SP800-108 HMAC-CTR             | KDF to use for CDI (tcg.derive.kdf-sha384) and asymmetric key (tcg.derive.kdf-sha384-p384) derivation.
| Simulation Context Support | Yes                            | Whether Caliptra implements the optional Simulation Contexts feature
| Supports ExtendTci         | Yes                            | Whether Caliptra implements the optional ExtendTci command
| Supports Auto Init         | Yes                            | Whether Caliptra will automatically initialize the default DPE context.
| Supports Tagging           | Yes                            | Whether Caliptra implements the optional TCI tagging feature.
| Supports Rotate Context    | Yes                            | Whether Caliptra supports the optional RotateContextHandle command.
| CertifyKey Alias Key       | Caliptra Runtime Alias Key     | The key that will be used to sign certificates produced by the DPE CertifyKey command.

### Initializing DPE

Caliptra Runtime firmware is responsible for initializing DPE’s Default Context.

* Runtime Firmware SHALL initialize the Default Context in “internal-cdi” mode.
* Call DeriveChild to measure the Caliptra Journey PCR
* INPUT\_DATA = PCRX (RT journey PCR)
* TYPE = “RTJM”
* CONTEXT\_HANDLE = Default context
* Set flag in the TCI Node that this node was created by the DPE implementation.
  This will be used to set the VENDOR\_INFO field in TcbInfo to “VNDR”.

*Note: the Runtime CDI will be read as-needed and will not be accessed during
initialization.*

### TCI Storage

The DPE iRoT profile sets the maximum number of DPE TCI Nodes to 24. Caliptra
SHALL allocate 24 hardware PCRs to be exclusively used by DPE.

These PCRs will store only the cumulative journey of the PCRs.

#### PCR Properties

* 48 bytes
* Initial value of all zeros
* Extend operation: `NEW_VALUE = SHA384_HASH(OLD_VALUE || MEASUREMENT)`
* Clear operation: Resettable to initial value by Runtime Firmware

#### DPE PCR Usage

DPE will use one hardware PCR to store the TCI value for each TCI Node.

The DPE DeriveChild command will exercise the following PCR operations:

* `Extend(pcr_index, INPUT_DATA)`

The DPE ExtendTci command will exercise the following PCR operations:

* `Extend(pcr_index, INPUT_DATA)`

The DPE DestroyContext command will exercise the following PCR operations:

* `Clear(pcr_index)`

### CDI Derivation

The DPE Sign and CertifyKey commands derive an asymmetric key for that handle.

DPE will first collect measurements and concatenate them in a byte buffer
`MEASUREMENT_DATA`:

* LABEL parameter passed to Sign or CertifyKey.
* The PCR values for each TCI node in the path from the current TCI node to the
  root, inclusive, starting with the current node.

To derive a key for a given node, DPE shall use KeyVault hardware to derive a
CDI with the following inputs:

* CDI = Runtime Firmware CDI (from KeyVault)
* Label = LABEL parameter provided to Sign or CertifyKey
* Context = `MEASUREMENT_DATA`

This CDI shall be loaded into KeyVault slot 0.

### Leaf Key Derivation

If `FIPS_MODE` is disabled for the DPE command, DPE will

* Derive an ECC P384 keypair from KV slot 0 CDI into KV slot 1
* For CertifyKey: Request the public key
* For Sign: Sign passed data
* Erase KeyVault slots 0 and 1

If `FIPS_MODE` is enabled for the DPE command, DPE will

* If the key has been derived before and is cached in KeyVault
  * Use cached key from KeyVault
* If key is not cached
  * Derive a random CDI from TRNG and CDI in KV slot 0 and place in KV slot 1
  * Derive an ECC P384 keypair from KV slot 1 CDI into the next available Runtime
    KeyVault Slot
  * If no slots are available, evict the oldest Runtime slot and use that slot.
* For CertifyKey: Request the public key
* For Sign: Sign passed data
* Erase KeyVault slots 0 and 1

### Internal Representation of TCI Nodes

| Byte Offset | Bits  | Name           | Description
| ----------- | ----- | ------------   | -------------
| 0x00        | 15:0  | PCR Index      | Index of the hardware PCR which holds the journey PCR for this TCI node
| 0x02        | 15:0  | Parent Index   | Index of the TCI node that is the parent of this node. 0xFF if this node is the root.
| 0x04        | 31:0  | Node Tag       | Tag of this node provided by the TagTci command.
| 0x08        | 159:0 | Context Handle | DPE context handle referring to this node
| 0x1C        | 31    | Internal TCI   | This TCI was measured by Runtime Firmware itself
|             | 30:0  | Reserved       | Reserved flag bits
| 0x20        | 383:0 | Latest TCI     | The latest `INPUT_DATA` extended into this TCI by ExtendTci or DeriveChild

### Certificate Generation

DPE leaf certs are mostly fixed size, but do have some variable-size sections:

* tcg-dice-MultiTcbInfo extension
* Signature

For this reason, DPE must do some ASN.1 generation. An implementation MAY
choose to template certain structures in the certificate for convenience.

The DPE Runtime Alias Key SHALL sign DPE leaf certificates.

The DPE `GET_CERTIFICATE_CHAIN` command shall return the following certificates:

* IDevID
* LDevID
* FMC Alias
* Runtime Alias

### DPE Leaf Certificate Definition

| Field                          | Sub Field   | Value
| -------------                  | ---------   | ---------
| Version                        | v3          | 2
| Serial Number                  |             | First 20 bytes of sha256 hash of DPE Alias public key
| Issuer Name                    | CN          | Caliptra Runtime Alias
|                                | serialNumber | First 20 bytes of sha384 hash of Runtime Alias public key
| Validity                       | notBefore   | February 10th, 2023
|                                | notAfter    | 99991231235959Z
| Subject Name                   | CN          | Caliptra DPE Leaf
|                                | serialNumber | SHA384 hash of Subject public key
| Subject Public Key Info        | Algorithm   | ecdsa-with-SHA384
|                                | Parameters  | Named Curve = prime384v1
|                                | Public Key  | DPE Alias Public Key value
| Signature Algorithm Identifier | Algorithm   | ecdsa-with-SHA384
|                                | Parameters  | Named Curve = prime384v1
| Signature Value                |             | Digital signature for the certificate
| KeyUsage                       | keyCertSign | 1
| Basic Constraints              | CA          | False
| Policy OIDs                    |             | id-tcg-kp-attestLoc
| tcg-dice-MultiTcbInfo\*        | Vendor      | {Vendor-defined}
|                                | Model       | Caliptra
|                                | SVN         | 1
|                                | FWIDs       | [0] "Journey" TCI Value
|                                |             | [1] "Current" TCI Value. Latest `INPUT_DATA` made by DeriveChild or ExtendTci.
|                                | Type        | 4-byte TYPE field of TCI node

\*MultiTcbInfo ontains one TcbInfo for each TCI Node in the path from the
current TCI Node to the root. Max of 24.
