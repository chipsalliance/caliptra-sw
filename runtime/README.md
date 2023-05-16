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
Upon completion, Runtime Firmware will signal `mailbox_data_avail` to notify the
caller. Once the mailbox data has been read and the lock is released,
`mailbox_flow_done` will be signaled to notify callers that the mailbox is ready
for use.

### Fault Handling

A mailbox command can fail to complete in a couple ways

* Hang/timeout which results in the watchdog firing
* Unrecoverable panic

In both these cases, the panic handler will write diagnostic panic information
to registers readable by the SoC, firmware will undergo impactless reset, and
`mailbox_data_avail` will be asserted.

The caller is expected to check status registers upon reading responses from the
mailbox.

Depending on the type of fault, the SoC may:

* Resubmit the mailbox command
* Attempt to update Runtime Firmware
* Perform a full SoC reset
* Some other SoC-specific behavior

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
| `BAD_CHKSUM`     | `0x4243_484B` ("BCHK") | Checksum check failed on input arguments

Relevant Registers:

* mbox\_csr -> COMMAND: Command code to execute
* mbox\_csr -> DLEN: Number of bytes written to mailbox
* CPTRA\_FW\_ERROR\_NON\_FATAL: Status code of mailbox command. Any result
  other than `SUCCESS` signifies a mailbox command failure.

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

`CALIPTRA_FW_LOAD` returns no output arguments.

### GET\_IDEV\_CSR

ROM exposes a command to get a self-signed IDEVID CSR.
GET\_IDEV\_CSR is not exposed by runtime firmware.

Command Code: `0x4944_4556` ("IDEV")

`GET_IDEV_CSR` takes no input arguments.

Table: `GET_IDEV_CSR` output arguments

| **Name**  | **Type**      | **Description**
| --------  | --------      | ---------------
| data      | u8[...]       | DER-encoded IDevID CSR

### GET\_LDEV\_CERT

ROM exposes a command to get a self-signed LDevID Certificate signed by IDevID.
GET\_LDEV\_CERT is not exposed by runtime firmware.

Command Code: `0x4C44_4556` ("LDEV")

`GET_LDEV_CERT` takes no input arguments.

Table: `GET_LDEV_CERT` output arguments

| **Name**  | **Type**      | **Description**
| --------  | --------      | ---------------
| data      | u8[...]       | DER-encoded LDevID Certificate

### ECDSA384\_SIGNATURE\_VERIFY

Verifies an ECDSA P-384 signature. The hash to be verified is taken from
Caliptra's SHA384 accelerator peripheral.

Command Code: `0x5349_4756` ("SIGV")

Table: `ECDSA384_SIGNATURE_VERIFY` input arguments

| **Name**     | **Type** | **Description**
| --------     | -------- | ---------------
| chksum       | u32      | Checksum over other input arguments, computed by the caller. Little endian.
| pub\_key\_x  | u8[48]   | X portion of ECDSA verification key
| pub\_key\_y  | u8[48]   | Y portion of ECDSA verification key
| signature\_r | u8[48]   | R portion of signature to verify
| signature\_s | u8[48]   | S portion of signature to verify

`ECDSA384_SIGNATURE_VERIFY` returns no output arguments.

### STASH\_MEASUREMENT

Make a measurement into the DPE default context. This command is intendend for
callers who update infrequently and cannot tolerate a changing DPE API surface.

Internally, this will call the DPE DeriveChild command.

Command Code: `0x4D45_4153` ("MEAS")

Table: `STASH_MEASUREMENT` input arguments

| **Name**     | **Type** | **Description**
| --------     | -------- | ---------------
| chksum       | u32      | Checksum over other input arguments, computed by the caller. Little endian.
| metadata     | u8[4]    | 4-byte measurement identifier.
| measurement  | u8[48]   | Data to measure into DPE.


Table: `STASH_MEASUREMENT` output arguments

| **Name**    | **Type** | **Description**
| --------    | -------- | ---------------
| chksum      | u32      | Checksum over other output arguments, computed by Caliptra. Little endian.
| dpe\_result | u32      | Result code of DPE DeriveChild command. Little endian.

### DISABLE\_ATTESTATION

Disable attestation by erasing the CDI and DICE key. This command is intended
for callers who update infrequently and cannot tolerate a changing DPE API surface, and is intended for situations where Caliptra firmware cannot be loaded
and the SoC must proceed with boot.

Upon receipt of this command, Caliptra's current CDI is replaced with zeroes,
and the associated DICE key is re-derived from the zeroed CDI.

Command Code: `0x4453_424C` ("DSBL")

`DISABLE_ATTESTATION` takes no input arguments.

`DISABLE_ATTESTATION` returns no output arguments.


### INVOKE\_DPE\_COMMAND

Command Code: `0x4450_4543` ("DPEC")

Table: `INVOKE_DPE_COMMAND` input arguments

| **Name**     | **Type**      | **Description**
| --------     | --------      | ---------------
| chksum       | u32           | Checksum over other input arguments, computed by the caller. Little endian.
| data         | u8[...]       | DPE command structure as defined in the DPE iRoT profile


Table: `INVOKE_DPE_COMMAND` output arguments

| **Name**    | **Type**      | **Description**
| --------    | --------      | ---------------
| chksum      | u32           | Checksum over other output arguments, computed by Caliptra. Little endian.
| data        | u8[...]       | DPE response structure as defined in the DPE iRoT profile.

## Checksum

For every command input/output arguments which have a "chksum" field, the
request and response feature a checksum. This mitigates glitches between clients
and Caliptra.

The Checksum is a little-endian 32-bit value, defined as:

```
0 - (SUM(command code bytes) + SUM(request/response bytes))
```

The sum of all bytes in a request/response body, and command code, should be
zero.

If Caliptra detects an invalid Checksum in input parameters, it will return
`BAD_CHKSUM` as the result.

Caliptra will also compute a Checksum over all responses and write it to the
chksum field.

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

Caliptra Runtime Firmware SHALL implement a profile of the DICE Protection
Environment (DPE) API.

### PAUSER Privilege Levels

Caliptra models PAUSER callers to its mailbox as having 1 of 2 privilege levels:

* PL0 - High Privilege. Only 1 PAUSER in the SoC may be at PL0. The PL0 PAUSER
  is denoted in the signed Caliptra firmware image. The PL0 PAUSER may call any
  supported DPE commands. Only PL0 can use the CertifyKey command. Success of the
  CertifyKey command signifies to the caller that it is at PL0.
* PL1 - Restricted Privilege. All other PAUSERs in the SoC are PL1. Caliptra
  SHALL fail any calls to the DPE CertifyKey command by PL1 callers.
  PL1 callers should use the CertifyCsr command instead.

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

Caliptra SHALL set `MAX_TCI_NODES` to 24. To support this, Caliptra will
allocate 24 hardware PCRs to be exclusively used by DPE.

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

To derive a CDI for a given context, DPE shall use KeyVault hardware with the
following inputs:

If `FIPS_MODE` is disabled for the DPE command OR Sign(SYMMETRIC=true), DPE will

* CDI = Runtime Firmware CDI (from KeyVault)
* Label = LABEL parameter provided to Sign or CertifyKey
* Context = `MEASUREMENT_DATA`

If `FIPS_MODE` is enabled for the DPE command AND Sign(SYMMETRIC=false), DPE will

* CDI = Output from TRNG
* Label = LABEL parameter provided to Sign or CertifyKey
* Context = `MEASUREMENT_DATA`

In either case, the CDI shall be loaded into KeyVault slot 0.

### Leaf Key Derivation

To derive an asymmetric key for Sign and CertifyKey

If `FIPS_MODE` is disabled for the DPE command OR Sign(SYMMETRIC=true), DPE will

* Derive an ECC P384 keypair from KV slot 0 CDI into KV slot 1
* For CertifyKey: Request the public key
* For Sign: Sign passed data
* Erase KeyVault slots 0 and 1

If `FIPS_MODE` is enabled for the DPE command AND Sign(SYMMETRIC=false), DPE will

* If the key has been derived before and is cached in KeyVault
  * Use cached key from KeyVault
* If key is not cached
  * Derive an ECC P384 keypair from KV slot 0 CDI into the next available Runtime
    KeyVault Slot
  * If no slots are available, evict the oldest Runtime slot and use that slot.
* For CertifyKey: Request the public key
* For Sign: Sign passed data
* Erase KeyVault slot 0

### FIPS Mode Caching

Caliptra has 32 KeyVault slots and a max of 24 DPE contexts. To accomodate
FIPS-mode caching, each DPE context will have a dedicated KeyVault slot
for caching FIPS-mode keys. This ensures that a cached key can live for
as long as the context does.

A context's cached FIPS-mode key will be invalidated under the following
circumstances:

* A new measurement is made (DeriveChild or ExtendTci)
* The context is destroyed
* Caliptra Runtime firmware is impactlessly updated to different firmware
  leading to a change in the Runtime CDI.

This gives FIPS-mode keys the following properties:

* During a a steady-state boot, the FIPS-mode key WILL NOT change
* During any type of Caliptra reset (including impactless), the FIPS-mode key
  WILL change
* If the component weilding the key resets or changes its measurements, its
  FIPS-mode key WILL change

For cases like signing attestation messages (SPDM, Confidential Compute) these
properties are acceptable.

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

The DPE Runtime Alias Key SHALL sign DPE leaf certificates and CSRs.

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
|                                | VendorInfo  | Locality of the caller (analog for PAUSER)

\*MultiTcbInfo ontains one TcbInfo for each TCI Node in the path from the
current TCI Node to the root. Max of 24.

# Opens

The following items are still under discussion in the Caliptra WG:

* Expiration of DPE leaf certificates. See https://github.com/chipsalliance/caliptra-sw/issues/16
* Should hardware PCRs be clearable by runtime firmware?
* Should runtime firmware support a quote API for signing hardware PCRs with a
  runtime alias key?
* Should `ECDSA384_SIGNATURE_VERIFY` take an hash from the mailbox or use a
  hash from the SHA block?

Needs clarification or more details:

* Describe mailbox flow for commands which need to send data which exceeds the
  mailbox size
* This specification should fully enumerate how runtime firmware uses shared
  hardware resources. See https://github.com/chipsalliance/caliptra-sw/issues/17
