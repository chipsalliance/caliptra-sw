# Caliptra Runtime Firmware v1.1

This specification describes the Caliptra Runtime Firmware.

## Runtime Firmware environment

This section provides an overview of the Runtime Firmware environment.

### Boot and initialization

The Runtime Firmware main function SHALL perform the following on cold boot reset:

* Initialize the [DICE Protection Environment (DPE)](#dice-protection-environment-dpe)
* Initialize any SRAM structures used by Runtime Firmware

For behavior during other types of reset, see [Runtime firmware updates](#runtime-firmware-updates).

If Runtime Firmware detects that Caliptra was reset during the execution of an operation, Runtime Firmware calls `DISABLE_ATTESTATION` because the internal state of Caliptra may
be corrupted.

### Main loop

After booting, Caliptra Runtime Firmware is responsible for the following.

* Wait for mailbox interrupts. On mailbox interrupt, Runtime Firmware:
  * Reads command from mailbox
  * Executes command
  * Writes response to mailbox and sets necessary status registers
  * Sleeps until next interrupt
* On panic, Runtime Firmware:
  * Saves diagnostic information

Callers must wait until Caliptra is no longer busy to call a mailbox command.

### Fault handling

A mailbox command can fail to complete in the following ways:

* Hang or timeout, which result in the watchdog firing
* Unrecoverable panic

In both of these cases, the panic handler writes diagnostic panic information
to registers that are readable by the SoC. Firmware then undergoes an impactless reset.

The caller is expected to check status registers upon reading responses from the
mailbox.

Depending on the type of fault, the SoC may:

* Resubmit the mailbox command
* Attempt to update Runtime Firmware
* Perform a full SoC reset
* Some other SoC-specific behavior

### Drivers

Caliptra Runtime Firmware will share driver code with ROM and FMC where
possible; however, it will have its own copies of all of these drivers linked into
the Runtime Firmware binary.

## Manifest-Based Image Authorization (new in 1.2)

Caliptra's goal is to enable integrators to meet standard security requirements for creating cryptographic identity and securely reporting measurements through DICE and DPE Certificate chains and Caliptra-owned private-public key pairs. In addition, Caliptra 1.0 provides an `ECDSA384_SIGNATURE_VERIFY` command to enable an SoC RoT to verify its own FW signatures so that it can develop an SoC secure boot using Caliptra cryptography. Caliptra 1.1 expanded the verify command to a PQC-safe `LMS_SIGNATURE_VERIFY` command. In each of these cases, it is left up to the vendor to ensure that they build a secure environment for introducing and verifying FW integrity and authenticity and then executing mutable FW.

The Caliptra Measurement manifest feature expands on Caliptra-provided secure verifier abilities. The Measurement Manifest feature provides a standard Caliptra-supported definition to enable the following use cases for integrators, vendors, and owners.

* Caliptra-Endorsed Aggregated Measured Boot
* Caliptra-Endorsed Local Verifier

Each of these abilities are tied to Caliptra Vendor and Owner FW signing keys and should be independent of any SoC RoT FW signing keys.

Manifest-based image authorization is implemented via two mailbox commands: [`SET_AUTH_MANIFEST`](#set-auth-manifest) and [`AUTHORIZE_AND_STASH`](#authorize-and-stash). For image format of the manifest, please refer [this file](../auth-manifest/README.md).

### Caliptra-Endorsed Aggregated Measured Boot

Aggregated Measured Boot is a verified boot where one signed manifest attests to FW integrity of many different FW measurements. The authenticity of the FW is tied to the trust in the public key signing the measurement manifest, which is endorsed by the Caliptra Vendor and/or Owner FW Keys.

### Caliptra-Endorsed Local Verifier

A local verifier provides an authentication of SoC FW by matching SoC FW measurements with measurements from the Caliptra measurement manifest. In this case, the SoC RoT still has its own FW public-key chain that is verified by the SoC RoT, but in addition the SoC RoT introduces the Caliptra Measurement Manifest, which is endorsed by the Caliptra FW key pair. Caliptra provides approval or disapproval of the measurement of any FW back to the SoC RoT. This effectively provides a multi-factor authentication of SoC FW.

The Caliptra-Endorsed Local Verifier could be required by the owner only or both the vendor and the owner.

The main difference between Caliptra-Endorsed Aggregated Measured Boot and Caliptra-Endorsed Local Verifier is whether the SoC RoT is relying on the Measurement Manifest for SoC Secure Boot services as opposed to using it as an additional verification.

### SoC RoT Enforcement of Measurement Manifest

In both use cases, the SoC RoT chooses to provide the Caliptra Measurement Manifest and to enforce the result of the authorization. Caliptra 1.x is not capable of providing any enforcement of measurements for SoC FW execution.

### Caliptra Measurement Manifest Signing Keys Authenticity

Caliptra 1.0 and 1.1 do not put any requirements on how the SoC RoT ensures integrity and authenticity of SoC FW other than requiring the SoC RoT to provide a measurement to Caliptra of any SoC FW before execution. Caliptra Measurement Manifest enables the SoC RoT to perform the integrity check through Caliptra-authorized FW signing keys.

### Unique Measurement Manifest Signing Keys

In order to reduce usage of the Caliptra FW Signing keys, the measurement manifest will be signed by new key pairs: one for the owner and optionally one for the vendor. These new key pairs are endorsed once by the Caliptra FW signing keys, the signature being in the Measurement Manifest, thus allowing the measurement manifest keys to be used independently of the Caliptra FW signing keys.

### Caliptra Measurement Manifest Vendor Public Key Authenticity

The Measurement Manifest MUST have an endorsement by the Caliptra Vendor Public Key. In order to fulfill this requirement, the Vendor has 2 options:

* Vendor signing of `Image Metadata Collection` required: The Vendor creates a new Measurement keypair which will sign the measurement manifest and endorses this new public key with the Caliptra FW Vendor Private Key. The signature covers both the new public key as well as the flags field which indicates that the new Measurement Key Pair will be enforced.
* Vendor signing of `Image Metadata Collection` **not** required: Vendor leaves the Vendor public key as all zeros, and clears the flag which enforces vendor signing and then endorses these fields with a signature in the Measurement Manifest. In this case, the Vendor releases ownership of enforcing any specific FW in execution.

### Caliptra Measurement Manifest Owner Public Key Authenticity

Caliptra will always verify the endorsement of the Measurement Manifest Owner Public key and require that it signed the measurement manifest.

This feature is accomplished by having the SoC send a manifest to Caliptra Runtime through the `SET_AUTH_MANIFEST` mailbox command. The manifest will include a set of hashes for the different SoC images. Later, the SOC will ask for authorization for its images from the Caliptra Runtime through the `AUTHORIZE_AND_STASH` new mailbox command. Caliptra Runtime will authorize the image based on whether its hash was contained in the manifest.

#### Preamble

The manifest begins with the Preamble section, which contains new manifest ECC and LMS public keys of the vendor and the owner. These public keys correspond to the private keys that sign the Image Metadata Collection (IMC) section. These signatures are included in the Preamble. The Caliptra firmware's private keys endorse the manifest's public keys and these endorsements (i.e., signatures) are part of the Preamble as well.

#### Image Metadata Collection (IMC)

The IMC is a collection of Image Metadata entries (IME). Each IME has a hash that matches one of the multiple SoC images. The manifest vendor and owner private keys sign the IMC. The Preamble holds the IMC signatures. The manifest IMC vendor signatures are optional and are validated only if the Flags field Bit 0 is set to 1. Up to 127 image hashes will be supported.

#### Caliptra Measurement Manifest Keys Endorsement Verification Steps

When Caliptra receives the Measurement Manifest, Caliptra will:

* Verify the vendor endorsement using the Caliptra Vendor FW Public Key and compare with the vendor endorsement signature.
* If the vendor endorsement is invalid, the `SET_AUTH_MANIFEST` command will be rejected.
* If the vendor endorsement is valid, Caliptra will check if a vendor manifest measurement key is required:
    * If the key is required, Caliptra will trust the Vendor Public key that was just endorsed.
    * If the key is not required, Caliptra will not perform any more vendor verifications on this measurement manifest.
* Verify the owner endorsement using the Caliptra owner public key and compare with the owner endorsement signature.
    * If the owner endorsement is invalid, the `SET_AUTH_MANIFEST` command will be rejected.
    * Otherwise, the owner public key will be trusted and Caliptra will use it to verify the overall measurement manifest.

### Image Authorization Sequence

The diagram below illustrates how this feature is part of the Caliptra boot flow, and the order of operations needed to use the feature.

```mermaid
sequenceDiagram
    ROM->>FMC: Launch FMC
    FMC->>Runtime: Launch RT
    Runtime->>SOC: RDY_FOR_RT
    Note over Runtime,SOC: Manifest Load
    SOC->>Runtime: SET_AUTH_MANIFEST
    Runtime-->>SOC: Success/Failure
    Note over Runtime,SOC: Image Authorization
    loop n times
        SOC->>Runtime: AUTHORIZE_AND_STASH
        Runtime-->>SOC: Success/Failure
    end

    Note over Runtime,SOC: DPE Attestation
    SOC->>Runtime: DPE Attestation
```

## Mailbox commands

All mailbox command codes are little endian.

*Table: Mailbox command result codes*

| **Name**         | **Value**              | Description
| -------          | -----                  | -----------
| `SUCCESS`        | `0x0000_0000`          | Mailbox command succeeded
| `BAD_VENDOR_SIG` | `0x5653_4947` ("VSIG") | Vendor signature check failed
| `BAD_OWNER_SIG`  | `0x4F53_4947` ("OSIG") | Owner signature check failed
| `BAD_SIG`        | `0x4253_4947` ("BSIG") | Generic signature check failure (for crypto offload)
| `BAD_IMAGE`      | `0x4249_4D47` ("BIMG") | Malformed input image
| `BAD_CHKSUM`     | `0x4243_484B` ("BCHK") | Checksum check failed on input arguments

Relevant registers:

* mbox\_csr -> COMMAND: Command code to execute.
* mbox\_csr -> DLEN: Number of bytes written to mailbox.
* CPTRA\_FW\_ERROR\_NON\_FATAL: Status code of mailbox command. Any result
  other than `SUCCESS` signifies a mailbox command failure.

### CALIPTRA\_FW\_LOAD

The `CALIPTRA_FW_LOAD` command is handled by both ROM and Runtime Firmware.

#### ROM behavior

On cold boot, ROM exposes the `CALIPTRA_FW_LOAD` mailbox command to accept
the firmware image that ROM will boot. This image includes Manifest, FMC, and Runtime
firmware.

#### Runtime Firmware behavior

Caliptra Runtime Firmware also exposes the `CALIPTRA_FW_LOAD` mailbox command for loading
impactless updates. For more information, see [Runtime Firmware updates](#runtime-firmware-updates).

Command Code: `0x4657_4C44` ("FWLD")

*Table: `CALIPTRA_FW_LOAD` input arguments*

| **Name**  | **Type**      | **Description**
| --------  | --------      | ---------------
| data      | u8[...]       | Firmware image to load.

`CALIPTRA_FW_LOAD` returns no output arguments.

### CAPABILITIES

Exposes a command to retrieve firmware capabilities

Command Code: `0x4341_5053` ("CAPS")

*Table: `CAPABILITIES` input arguments*

| **Name**  | **Type**      | **Description**
| --------  | --------      | ---------------
| chksum    | u32           | Checksum over other input arguments, computed by the caller. Little endian.

*Table: `CAPABILITIES` output arguments*

| **Name**      | **Type**   | **Description**
| --------      | --------   | ---------------
| chksum        | u32        | Checksum over other output arguments, computed by Caliptra. Little endian.
| fips\_status  | u32        | Indicates if the command is FIPS approved or an error.
| capabilities  | u8[16]     | Firmware capabilities

### GET\_IDEV\_CERT

Exposes a command to reconstruct the IDEVID CERT.

Command Code: `0x4944_4543` ("IDEC")

*Table: `GET_IDEV_CERT` input arguments*

| **Name**      | **Type**      | **Description**
| --------      | --------      | ---------------
| chksum        | u32           | Checksum over other input arguments, computed by the caller. Little endian.
| signature\_r  | u8[48]        | R portion of signature of the cert.
| signature\_s  | u8[48]        | S portion of signature of the cert.
| tbs\_size     | u32           | Size of the TBS.
| tbs           | u8[916]       | TBS, with a maximum size of 916. Only bytes up to tbs_size are used.

*Table: `GET_IDEV_CERT` output arguments*

| **Name**      | **Type**   | **Description**
| --------      | --------   | ---------------
| chksum        | u32        | Checksum over other output arguments, computed by Caliptra. Little endian.
| fips\_status  | u32        | Indicates if the command is FIPS approved or an error.
| cert\_size    | u32        | Length in bytes of the cert field in use for the IDevId certificate.
| cert          | u8[1024]   | DER-encoded IDevID CERT.

### POPULATE\_IDEV\_CERT

Exposes a command that allows the SoC to provide a DER-encoded
IDevId certificate on every boot. The IDevId certificate is added
to the start of the certificate chain.

Command Code: `0x4944_4550` ("IDEP")

*Table: `POPULATE_IDEV_CERT` input arguments*

| **Name**     | **Type**      | **Description**
| --------     | --------      | ---------------
| chksum       | u32           | Checksum over other input arguments, computed by the caller. Little endian.
| cert\_size   | u32           | Size of the DER-encoded IDevId certificate.
| cert         | u8[1024]      | DER-encoded IDevID CERT.

*Table: `POPULATE_IDEV_CERT` output arguments*

| **Name**      | **Type** | **Description**
| --------      | -------- | ---------------
| chksum        | u32      | Checksum over other output arguments, computed by Caliptra. Little endian.
| fips\_status  | u32      | Indicates if the command is FIPS approved or an error.

### GET\_IDEV\_INFO

Exposes a command to get an IDEVID public key.

Command Code: `0x4944_4549` ("IDEI")

*Table: `GET_IDEV_INFO` input arguments*

| **Name**  | **Type**      | **Description**
| --------  | --------      | ---------------
| chksum    | u32           | Checksum over other input arguments, computed by the caller. Little endian.

*Table: `GET_IDEV_INFO` output arguments*

| **Name**      | **Type**   | **Description**
| --------      | --------   | ---------------
| chksum        | u32        | Checksum over other output arguments, computed by Caliptra. Little endian.
| fips\_status  | u32        | Indicates if the command is FIPS approved or an error.
| idev\_pub\_x  | u8[48]     | X portion of ECDSA IDevId key.
| idev\_pub\_y  | u8[48]     | Y portion of ECDSA IDevId key.

### GET\_LDEV\_CERT

Exposes a command to get an LDevID certificate signed by IDevID.

Command Code: `0x4C44_4556` ("LDEV")

*Table: `GET_LDEV_CERT` input arguments*

| **Name**  | **Type**      | **Description**
| --------  | --------      | ---------------
| chksum    | u32           | Checksum over other input arguments, computed by the caller. Little endian.

*Table: `GET_LDEV_CERT` output arguments*

| **Name**      | **Type**   | **Description**
| --------      | --------   | ---------------
| chksum        | u32        | Checksum over other output arguments, computed by Caliptra. Little endian.
| fips\_status  | u32        | Indicates if the command is FIPS approved or an error.
| data\_size    | u32        | Length in bytes of the valid data in the data field.
| data          | u8[...]    | DER-encoded LDevID certificate.

### GET\_FMC\_ALIAS\_CERT

Exposes a command to get an FMC alias certificate signed by LDevID.

Command Code: `0x4345_5246` ("CERF")

*Table: `GET_FMC_ALIAS_CERT` input arguments*

| **Name**  | **Type**      | **Description**
| --------  | --------      | ---------------
| chksum    | u32           | Checksum over other input arguments, computed by the caller. Little endian.

*Table: `GET_FMC_ALIAS_CERT` output arguments*

| **Name**      | **Type**   | **Description**
| --------      | --------   | ---------------
| chksum        | u32        | Checksum over other output arguments, computed by Caliptra. Little endian.
| fips\_status  | u32        | Indicates if the command is FIPS approved or an error.
| data\_size    | u32        | Length in bytes of the valid data in the data field.
| data          | u8[...]    | DER-encoded FMC alias certificate.

### GET\_RT\_ALIAS\_CERT

Exposes a command to get a Runtime alias certificate signed by the FMC alias.

Command Code: `0x4345_5252` ("CERR")

*Table: `GET_RT_ALIAS_CERT` input arguments*

| **Name**  | **Type**      | **Description**
| --------  | --------      | ---------------
| chksum    | u32           | Checksum over other input arguments, computed by the caller. Little endian.

*Table: `GET_RT_ALIAS_CERT` output arguments*

| **Name**      | **Type**   | **Description**
| --------      | --------   | ---------------
| chksum        | u32        | Checksum over other output arguments, computed by Caliptra. Little endian.
| fips\_status  | u32        | Indicates if the command is FIPS approved or an error.
| data\_size    | u32        | Length in bytes of the valid data in the data field.
| data          | u8[...]    | DER-encoded Runtime alias certificate.

### ECDSA384\_SIGNATURE\_VERIFY

Verifies an ECDSA P-384 signature. The hash to be verified is taken from
Caliptra's SHA384 accelerator peripheral.

In the event of an invalid signature, the mailbox command will report CMD_FAILURE
and the cause will be logged as a non-fatal error.

Command Code: `0x5349_4756` ("SIGV")

*Table: `ECDSA384_SIGNATURE_VERIFY` input arguments*

| **Name**     | **Type** | **Description**
| --------     | -------- | ---------------
| chksum       | u32      | Checksum over other input arguments, computed by the caller. Little endian.
| pub\_key\_x  | u8[48]   | X portion of ECDSA verification key.
| pub\_key\_y  | u8[48]   | Y portion of ECDSA verification key.
| signature\_r | u8[48]   | R portion of signature to verify.
| signature\_s | u8[48]   | S portion of signature to verify.

*Table: `ECDSA384_SIGNATURE_VERIFY` output arguments*

| **Name**      | **Type** | **Description**
| --------      | -------- | ---------------
| chksum        | u32      | Checksum over other output arguments, computed by Caliptra. Little endian.
| fips\_status  | u32      | Indicates if the command is FIPS approved or an error.

### LMS\_SIGNATURE\_VERIFY

Verifies an LMS signature. The hash to be verified is taken from
Caliptra's SHA384 accelerator peripheral.

In the event of an invalid signature, the mailbox command will report CMD_FAILURE
and the cause will be logged as a non-fatal error.

The supported parameter set is limited to those used for the caliptra image signature:
*Table: LMS parameters*
| **Param Name**        | **Value** | **Description**
| --------------        | --------- | ---------------
| LMS algorithm type    | 12        | 12 = LmsSha256N24H15
| LM-OTS algorithm type | 7         | 7 = LmotsSha256N24W4
| n                     | 24        | Bytes of output from sha256/192 hash function
| w                     | 4         | Width (in bits) of the Winternitz coefficient
| h                     | 15        | Height of the tree

Command Code: `0x4C4D_5356` ("LMSV")

*Table: `LMS_SIGNATURE_VERIFY` input arguments*

| **Name**              | **Type** | **Description**
| --------              | -------- | ---------------
| chksum                | u32      | Checksum over other input arguments, computed by the caller. Little endian.
| pub\_key\_tree\_type  | u8[4]    | LMS public key algorithm type. Must equal 12.
| pub\_key\_ots\_type   | u8[4]    | LM-OTS algorithm type. Must equal 7.
| pub\_key\_id          | u8[16]   | "I" Private key identifier
| pub\_key\_digest      | u8[24]   | "T[1]" Public key hash value
| signature\_q          | u8[4]    | Leaf of the Merkle tree where the OTS public key appears
| signature\_ots        | u8[1252] | LM-OTS signature
| signature\_tree\_type | u8[4]    | LMS signature Algorithm type. Must equal 12.
| signature\_tree\_path | u8[360]  | Path through the tree from the leaf associated with the LM-OTS signature to the root

*Table: `LMS_SIGNATURE_VERIFY` output arguments*

| **Name**    | **Type** | **Description**
| --------    | -------- | ---------------
| chksum      | u32      | Checksum over other output arguments, computed by Caliptra. Little endian.
| fips\_status | u32      | Indicates if the command is FIPS approved or an error.

### STASH\_MEASUREMENT

Makes a measurement into the DPE default context. This command is intended for
callers who update infrequently and cannot tolerate a changing DPE API surface.

* Call the DPE DeriveContext command with the DefaultContext in the locality of
  the PL0 PAUSER.
* Extend the measurement into PCR31 (`PCR_ID_STASH_MEASUREMENT`).
* **Note**: This command can only be called in the locality of the PL0 PAUSER. 

Command Code: `0x4D45_4153` ("MEAS")

*Table: `STASH_MEASUREMENT` input arguments*

| **Name**     | **Type** | **Description**
| --------     | -------- | ---------------
| chksum       | u32      | Checksum over other input arguments, computed by the caller. Little endian.
| metadata     | u8[4]    | 4-byte measurement identifier.
| measurement  | u8[48]   | Data to measure into DPE.
| context      | u8[48]   | Context field for `svn`; e.g., a hash of the public key that authenticated the SVN.
| svn          | u32      | SVN passed to the DPE to be used in the derived child.

*Table: `STASH_MEASUREMENT` output arguments*

| **Name**      | **Type** | **Description**
| --------      | -------- | ---------------
| chksum        | u32      | Checksum over other output arguments, computed by Caliptra. Little endian.
| fips\_status  | u32      | Indicates if the command is FIPS approved or an error.
| dpe\_result   | u32      | Result code of DPE DeriveContext command. Little endian.

### DISABLE\_ATTESTATION

Disables attestation by erasing the CDI and DICE key. This command is intended
for callers who update infrequently and cannot tolerate a changing DPE API
surface. It is intended for situations where Caliptra firmware cannot be loaded
and the SoC must proceed with boot.

Upon receipt of this command, Caliptra's current CDI is replaced with zeroes,
and the associated DICE key is re-derived from the zeroed CDI.

This command is intended to allow the SoC to continue booting for diagnostic
and error reporting. All attestations produced in this mode are expected to
fail certificate chain validation. Caliptra MUST undergo a cold reset in order
to re-enable attestation.

Command Code: `0x4453_424C` ("DSBL")

*Table: `DISABLE_ATTESTATION` input arguments*

| **Name**  | **Type**      | **Description**
| --------  | --------      | ---------------
| chksum    | u32           | Checksum over other input arguments, computed by the caller. Little endian.

*Table: `DISABLE_ATTESTATION` output arguments*

| **Name**      | **Type** | **Description**
| --------      | -------- | ---------------
| chksum        | u32      | Checksum over other output arguments, computed by Caliptra. Little endian.
| fips\_status  | u32      | Indicates if the command is FIPS approved or an error.

### INVOKE\_DPE\_COMMAND

Invokes a serialized DPE command.

Command Code: `0x4450_4543` ("DPEC")

*Table: `INVOKE_DPE_COMMAND` input arguments*

| **Name**     | **Type**      | **Description**
| --------     | --------      | ---------------
| chksum       | u32           | Checksum over other input arguments, computed by the caller. Little endian.
| data\_size   | u32           | Length in bytes of the valid data in the data field.
| data         | u8[...]       | DPE command structure as defined in the DPE iRoT profile.

*Table: `INVOKE_DPE_COMMAND` output arguments*

| **Name**      | **Type**      | **Description**
| --------      | --------      | ---------------
| chksum        | u32           | Checksum over other output arguments, computed by Caliptra. Little endian.
| fips\_status  | u32           | Indicates if the command is FIPS approved or an error.
| data\_size    | u32           | Length in bytes of the valid data in the data field.
| data          | u8[...]       | DPE response structure as defined in the DPE iRoT profile.

### QUOTE\_PCRS

Generates a signed quote over all Caliptra hardware PCRs that are using the Caliptra PCR quoting key.
All PCR values are hashed together with the nonce to produce the quote.

Command Code: `0x5043_5251` ("PCRQ")

*Table: `QUOTE_PCRS` input arguments*

| **Name**     | **Type**      | **Description**
| --------     | --------      | ---------------
| chksum       | u32           | Checksum over other input arguments, computed by the caller. Little endian.
| nonce        | u8[32]        | Caller-supplied nonce to be included in signed data.

PcrValue is defined as u8[48]

*Table: `QUOTE_PCRS` output arguments*

| **Name**     | **Type**     | **Description**
| --------     | --------     | ---------------
| chksum       | u32          | Checksum over other output arguments, computed by Caliptra. Little endian.
| fips\_status | u32          | Indicates if the command is FIPS approved or an error.
| PCRs         | PcrValue[32] | Values of all PCRs.
| nonce        | u8[32]       | Return the nonce used as input for convenience.
| digest       | u8[48]       | Return the digest over the PCR values and the nonce.
| reset\_ctrs  | u32[32]      | Reset counters for all PCRs.
| signature\_r | u8[48]       | R portion of the signature over the PCR quote.
| signature\_s | u8[48]       | S portion of the signature over the PCR quote.

### EXTEND\_PCR

Extends a Caliptra hardware PCR.

Command Code: `0x5043_5245` ("PCRE")

*Table: `EXTEND_PCR` input arguments*

| **Name**     | **Type**      | **Description**
| --------     | --------      | ---------------
| chksum       | u32           | Checksum over other input arguments, computed by the caller. Little endian.
| index        | u32           | Index of the PCR to extend.
| value        | u8[..]        | Value to extend into the PCR at `index`.

*Table: `EXTEND_PCR` output arguments*

| **Name**      | **Type** | **Description**
| --------      | -------- | ---------------
| chksum        | u32      | Checksum over other output arguments, computed by Caliptra. Little endian.
| fips\_status  | u32      | Indicates if the command is FIPS approved or an error.

Note that extensions made into Caliptra's PCRs are _not_ appended to Caliptra's internal PCR log.

### GET\_PCR\_LOG

Gets Caliptra's internal PCR log.

Command Code: `0x504C_4F47` ("PLOG")

*Table: `GET_PCR_LOG` input arguments*

| **Name**  | **Type**      | **Description**
| --------  | --------      | ---------------
| chksum    | u32           | Checksum over other input arguments, computed by the caller. Little endian.

*Table: `GET_PCR_LOG` output arguments*

| **Name**      | **Type**   | **Description**
| --------      | --------   | ---------------
| chksum        | u32        | Checksum over other output arguments, computed by Caliptra. Little endian.
| fips\_status  | u32        | Indicates if the command is FIPS approved or an error.
| data\_size    | u32        | Length in bytes of the valid data in the data field.
| data          | u8[...]    | Internal PCR event log.

See [pcr\_log.rs](../drivers/src/pcr_log.rs) for the format of the log.

Note: the log contents reflect PCR extensions that are made autonomously by Caliptra during boot. The log contents
are not preserved across cold or update resets. Callers who wish to verify PCRs that are autonomously
extended during update reset should cache the log before triggering an update reset.

### INCREMENT\_PCR\_RESET\_COUNTER

Increments the reset counter for a PCR.

Command Code: `0x5043_5252` ("PCRR")

*Table: `INCREMENT_PCR_RESET_COUNTER` input arguments*

| **Name**     | **Type**      | **Description**
| --------     | --------      | ---------------
| chksum       | u32           | Checksum over other input arguments, computed by the caller. Little endian.
| index        | u32           | Index of the PCR for which to increment the reset counter.

*Table: `INCREMENT_PCR_RESET_COUNTER` output arguments*

| **Name**      | **Type** | **Description**
| --------      | -------- | ---------------
| chksum        | u32      | Checksum over other output arguments, computed by Caliptra. Little endian.
| fips\_status  | u32      | Indicates if the command is FIPS approved or an error.

### DPE\_TAG\_TCI

Associates a unique tag with a DPE context.

Command Code: `0x5451_4754` ("TAGT")

*Table: `DPE_TAG_TCI` input arguments*

| **Name**     | **Type**      | **Description**
| --------     | --------      | ---------------
| chksum       | u32           | Checksum over other input arguments, computed by the caller. Little endian.
| handle       | u8[16]        | DPE context handle.
| tag          | u32           | A unique tag that the handle will be associated with.

*Table: `DPE_TAG_TCI` output arguments*

| **Name**      | **Type** | **Description**
| --------      | -------- | ---------------
| chksum        | u32      | Checksum over other output arguments, computed by Caliptra. Little endian.
| fips\_status  | u32      | Indicates if the command is FIPS approved or an error.

### DPE\_GET\_TAGGED\_TCI

Retrieves the TCI measurements corresponding to the tagged DPE context.

Command Code: `0x4754_4744` ("GTGD")

*Table: `DPE_GET_TAGGED_TCI` input arguments*

| **Name**     | **Type**      | **Description**
| --------     | --------      | ---------------
| chksum       | u32           | Checksum over other input arguments, computed by the caller. Little endian.
| tag          | u32           | A unique tag corresponding to a DPE context.

*Table: `DPE_GET_TAGGED_TCI` output arguments*

| **Name**         | **Type**  | **Description**
| --------         | --------  | ---------------
| chksum           | u32       | Checksum over other input arguments, computed by the caller. Little endian.
| fips\_status     | u32       | Indicates if the command is FIPS approved or an error.
| tci\_cumulative  | u8[48]    | Hash of all of the input data provided to the context.
| tci\_current     | u8[48]    | Most recent measurement made into the context.

### FW\_INFO

Retrieves information about the current Runtime Firmware, FMC, and ROM.

NOTE: Additional fields and info may be appended to the response in subsequent FW versions.

Command Code: `0x494E_464F` ("INFO")

*Table: `FW_INFO` input arguments*

| **Name**     | **Type**      | **Description**
| --------     | --------      | ---------------
| chksum       | u32           | Checksum over other input arguments, computed by the caller. Little endian.

*Table: `FW_INFO` output arguments*

| **Name**               | **Type**       | **Description**
| --------               | --------       | ---------------
| chksum                 | u32            | Checksum over other input arguments, computed by the caller. Little endian.
| fips\_status           | u32            | Indicates if the command is FIPS approved or an error.
| pl0_pauser             | u32            | PAUSER with PL0 privileges (from image header).
| runtime_svn            | u32            | Runtime SVN.
| min_runtime_svn        | u32            | Min Runtime SVN.
| fmc_manifest_svn       | u32            | FMC SVN.
| attestation_disabled   | u32            | State of attestation disable.
| rom_revision           | u8[20]         | Revision (Git commit ID) of ROM build.
| fmc_revision           | u8[20]         | Revision (Git commit ID) of FMC build.
| runtime_revision       | u8[20]         | Revision (Git commit ID) of runtime build.
| rom_sha256_digest      | u32[8]         | Digest of ROM binary.
| fmc_sha384_digest      | u32[12]        | Digest of FMC binary.
| runtime_sha384_digest  | u32[12]        | Digest of runtime binary.
| owner_pub_key_hash     | u32[12]        | Hash of the owner public keys provided in the image bundle manifest.

### VERSION

FIPS command to get version info for the module

Command Code: `0x4650_5652` ("FPVR")

Table: `VERSION` input arguments

| **Name**     | **Type**  | **Description**
| --------     | --------  | ---------------
| chksum       | u32       | Checksum over other input arguments, computed by the caller. Little endian.

Table: `VERSION` output arguments

| **Name**     | **Type**  | **Description**
| --------     | --------  | ---------------
| chksum       | u32       | Checksum over other output arguments, computed by Caliptra. Little endian.
| fips_status  | u32       | Indicates if the command is FIPS approved or an error
| mode         | u32       | Mode identifier
| fips_rev     | u32[3]    | [31:0] HW rev ID, [47:32] ROM version, [63:48] FMC version, [95:64] FW version
| name         | u8[12]    | 12 character module name "Caliptra RTM"

### SELF\_TEST\_START

FIPS command to start the self tests

Command Code: `0x4650_4C54`

Table: `SELF_TEST_START` input arguments

| **Name**     | **Type**  | **Description**
| --------     | --------  | ---------------
| chksum       | u32       | Checksum over other input arguments, computed by the caller. Little endian.

Table: `SELF_TEST_START` output arguments

| **Name**     | **Type**  | **Description**
| --------     | --------  | ---------------
| chksum       | u32       | Checksum over other output arguments, computed by Caliptra. Little endian.
| fips_status  | u32       | Indicates if the command is FIPS approved or an error

### SELF\_TEST\_GET\_RESULTS

FIPS command to get the results of the self tests. Mailbox command will return a failure if still active.

Command Code: `0x4650_4C67`

Table: `SELF_TEST_GET_RESULTS` input arguments

| **Name**     | **Type**  | **Description**
| --------     | --------  | ---------------
| chksum       | u32       | Checksum over other input arguments, computed by the caller. Little endian.

Table: `SELF_TEST_GET_RESULTS` output arguments

| **Name**     | **Type**  | **Description**
| --------     | --------  | ---------------
| chksum       | u32       | Checksum over other output arguments, computed by Caliptra. Little endian.
| fips_status  | u32       | Indicates if the command is FIPS approved or an error

### SHUTDOWN

FIPS command to zeroize and shut down the module

Command Code: `0x4650_5344` ("FPSD")

Table: `SHUTDOWN` input arguments

| **Name**     | **Type**  | **Description**
| --------     | --------  | ---------------
| chksum       | u32       | Checksum over other input arguments, computed by the caller. Little endian.

Table: `SHUTDOWN` output arguments

| **Name**     | **Type**  | **Description**
| --------     | --------  | ---------------
| chksum       | u32       | Checksum over other output arguments, computed by Caliptra. Little endian.
| fips_status  | u32       | Indicates if the command is FIPS approved or an error

### ADD\_SUBJECT\_ALT\_NAME

Provides a subject alternative name otherName. Whenever CERTIFY_KEY_EXTENDED is called with the 
DMTF_OTHER_NAME flag after ADD_SUBJECT_ALT_NAME is called, the resulting DPE CSR or leaf certificate 
will contain a subject alternative name extension containing the provided otherName, which must be a 
DMTF device info. All such certificates produced by CERTIFY_KEY_EXTENDED will continue to have the 
DMTF otherName subject alternative name extension until reset.

Command Code: `0x414C_544E` ("ALTN")

*Table: `ADD_SUBJECT_ALT_NAME` input arguments*

| **Name**                  | **Type** | **Description**
| --------                  | -------- | ---------------
| chksum                    | u32      | Checksum over other input arguments, computed by the caller. Little endian.
| dmtf\_device\_info\_size  | u32      | The size of the DMTF Device Info UTF8String.
| dmtf\_device\_info        | u8[128]  | The DMTF Device Info UTF8String.

*Table: `ADD_SUBJECT_ALT_NAME` output arguments*

| **Name**     | **Type** | **Description**
| --------     | -------- | ---------------
| chksum       | u32      | Checksum over other output arguments, computed by Caliptra. Little endian.
| fips\_status | u32      | Indicates if the command is FIPS approved or an error.

### CERTIFY\_KEY\_EXTENDED

Produces a DPE leaf certificate or CSR containing custom extensions provided by the SoC.

Command Code: `0x434B_4558` ("CKEX")

*Table: `CERTIFY_KEY_EXTENDED` input arguments*

| **Name**           | **Type** | **Description**
| --------           | -------- | ---------------
| chksum             | u32      | Checksum over other input arguments, computed by the caller. Little endian.
| certify\_key\_req  | u8[72]   | Certify Key Request.
| flags              | u32      | Flags determining which custom extensions to include in the certificate.

*Table: `CERTIFY_KEY_EXTENDED` input flags*

| **Name**              | **Offset** 
| --------              | ----------
| DMTF_OTHER_NAME       | 1 << 31      

*Table: `CERTIFY_KEY_EXTENDED` output arguments*

| **Name**            | **Type**  | **Description**
| --------            | --------  | ---------------
| chksum              | u32       | Checksum over other output arguments, computed by Caliptra. Little endian.
| fips\_status        | u32       | Indicates if the command is FIPS approved or an error.
| certify\_key\_resp  | u8[2176]  | Certify Key Response.

### SET\_AUTH\_MANIFEST

Command Code: `0x4154_4D4E` ("ATMN")

*Table: `SET_AUTH_MANIFEST` input arguments*

| **Name**                      | **Type**  | **Description** |
| ------------------------------| ------------------| --------------- |
| chksum                        | u32                 | Checksum over other input arguments, computed by the caller. Little endian. |
| manifest size                 | u32                 | The size of the full Authentication Manifest |
| manifest\_marker              | u32                 | Marker needs to be 0x4154_4D4E for the preamble to be valid |
| preamble\_size                | u32                 | Size of the preamble |
| manifest\_version             | u32                 | Version of the preamble |
| manifest\_flags               | u32                 | Manifest flags. See `AUTH_MANIFEST_FLAGS` below. |
| manifest\_vendor\_ecc384\_key | u32[24]                | Manifest Vendor ECC P-384 public key used to verify the IMC Signature. <br> **X-Coordinate:** Public Key X-Coordinate (48 bytes) <br> **Y-Coordinate:** Public Key Y-Coordinate (48 bytes) |
| manifest\_vendor\_lms\_key    | u32[12]                | Manifest Vendor LMS public key used to verify the IMC Signature. <br> **tree_type:** LMS Algorithm Type (4 bytes) <br> **otstype:** LMS Ots Algorithm Type (4 bytes) <br> **id:**  (16 bytes) <br> **digest:**  (24 bytes) <br> Note: If LMS validation is not required, this should field should be zeroed out. |
| manifest\_vendor\_ecc384\_sig | u32[24]                | Manifest Vendor ECDSA P-384 signature of the Version, Flags, Vendor ECC and LMS public keys, hashed using SHA2-384. <br> **R-Coordinate:** Random Point (48 bytes) <br> **S-Coordinate:** Proof (48 bytes) |
| manifest\_vendor\_LMS\_sig    | u32[405]              | Vendor LMS signature of the Version, Flags, Vendor ECC and LMS public keys, hashed using SHA2-384. <br> **q:** Leaf of the Merkle tree where the OTS public key appears (4 bytes) <br> **ots:** Lmots Signature (1252 bytes) <br> **tree_type:** Lms Algorithm Type (4 bytes) <br> **tree_path:** Path through the tree from the leaf associated with the LM-OTS signature to the root. (360 bytes) <br> Note: If LMS validation is not required, this should field should be zeroed out. |
| manifest\_owner\_ecc384\_key  | u32[24]                | Manifest Owner ECC P-384 public key used to verify the IMC Signature. <br> **X-Coordinate:** Public Key X-Coordinate (48 bytes) <br> **Y-Coordinate:** Public Key Y-Coordinate (48 bytes) |
| manifest\_owner\_lms\_key     | u32[12]                | Manifest Owner LMS public key used to verify the IMC Signature. <br> **tree_type:** LMS Algorithm Type (4 bytes) <br> **otstype:** LMS Ots Algorithm Type (4 bytes) <br> **id:**  (16 bytes) <br> **digest:**  (24 bytes) <br> Note: If LMS validation is not required, this should field should be zeroed out. |
| manifest\_owner\_ecc384\_sig  | u32[24]                | Owner ECDSA P-384 signature of the Owner ECC and LMS public keys, hashed using SHA2-384. <br> **R-Coordinate:** Random Point (48 bytes) <br> **S-Coordinate:** Proof (48 bytes) |
| manifest\_owner\_LMS\_sig     | u32[405]              | Owner LMS signature of the Version, Flags, Owner ECC and LMS public keys, hashed using SHA2-384. <br> **q:** Leaf of the Merkle tree where the OTS public key appears (4 bytes) <br> **ots:** Lmots Signature (1252 bytes) <br> **tree_type:** Lms Algorithm Type (4 bytes) <br> **tree_path:** Path through the tree from the leaf associated with the LM-OTS signature to the root. (360 bytes) <br> Note: If LMS validation is not required, this should field should be zeroed out. |
| metadata\_vendor\_ecc384\_sig | u32[24]                | Metadata Vendor ECC384 signature over the image metadata collection using the manifest vendor ecc384 key. |
| metadata\_vendor\_LMS\_sig    | u32[405]              | Metadata Vendor LMOTS-SHA192-W4 signature over the image metadata collection using the manifest vendor LMS key. |
| metadata\_owner\_ecc384\_sig  | u32[24]                | Metadata Owner ECC384 signature over the image metadata collection using the manifest owner ecc384 key. |
| metadata\_owner\_LMS\_sig     | u32[405]              | Metadata Owner LMOTS-SHA192-W4 signature over the image metadata collection manifest owner LMS key. |
| metadata\_entry\_entry\_count | u32                 | number of metadata entries |
| metadata\_entries             | MetaData[127]     | The max number of metadata entries is 127 but less can be used |


*Table: `AUTH_MANIFEST_FLAGS` input flags*

| **Name**                  | **Value** |
|---------------------------|-----------|
| VENDOR_SIGNATURE_REQUIRED | 1 << 0    |

*Table: `AUTH_MANIFEST_METADATA_ENTRY` digest entries*

| **Name**      | **Type** | **Description**                  |
|---------------|----------|----------------------------------|
| fw\_id        | u32      | Id of the image                  |
| flags         | u32      | See `METADATA_ENTRY_FLAGS` below |
| digest        | u32[48]  | Digest of the image              |


*Table: `METADATA_ENTRY_FLAGS` input flags*

| **Name**            | **Size (Bits)** | **Description** |
|---------------------|-----------------|-----------------|
| image\_source       | 2               | 1: InRequest    |
| ignore\_auth\_check | 1               | If set, the image digest is not compared for the firmware id |

*Table: `SET_AUTH_MANIFEST` output arguments*

| **Name**      | **Type** | **Description** |
| --------      | -------- | --------------- |
| chksum        | u32      | Checksum over other output arguments, computed by Caliptra. Little endian. |
| fips\_status  | u32      | Indicates if the command is FIPS approved or an error. |


### AUTHORIZE_AND_STASH

Command Code: `0x4154_5348` ("ATSH")

*Table: `AUTHORIZE_AND_STASH` input arguments*

| **Name**    | **Type** | **Description** |
| ------------| -------- | --------------- |
| chksum      | u32      | Checksum over other input arguments, computed by the caller. Little endian. |
| fw_id       | u8[4]    | Firmware id of the image, in little-endian format |
| measurement | u8[48]   | Digest of the image requested for authorization |
| context     | u8[48]   | Context field for `svn`; e.g., a hash of the public key that authenticated the SVN. |
| svn         | u32      | SVN |
| flags       | u32      | See AUTHORIZE_AND_STASH_FLAGS below |
| source      | u32      | Enumeration values: { InRequest(1) } |

*Table: `AUTHORIZE_AND_STASH_FLAGS` input flags*

| **Name**   | **Value**  |
|------------|------------|
| SKIP\_STASH | 1 << 0    |

*Table: `AUTHORIZE_AND_STASH` output arguments*
| **Name**        | **Type** | **Description**
| ----------------| -------- | ---------------
| chksum          | u32      | Checksum over other output arguments, computed by Caliptra. Little endian. |
| fips_status     | u32      | Indicates if the command is FIPS approved or an error.                     |
| auth_req_result | u32      | AUTHORIZE_IMAGE (0xDEADC0DE), IMAGE_NOT_AUTHORIZED (0x21523F21) or IMAGE_HASH_MISMATCH (0x8BFB95CB) |

### GET\_IDEVID\_CSR

Command Code: `0x4944_4352` ("IDCR")

*Table: `GET_IDEVID_CSR` input arguments*

| **Name**      | **Type** | **Description**
| --------      | -------- | ---------------
| chksum      | u32      | Checksum over other input arguments, computed by the caller. Little endian.  |

*Table: `GET_IDEVID_CSR` output arguments*
| **Name**      | **Type** | **Description**
| --------      | -------- | ---------------
| chksum        | u32      | Checksum over other output arguments, computed by Caliptra. Little endian. |
| data\_size    | u32      | Length in bytes of the valid data in the data field.                       |
| data          | u8[...]  | DER-encoded IDevID certificate signing request.                            |

The `mfg_flag_gen_idev_id_csr` manufacturing flag **MUST** have been set to generate a CSR. 

When called from ROM, if the CSR was not previously provisioned this command will return `FW_PROC_MAILBOX_UNPROVISIONED_CSR(0x0102000A)`. 

When called from runtime, if the CSR was not previously provisioned this command will return `RUNTIME_GET_IDEV_ID_UNPROVISIONED(0x000E0051)`. If the ROM did not support CSR generation, this command will return `RUNTIME_GET_IDEV_ID_UNSUPPORTED_ROM(0x000E0052)`.



When the `mfg_flag_gen_idev_id_csr` flag has been set, the SoC **MUST** wait for the `flow_status_set_idevid_csr_ready` bit to be set by Caliptra. Once set, the SoC **MUST** clear the `mfg_flag_gen_idev_id_csr` flag for Caliptra to progress.

### GET\_FMC\_ALIAS\_CSR

Command Code: `0x464D_4352` ("FMCR")

*Table: `GET_FMC_ALIAS_CSR` input arguments*

| **Name**      | **Type** | **Description**
| --------      | -------- | ---------------
| chksum        | u32      | Checksum over other input arguments, computed by the caller. Little endian. |

*Table: `GET_FMC_ALIAS_CSR` output arguments*
| **Name**      | **Type** | **Description**
| --------      | -------- | ---------------
| chksum        | u32      | Checksum over other output arguments, computed by Caliptra. Little endian.  |
| data\_size    | u32      | Length in bytes of the valid data in the data field.                        |
| data          | u8[...]  | DER-encoded FMC ALIAS certificate signing request.                          |

The FMC Alias CSR is generated unconditionally on every cold boot.

### SIGN\_WITH\_EXPORTED\_ECDSA

Command Code: `0x5357_4545` ("SWEE")

**Note**: This command is only available in the locality of the PL0 PAUSER. 

*Table: `SIGN_WITH_EXPORTED_ECDSA` input arguments*

| **Name**             | **Type** | **Description**
| --------             | -------- | ---------------
| chksum               | u32      | Checksum over other input arguments, computed by the caller. Little endian.         |
| exported_cdi_handle  | u8[32]   | The Exported CDI handle returned by the DPE `DeriveContext` command. Little endian. |
| tbs                  | u8[48]   | The bytes to be signed. Little endian.                                              |

*Table: `SIGN_WITH_EXPORTED_ECDSA` output arguments*
| **Name**           | **Type** | **Description**
| --------           | -------- | ---------------
| derived_pubkey_x   | u8[48]   | The X BigNum of the ECDSA public key associated with the signing key.      |
| derived_pubkey_y   | u8[48]   | The Y BigNum of the ECDSA public key associated with the signing key.      |
| signature_r        | u8[48]   | The R BigNum of an ECDSA signature.                                        |
| signature_s        | u8[48]   | The S BigNum of an ECDSA signature.                                        |

The `exported_cdi` can be created by calling `DeriveContext` with the `export-cdi` and `create-certificate` flags.

### REVOKE\_EXPORTED\_CDI\_HANDLE

Command Code: `5256_4348` ("RVCH")

**Note**: This command is only available in the locality of the PL0 PAUSER. 

*Table: `REVOKE_EXPORTED_CDI_HANDLE` input arguments*

| **Name**             | **Type** | **Description**
| --------             | -------- | ---------------
| chksum               | u32      | Checksum over other input arguments, computed by the caller. Little endian.         |
| exported_cdi_handle  | u8[32]   | The Exported CDI handle returned by the DPE `DeriveContext` command. Little endian. |

The `exported_cdi` can be created by calling `DeriveContext` with the `export-cdi` and `create-certificate` flags.

The `exported_cdi_handle` is no longer usable after calling `REVOKE_EXPORTED_CDI_HANDLE` with it. After the `exported_cdi_handle` 
has been revoked, a new exported CDI can be created by calling `DeriveContext` with the `export-cdi` and `create-certificate` flags.

## Checksum

For every command except for FW_LOAD, the request and response feature a checksum. This
mitigates glitches between clients and Caliptra.

The checksum is a little-endian 32-bit value, defined as:

```text
0 - (SUM(command code bytes) + SUM(request/response bytes))
```

The sum of all bytes in a request/response body, and command code, should be
zero.

If Caliptra detects an invalid checksum in input parameters, it returns
`BAD_CHKSUM` as the result.

Caliptra also computes a checksum over all of the responses and writes it to the
chksum field.

## FIPS status

For every command, the firmware responds with a FIPS status of FIPS approved. There is
currently no use case for any other responses or error values.

*Table: FIPS status codes*

| **Name**         | **Value**                   | Description
| -------          | -----                       | -----------
| `FIPS_APPROVED`  | `0x0000_0000`               | Status of command is FIPS approved
| `RESERVED`       | `0x0000_0001 - 0xFFFF_FFFF` | Other values reserved, will not be sent by Caliptra

## Runtime Firmware updates

Caliptra Runtime Firmware accepts impactless updates that update
Caliptra’s firmware without resetting other cores in the SoC.

### Applying updates

A Runtime Firmware update is triggered by the `CALIPTRA_FW_LOAD` command. Upon
receiving this command, Runtime Firmware does the following:

1. Locks the mailbox to writes
1. Invokes impactless reset

After impactless reset is invoked, FMC loads the hash of the image
from the verified Manifest into the necessary PCRs:

1. Runtime Journey PCR
1. Runtime Latest PCR

If ROM validation of the image fails:

* ROM SHALL NOT clear the Runtime Latest PCR. It SHALL still re-lock this
  PCR with the existing value.
* FMC SHALL NOT extend either of the Runtime PCRs.

### Boot process after update

After an impactless update is applied, the new Runtime Firmware is
able to sample a register to determine if it has undergone an Impactless Reset. In
this case, the new Runtime Firmware must:

1. Validate DPE state in SRAM
    1. Ensure the TCI tree is well-formed
    1. Ensure all nodes chain to the root (TYPE = RTJM, “Internal TCI” flag is set)
1. Verify that the “Latest TCI” field of the TCI Node that contains the
   Runtime Journey PCR (TYPE = RTJM, “Internal TCI” flag is set) matches the
   “Latest” Runtime PCR value from PCRX
    1. Ensure `SHA384_HASH(0x00..00, TCI from SRAM) == RT_FW_JOURNEY_PCR`
1. Check that retired and inactive contexts do not have tags
1. If any validations fail, Runtime Firmware executes the
   `DISABLE_ATTESTATION` command

## DICE Protection Environment (DPE)

Caliptra Runtime Firmware SHALL implement a profile of the DICE Protection
Environment (DPE) API.

### PAUSER privilege levels

Caliptra uses PAUSER as a HW mechanism to distinguish DPE Client localities.
Caliptra models PAUSER callers to its mailbox as having 1 of 2 privilege levels:

* PL0 - High privilege. Only 1 PAUSER in the SoC may be at PL0. The PL0 PAUSER
  is denoted in the signed Caliptra firmware image. The PL0 PAUSER may call any
  supported DPE commands. Only PL0 can use the CertifyKey command. Success of the
  CertifyKey command signifies to the caller that it is at PL0. Only PL0 can use
  the POPULATE\_IDEV\_CERT mailbox command.
* PL1 - Restricted privilege. All other PAUSERs in the SoC are PL1. Caliptra
  SHALL fail any calls to the DPE CertifyKey with format=X509 by PL1 callers.
  PL1 callers should use the CSR format instead.

PAUSER and Locality map 1:1. Consequently, only the single DPE Client associated
with PL0 level, is authorized to invoke CertifyKey DPE command with format=x509. 
All other DPE Clients have instead restricted privileges associated to PL1 (as 
described above).

#### PAUSER privilege level active context limits

Each active context in DPE is activated from either PL0 or PL1 through the
InvokeDpe mailbox command calling the DeriveContext or InitializeContext DPE
commands. However, a caller could easily exhaust space in DPE's context array
by repeatedly calling the aforementioned DPE commands with certain flags set.

To prevent this, we establish active context limits for each PAUSER
privilege level:

* PL0 - 16 active contexts
* PL1 - 16 active contexts

If a DPE command were to activate a new context such that the total number of
active contexts in a privilege level is above its active context limit, the
InvokeDpe command should fail.

At boot Caliptra Runtime FW consumes part of the PL0 active contexts (initially 16) to DeriveContext for:
   - RTFW Journey (RTFJ) Measurement (1)
   - Mailbox Valid Pauser digest (MBVP) (1)
   - ROM Stashed Measurements (max 8)

Further, it is not allowed for PL1 to call DeriveContext with the intent to change locality to PL0's locality; this would increase the number
of active contexts in PL0's locality, and hence allow PL1 to DOS PL0.

### DPE profile implementation

The DPE iRoT profile leaves some choices up to implementers. This section
describes specific requirements for the Caliptra DPE implementation.

| Name                       | Value                          | Description
| ----                       | -----                          | -----------
| Profile Variant            | `DPE_PROFILE_IROT_P384_SHA384` | The profile variant that Caliptra implements.
| KDF                        | SP800-108 HMAC-CTR             | KDF to use for CDI (tcg.derive.kdf-sha384) and asymmetric key (tcg.derive.kdf-sha384-p384) derivation.
| Simulation Context Support | Yes                            | Whether Caliptra implements the optional Simulation Contexts feature.
| Supports ExtendTci         | Yes                            | Whether Caliptra implements the optional ExtendTci command.
| Supports Auto Init         | Yes                            | Whether Caliptra will automatically initialize the default DPE context.
| Supports Rotate Context    | Yes                            | Whether Caliptra supports the optional RotateContextHandle command.
| CertifyKey Alias Key       | Caliptra Runtime Alias Key     | The key that will be used to sign certificates that are produced by the DPE CertifyKey command.

### Supported DPE commands

Caliptra DPE supports the following commands:

* GetProfile
* InitializeContext
* DeriveContext
    * **Note**: The "export-cdi" flag is only available in the locality of the PL0 PAUSER. 
* CertifyKey
  * Caliptra DPE supports two formats for CertifyKey: X.509 and PKCS#10 CSR.
    X.509 is only available to PL0 PAUSERs.
* Sign
* RotateContextHandle
* DestroyContext
* GetCertificateChain

### DPE state atomicity

This implementation guarantees that no internal DPE state is changed if a
command fails for any reason. This includes context handle rotation; single-use
context handles are not rotated if a command fails.

On failure, DPE only returns a command header, with no additional
command-specific response parameters. This is in line with the CBOR-based
main DPE spec, which does not return a response payload on failure.

### Initializing DPE

Caliptra Runtime Firmware is responsible for initializing DPE’s default context.

* Runtime Firmware SHALL initialize the default context in “internal-cdi” mode.
* Perform the following initial measurements:
  * Call DeriveContext with Caliptra Journey PCR
    * INPUT\_DATA = PCRX (RT journey PCR as defined in the FHT)
    * TYPE = “RTJM”
    * CONTEXT\_HANDLE = default context
    * TARGET\_LOCALITY = Caliptra locality (0xFFFFFFFF)
  * Call DeriveContext with mailbox valid PAUSERS
    * INPUT\_DATA = Hash of [CPTRA\_VALID\_PAUSER register](https://chipsalliance.github.io/caliptra-rtl/main/internal-regs/?p=clp.soc_ifc_reg.CPTRA_MBOX_VALID_PAUSER%5B0%5D).
    * TYPE = “MBVP”
    * CONTEXT\_HANDLE = default context
    * TARGET\_LOCALITY = PL0 PAUSER
  * Call DeriveContext for each STASH\_MEASUREMENT call made during Caliptra ROM execution
    * INPUT\_DATA = `measurement` parameter to STASH\_MEASUREMENT
    * TYPE = `type` parameter to STASH\_MEASUREMENT
    * CONTEXT\_HANDLE = default context
    * TARGET\_LOCALITY = PL0 PAUSER

### CDI derivation

The DPE Sign and CertifyKey commands derive an asymmetric key for that handle.

DPE first collects measurements and concatenates them in a byte buffer,
`MEASUREMENT_DATA`:

* LABEL parameter passed to Sign or CertifyKey.
* The `TCI_NODE_DATA` structures in the path from the current TCI node to the
  root, inclusive, starting with the current node.

To derive a CDI for a given context, DPE shall use KeyVault hardware with the
following inputs:

* CDI = Runtime Firmware CDI (from KeyVault)
* Label = LABEL parameter provided to Sign or CertifyKey
* Context = `MEASUREMENT_DATA`

The CDI shall be loaded into KeyVault slot 8.

### Leaf key derivation

To derive an asymmetric key for Sign and CertifyKey, Runtime Firmware does the following:

* Derives an ECC P384 keypair from KV slot 8 CDI into KV slot 9
* For CertifyKey: Requests the public key
* For Sign: Signs passed data
* Erases KeyVault slots 8 and 9

### Internal representation of TCI nodes

| **Byte offset** | **Bits** | **Name**         | **Description**
| -----           | ----     | ---------------- | -----------------------------------------------------
| 0x00            | 383:0    | `TCI_CURRENT`    | Current TCI measurement value
| 0x30            | 383:0    | `TCI_CUMULATIVE` | TCI measurement value
| 0x60            | 31:0     | `TYPE`           | `TYPE` parameter to the DeriveContext call that created this node
| 0x64            | 31:0     | `LOCALITY`       | `TARGET_LOCALITY` parameter to the DeriveContext call that created this node (PAUSER)

### Certificate generation

The DPE Runtime Alias Key SHALL sign DPE leaf certificates and CSRs.

The DPE `GET_CERTIFICATE_CHAIN` command shall return the following certificates:

* IDevID (optionally added by the SoC via POPULATE\_IDEV\_CERT)
* LDevID
* FMC Alias
* Runtime Alias

### DPE leaf certificate definition

| Field                          | Sub field          | Value
| -------------                  | ---------          | ---------
| Version                        | v3                 | 2
| Serial Number                  |                    | First 20 bytes of sha256 hash of DPE Alias public key
| Issuer Name                    | CN                 | Caliptra Runtime Alias
|                                | serialNumber       | First 20 bytes of sha384 hash of Runtime Alias public key
| Validity                       | notBefore          | notBefore from firmware manifest
|                                | notAfter           | notAfter from firmware manifest
| Subject Name                   | CN                 | Caliptra DPE Leaf
|                                | serialNumber       | SHA384 hash of Subject public key
| Subject Public Key Info        | Algorithm          | ecdsa-with-SHA384
|                                | Parameters         | Named Curve = prime384v1
|                                | Public Key         | DPE Alias Public Key value
| Signature Algorithm Identifier | Algorithm          | ecdsa-with-SHA384
|                                | Parameters         | Named Curve = prime384v1
| Signature Value                |                    | Digital signature for the certificate
| KeyUsage                       | keyCertSign        | 1
| Basic Constraints              | CA                 | False
| Policy OIDs                    |                    | id-tcg-kp-attestLoc
| tcg-dice-MultiTcbInfo\*        | FWIDs              | [0] "Current" TCI Value. Latest `INPUT_DATA` made by DeriveContext
|                                | IntegrityRegisters | [0] "Journey" TCI Value.
|                                | Type               | 4-byte TYPE field of TCI node
|                                | VendorInfo         | Locality of the caller (analog for PAUSER)

\*MultiTcbInfo contains one TcbInfo for each TCI Node in the path from the
current TCI Node to the root. Max of 32.
