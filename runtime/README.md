# Caliptra Runtime Firmware v1.0

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

## Maibox commands

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

| **Name**    | **Type**   | **Description**
| --------    | --------   | ---------------
| chksum      | u32        | Checksum over other output arguments, computed by Caliptra. Little endian.
| fips\_status | u32        | Indicates if the command is FIPS approved or an error.
| capabilities   | u8[16]        | Firmware capabilities

### GET\_IDEV\_CERT

Exposes a command to reconstruct the IDEVID CERT.

Command Code: `0x4944_4543` ("IDEC")

*Table: `GET_IDEV_CERT` input arguments*

| **Name**    | **Type**      | **Description**
| --------    | --------      | ---------------
| chksum      | u32           | Checksum over other input arguments, computed by the caller. Little endian.
| signature\_r | u8[48]        | R portion of signature of the cert.
| signature\_s | u8[48]        | S portion of signature of the cert.
| tbs\_size    | u32           | Size of the TBS.
| tbs         | u8[916]       | TBS, with a maximum size of 916. Only bytes up to tbs_size are used.

*Table: `GET_IDEV_CERT` output arguments*

| **Name**    | **Type**   | **Description**
| --------    | --------   | ---------------
| chksum      | u32        | Checksum over other output arguments, computed by Caliptra. Little endian.
| fips\_status | u32        | Indicates if the command is FIPS approved or an error.
| cert\_size   | u32        | Length in bytes of the cert field in use for the IDevId certificate.
| cert        | u8[1024]   | DER-encoded IDevID CERT.

### POPULATE\_IDEV\_CERT

Exposes a command that allows the SoC to provide a DER-encoded
IDevId certificate on every boot. The IDevId certificate is added
to the start of the certificate chain.

Command Code: `0x4944_4550` ("IDEP")

*Table: `POPULATE_IDEV_CERT` input arguments*

| **Name**    | **Type**      | **Description**
| --------    | --------      | ---------------
| chksum      | u32           | Checksum over other input arguments, computed by the caller. Little endian.
| cert\_size   | u32           | Size of the DER-encoded IDevId certificate.
| cert        | u8[1024]      | DER-encoded IDevID CERT.

*Table: `POPULATE_IDEV_CERT` output arguments*

| **Name**    | **Type** | **Description**
| --------    | -------- | ---------------
| chksum      | u32      | Checksum over other output arguments, computed by Caliptra. Little endian.
| fips\_status | u32      | Indicates if the command is FIPS approved or an error.

### GET\_IDEV\_INFO

Exposes a command to get an IDEVID public key.

Command Code: `0x4944_4549` ("IDEI")

*Table: `GET_IDEV_INFO` input arguments*

| **Name**  | **Type**      | **Description**
| --------  | --------      | ---------------
| chksum    | u32           | Checksum over other input arguments, computed by the caller. Little endian.

*Table: `GET_IDEV_INFO` output arguments*

| **Name**    | **Type**   | **Description**
| --------    | --------   | ---------------
| chksum      | u32        | Checksum over other output arguments, computed by Caliptra. Little endian.
| fips\_status | u32        | Indicates if the command is FIPS approved or an error.
| idev\_pub\_x  | u8[48]     | X portion of ECDSA IDevId key.
| idev\_pub\_y  | u8[48]     | Y portion of ECDSA IDevId key.

### GET\_LDEV\_CERT

Exposes a command to get a self-signed LDevID certificate signed by IDevID.

Command Code: `0x4C44_4556` ("LDEV")

*Table: `GET_LDEV_CERT` input arguments*

| **Name**  | **Type**      | **Description**
| --------  | --------      | ---------------
| chksum    | u32           | Checksum over other input arguments, computed by the caller. Little endian.

*Table: `GET_LDEV_CERT` output arguments*

| **Name**    | **Type**   | **Description**
| --------    | --------   | ---------------
| chksum      | u32        | Checksum over other output arguments, computed by Caliptra. Little endian.
| fips\_status | u32        | Indicates if the command is FIPS approved or an error.
| data\_size   | u32        | Length in bytes of the valid data in the data field.
| data        | u8[...]    | DER-encoded LDevID certificate.

### GET\_FMC\_ALIAS\_CERT

Exposes a command to get a self-signed FMC alias certificate signed by LDevID.

Command Code: `0x4345_5246` ("CERF")

*Table: `GET_FMC_ALIAS_CERT` input arguments*

| **Name**  | **Type**      | **Description**
| --------  | --------      | ---------------
| chksum    | u32           | Checksum over other input arguments, computed by the caller. Little endian.

*Table: `GET_FMC_ALIAS_CERT` output arguments*

| **Name**    | **Type**   | **Description**
| --------    | --------   | ---------------
| chksum      | u32        | Checksum over other output arguments, computed by Caliptra. Little endian.
| fips\_status | u32        | Indicates if the command is FIPS approved or an error.
| data\_size   | u32        | Length in bytes of the valid data in the data field.
| data        | u8[...]    | DER-encoded FMC alias certificate.

### GET\_RT\_ALIAS\_CERT

Exposes a command to get a self-signed Runtime alias certificate signed by the FMC alias.

Command Code: `0x4345_5252` ("CERR")

*Table: `GET_RT_ALIAS_CERT` input arguments*

| **Name**  | **Type**      | **Description**
| --------  | --------      | ---------------
| chksum    | u32           | Checksum over other input arguments, computed by the caller. Little endian.

*Table: `GET_RT_ALIAS_CERT` output arguments*

| **Name**    | **Type**   | **Description**
| --------    | --------   | ---------------
| chksum      | u32        | Checksum over other output arguments, computed by Caliptra. Little endian.
| fips\_status | u32        | Indicates if the command is FIPS approved or an error.
| data\_size   | u32        | Length in bytes of the valid data in the data field.
| data        | u8[...]    | DER-encoded Runtime alias certificate.

### ECDSA384\_SIGNATURE\_VERIFY

Verifies an ECDSA P-384 signature. The hash to be verified is taken from
Caliptra's SHA384 accelerator peripheral.

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

| **Name**    | **Type** | **Description**
| --------    | -------- | ---------------
| chksum      | u32      | Checksum over other output arguments, computed by Caliptra. Little endian.
| fips\_status | u32      | Indicates if the command is FIPS approved or an error.

### STASH\_MEASUREMENT

Makes a measurement into the DPE default context. This command is intendend for
callers who update infrequently and cannot tolerate a changing DPE API surface.

* Call the DPE DeriveContext command with the DefaultContext in the locality of
  the PL0 PAUSER.
* Extend the measurement into PCR31 (`PCR_ID_STASH_MEASUREMENT`).

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

| **Name**    | **Type** | **Description**
| --------    | -------- | ---------------
| chksum      | u32      | Checksum over other output arguments, computed by Caliptra. Little endian.
| fips\_status | u32      | Indicates if the command is FIPS approved or an error.
| dpe\_result | u32      | Result code of DPE DeriveContext command. Little endian.

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

| **Name**    | **Type** | **Description**
| --------    | -------- | ---------------
| chksum      | u32      | Checksum over other output arguments, computed by Caliptra. Little endian.
| fips\_status | u32      | Indicates if the command is FIPS approved or an error.

### INVOKE\_DPE\_COMMAND

Invokes a serialized DPE command.

Command Code: `0x4450_4543` ("DPEC")

*Table: `INVOKE_DPE_COMMAND` input arguments*

| **Name**     | **Type**      | **Description**
| --------     | --------      | ---------------
| chksum       | u32           | Checksum over other input arguments, computed by the caller. Little endian.
| data\_size    | u32           | Length in bytes of the valid data in the data field.
| data         | u8[...]       | DPE command structure as defined in the DPE iRoT profile.

*Table: `INVOKE_DPE_COMMAND` output arguments*

| **Name**    | **Type**      | **Description**
| --------    | --------      | ---------------
| chksum      | u32           | Checksum over other output arguments, computed by Caliptra. Little endian.
| fips\_status | u32           | Indicates if the command is FIPS approved or an error.
| data\_size   | u32           | Length in bytes of the valid data in the data field.
| data        | u8[...]       | DPE response structure as defined in the DPE iRoT profile.

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

`EXTEND_PCR` returns no output arguments.

Note that extensions made into Caliptra's PCRs are _not_ appended to Caliptra's internal PCR log.

### GET\_PCR\_LOG

Gets Caliptra's internal PCR log.

Command Code: `0x504C_4F47` ("PLOG")

*Table: `GET_PCR_LOG` input arguments*

| **Name**  | **Type**      | **Description**
| --------  | --------      | ---------------
| chksum    | u32           | Checksum over other input arguments, computed by the caller. Little endian.

*Table: `GET_PCR_LOG` output arguments*

| **Name**    | **Type**   | **Description**
| --------    | --------   | ---------------
| chksum      | u32        | Checksum over other output arguments, computed by Caliptra. Little endian.
| fips\_status | u32        | Indicates if the command is FIPS approved or an error.
| data\_size   | u32        | Length in bytes of the valid data in the data field.
| data        | u8[...]    | Internal PCR event log.

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

`INCREMENT_PCR_RESET_COUNTER` returns no output arguments.

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

| **Name**    | **Type** | **Description**
| --------    | -------- | ---------------
| chksum      | u32      | Checksum over other output arguments, computed by Caliptra. Little endian.
| fips\_status | u32      | Indicates if the command is FIPS approved or an error.

### DPE\_GET\_TAGGED\_TCI

Retrieves the TCI measurements corresponding to the tagged DPE context.

Command Code: `0x4754_4744` ("GTGD")

*Table: `DPE_GET_TAGGED_TCI` input arguments*

| **Name**     | **Type**      | **Description**
| --------     | --------      | ---------------
| chksum       | u32           | Checksum over other input arguments, computed by the caller. Little endian.
| tag          | u32           | A unique tag corresponding to a DPE context.

*Table: `DPE_GET_TAGGED_TCI` output arguments*

| **Name**          | **Type**       | **Description**
| --------          | --------       | ---------------
| chksum            | u32            | Checksum over other input arguments, computed by the caller. Little endian.
| tci\_cumulative    | u8[48]         | Hash of all of the input data provided to the context.
| tci\_current       | u8[48]         | Most recent measurement made into the context.

### FW\_INFO

Retrieves information about the current Runtime Firmware, FMC, and ROM.

Command Code: `0x494E_464F` ("INFO")

*Table: `FW_INFO` input arguments*

| **Name**     | **Type**      | **Description**
| --------     | --------      | ---------------
| chksum       | u32           | Checksum over other input arguments, computed by the caller. Little endian.

*Table: `FW_INFO` output arguments*

| **Name**               | **Type**       | **Description**
| --------               | --------       | ---------------
| chksum                 | u32            | Checksum over other input arguments, computed by the caller. Little endian.
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

Caliptra models PAUSER callers to its mailbox as having 1 of 2 privilege levels:

* PL0 - High privilege. Only 1 PAUSER in the SoC may be at PL0. The PL0 PAUSER
  is denoted in the signed Caliptra firmware image. The PL0 PAUSER may call any
  supported DPE commands. Only PL0 can use the CertifyKey command. Success of the
  CertifyKey command signifies to the caller that it is at PL0. Only PL0 can use
  the POPULATE\_IDEV\_CERT mailbox command.
* PL1 - Restricted privilege. All other PAUSERs in the SoC are PL1. Caliptra
  SHALL fail any calls to the DPE CertifyKey with format=X509 by PL1 callers.
  PL1 callers should use the CSR format instead.

#### PAUSER privilege level active context limits

Each active context in DPE is activated from either PL0 or PL1 through the
InvokeDpe mailbox command calling the DeriveContext or InitializeContext DPE
commands. However, a caller could easily exhaust space in DPE's context array
by repeatedly calling the aforementioned DPE commands with certain flags set.

To prevent this, we establish active context limits for each PAUSER
privilege level:

* PL0 - 8 active contexts
* PL1 - 16 active contexts

If a DPE command were to activate a new context such that the total number of
active contexts in a privilege level is above its active context limit, the
InvokeDpe command should fail.

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

| Field                          | Sub field   | Value
| -------------                  | ---------   | ---------
| Version                        | v3          | 2
| Serial Number                  |             | First 20 bytes of sha256 hash of DPE Alias public key
| Issuer Name                    | CN          | Caliptra Runtime Alias
|                                | serialNumber | First 20 bytes of sha384 hash of Runtime Alias public key
| Validity                       | notBefore   | notBefore from firmware manifest
|                                | notAfter    | notAfter from firmware manifest
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
| tcg-dice-MultiTcbInfo\*        | FWIDs       | [0] "Journey" TCI Value
|                                |             | [1] "Current" TCI Value. Latest `INPUT_DATA` made by DeriveContext.
|                                | Type        | 4-byte TYPE field of TCI node
|                                | VendorInfo  | Locality of the caller (analog for PAUSER)

\*MultiTcbInfo contains one TcbInfo for each TCI Node in the path from the
current TCI Node to the root. Max of 24.
