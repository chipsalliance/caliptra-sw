# libcaliptra

## Purpose

libcaliptra is an abstraction layer between SoC applications and the Caliptra implementation in hardware.

## Structure

libcaliptra exists in two parts, the API and the Interface.

### API

Specified in caliptra_api.h and defined in caliptra_api.c

Provides abstract APIs and functionality to SoC applications, independent of hardware details.

#### FIPS status handling

The C API requires an approved FIPS status and returns
`MBX_RESP_FIPS_NOT_APPROVED` for any non-approved response. This policy is
separate from firmware command success: a command can execute successfully and
return a non-approved service indicator.

`CM_IMPORT` and cryptographic services using imported CMKs or their derivatives
return `FIPS_STATUS_NOT_APPROVED_USER_SUPPLIED_KEY` (`0x5553524B`, "USRK").
The response buffer remains available for the caller to inspect this status.
The C API's approved-only policy is unchanged; unlike the Rust typed API, it
does not return success for known non-approved statuses.

### IF

Specified in caliptra_if.h and used by caliptra_api.c

The caliptra implementation must supply the definitions for the functions named in caliptra_if.h

## Build

To compile the API, the following must be provided:

* Standard C headers
* Access to the caliptra_top_reg.h header

Run `make RTL_SOC_IFC_INCLUDE_PATH=<path>` to generate libcaliptra.a

Run `make CROSS_COMPILE=<prefix> RTL_SOC_IFC_INCLUDE_PATH=<path>` to cross compile libcaliptra.a for a different target.

## Link

To link the API, the following must be provided:

* A main application utilizing these functions
* An interface implementation

## Implementation and consumer examples

See examples/README.md for details on specific examples.
