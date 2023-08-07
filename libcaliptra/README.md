# libcaliptra

## Purpose

libcaliptra is an abstraction layer between SoC applications and the Caliptra implementation in hardware.

## Structure

libcaliptra exists in two parts, the API and the Interface.

### API

Specified in caliptra_api.h and defined in caliptra_api.c

Provides abstract APIs and functionality to SoC applications, independent of hardware details.

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
