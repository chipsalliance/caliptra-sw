# libcaliptra

## Purpose

libcaliptra is an abstraction layer between SoC applications and the Caliptra implementation in hardware.

## Structure

libcaliptra exists in two parts:

### Caliptra API

Specified in caliptra_api.h and defined in caliptra_api.c

Provides abstract APIs and functionality to SoC applications, independent of hardware details.

### Caliptra IF

Specified in caliptra_if.h and used by caliptra_api.c

The caliptra implementation must supply the definitions for the functions named in caliptra_if.h

## Build

The top level Makefile has a few targets:

debug
release

The default is debug (note: there is no difference between the two at this time)

## Linking
Applications will need to compile and link caliptra_api.c and the definitions for caliptra_if.hardware

# Notes

This is an early check-in to ensure its presence upstream and to generate feedback going forward.

* Expand available APIs
* Interrupts?
** Handling thereof?
* Add a demonstration interface connecting to the hardware model
* Add a demonstration interface to the software simulator (?)
* Add support for building the caliptra interface implementation if present?
