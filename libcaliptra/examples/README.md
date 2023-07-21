# Caliptra C API Examples

In this directory you will find a basic example on how to interact with the
Caliptra C API and adapt it to your target platform.

## Generic

`generic/`

The generic example contains the main() function, basic Caliptra startup, and firmware interaction.

> NOTE: The current test executes a command that is ignored by ROM and not yet implemented by firmware.

## hwmodel

`hwmodel/`

This is an implementation of the Caliptra C API Interface functions that target the hardware model. It abstracts out model specific details including:
* ROM and Firmware image file opening
** The paths are set at compile time, see the Makefile for details
* Model-specific behavior (loading of ROM)
* Model object management

