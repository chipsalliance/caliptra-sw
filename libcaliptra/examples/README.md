# Caliptra C API Examples

In this directory you will find a basic example on how to interact with the
Caliptra C API and adapt it to your target platform.

## Build

Build can be done either in this directory by naming a target, or in the individual interface example directories.

In the examples root, the following is valid:

`$ make`

`$ make run`

`$ make clean`

By default, the *hwmodel* example will be built and run. By supplying:

`PLAT=<target>`

on the Make command line, where <target> is a directory in *examples* other than *generic*, that example will be acted upon:

`$ make PLAT=hwmodel`

`$ make PLAT=hwmodel run`

## Generic

`generic/`

The generic example contains the main() function, basic Caliptra startup, and firmware interaction. This file is built by and linked in by other examples.

## Example: hwmodel

`hwmodel/`

This is an implementation of the Caliptra C API Interface functions that target the hardware model. It abstracts out model specific details including:
* ROM and Firmware image file opening
** The paths are set at compile time, see the Makefile for details
* Model-specific behavior (loading of ROM)
* Model object management

