# Zephyr Project Configuration

This directory contains everything needed to include Libcaliptra as a library
within a Zephyr project.

It leaves the implementation for the functions in `caliptra_if.h` undefined. They
will need to be defined external to this directory.

The module is labeled `LIBCALIPTRA`. It can be added to your Zephyr project with
`CONFIG_LIBCALIPTRA=y`. Be sure to add this directory to the list of
`ZEPHYR_MODULES` in the build rules.
