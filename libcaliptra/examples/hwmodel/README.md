# hwmodel

This example defines the Caliptra interface functions, allowing the generic application to communicate with the hardware model without having to directly manage model-specific details.

# Prerequisites

The c-binding, rom, and firmware must all be built.

# Build

Running "make" will compile the Caliptra C API, the interface, and link the application against the C binding.

Select `CALIPTRA_HW_REV=2.1` or `CALIPTRA_HW_REV=latest` consistently when
building the C binding, ROM, firmware, and this example. The example defaults
to `latest` and rejects unsupported selectors. Its Makefile selects matching
C register headers and compiles the corresponding hardware-model revision
into the executable; changing the environment only when running the executable
does not retarget it.

Clean the native objects before changing revisions:

```sh
make clean
CALIPTRA_HW_REV=2.1 make
./hwmodel
```

Use separate firmware/Cargo output directories for each hardware revision.
With a custom `CARGO_TARGET_DIR`, pass `OUTPUT_DIR="$CARGO_TARGET_DIR/debug"`
to Make so the example uses the matching Rust library, ROM, and firmware.
