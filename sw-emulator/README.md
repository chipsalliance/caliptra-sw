# Emulator for Caliptra

This repository contains code for creating an emulator for the Caliptra hardware.

## Peripheral emulation

### Hardware revisions and HMAC

The hardware model passes its selected `CaliptraHwVersion` to the emulator's
peripherals. HMAC keeps the legacy protocol for 2.0/2.1 and uses the final-block
protocol for 2.2/`latest`. Hardware selection is independent of firmware Cargo
features; the emulator does not infer a revision from firmware register writes.

On 2.2, only the final padded block carries `LAST`. Intermediate commands expose
the inner SHA digest, while the final command produces the outer HMAC tag. The
driver enables key-vault tag output only for that final command. The model also
implements command pulses, busy-command handling, zeroize cancellation, live
outer-key loading, and the six-word write-only seed bank. The legacy model keeps
its twelve-word seed bank and existing completion behavior.

`CALIPTRA_HW_REV=2.1` selects legacy firmware; `CALIPTRA_HW_REV=latest` selects the
current 2.2 hardware bindings. `cargo xtask build`, the firmware/image builder,
and the ROM/FMC Makefiles select `caliptra-drivers/hmac-final-block` only for the
2.2 target. Explicit per-firmware hardware overrides take precedence over the
environment. Builder caches and prebuilt ELF filenames include the effective
hardware revision so artifacts cannot be reused across targets.

For direct firmware Cargo commands, enable `hmac-final-block` on ROM, FMC,
Runtime, or driver test firmware, or use the namespaced
`--features caliptra-drivers/hmac-final-block` for other workspace fixtures.
The driver rejects that feature on 2.1 and rejects latest RISC-V firmware builds
without it. The standalone emulator defaults to 2.1; pass
`--hw-version latest` (or `--hw-version 2.2`) when running 2.2 firmware.

### Mailbox

#### Class diagram

![alternative text](http://www.plantuml.com/plantuml/proxy?cache=no&src=https://raw.githubusercontent.com/attzonko/plantuml_test/main/test.puml)

#### State diagram

The UML state diagram depicted below represents the behavior of the mailbox state machine. The notation follows the UML conventions:

![alternative text](http://www.plantuml.com/plantuml/proxy?cache=no&src=https://raw.githubusercontent.com/rusty1968/rust_documentation/main/docs/mb_state_diagram.puml)
