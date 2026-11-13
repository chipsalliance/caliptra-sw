# Emulator for Caliptra

This repository contains code for creating an emulator for the Caliptra hardware.

## Peripheral emulation

### HMAC

For `latest` (2.2), the driver and emulator use the final-block protocol: only the final padded
message block sets `LAST`. Earlier commands expose the inner SHA digest; `LAST`
produces the outer HMAC tag. The driver arms key-vault tag output only for that
final command. The emulator models the six-word, write-only LFSR seed bank,
live-key OPAD finalization, command pulses, and zeroize cancellation.

The emulator selects the HMAC model by hardware revision, independently of
driver features. Firmware for `latest` must enable `last-hmac-block`; the
builder, xtask, and ROM/FMC Makefiles select it automatically. Revision `2.1`
continues to use the legacy driver protocol and peripheral model.

### Mailbox

#### Class diagram

![alternative text](http://www.plantuml.com/plantuml/proxy?cache=no&src=https://raw.githubusercontent.com/attzonko/plantuml_test/main/test.puml)

#### State diagram

The UML state diagram depicted below represents the behavior of the mailbox state machine. The notation follows the UML conventions:

![alternative text](http://www.plantuml.com/plantuml/proxy?cache=no&src=https://raw.githubusercontent.com/rusty1968/rust_documentation/main/docs/mb_state_diagram.puml)
