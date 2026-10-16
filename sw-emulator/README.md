# Emulator for Caliptra

This repository contains code for creating an emulator for the Caliptra hardware.

This branch builds firmware for the pinned 2.2 development hardware only.
The emulator CLI defaults to 2.2, as do hardware-model initialization parameters.
Legacy hardware enum values remain for historical peripheral-slot tests; they
do not imply support for building or booting 2.1 firmware on this branch.

## Peripheral emulation

### HMAC

The driver and emulator use the 2.2 final-block protocol: only the final padded
message block sets `LAST`. Earlier commands expose the inner SHA digest; `LAST`
produces the outer HMAC tag. The driver arms key-vault tag output only for that
final command. The emulator models the six-word, write-only LFSR seed bank,
live-key OPAD finalization, command pulses, and zeroize cancellation.

### Mailbox

#### Class diagram

![alternative text](http://www.plantuml.com/plantuml/proxy?cache=no&src=https://raw.githubusercontent.com/attzonko/plantuml_test/main/test.puml)

#### State diagram

The UML state diagram depicted below represents the behavior of the mailbox state machine. The notation follows the UML conventions:

![alternative text](http://www.plantuml.com/plantuml/proxy?cache=no&src=https://raw.githubusercontent.com/rusty1968/rust_documentation/main/docs/mb_state_diagram.puml)
