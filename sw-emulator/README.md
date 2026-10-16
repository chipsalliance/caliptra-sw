# Emulator for Caliptra

This repository contains code for creating an emulator for the Caliptra hardware.

This branch builds firmware for the pinned 2.2 development hardware only.
The emulator CLI defaults to 2.2, as do hardware-model initialization parameters.
Legacy hardware enum values remain for historical peripheral-slot tests; they
do not imply support for building or booting 2.1 firmware on this branch.

## Peripheral emulation

### Mailbox

#### Class diagram

![alternative text](http://www.plantuml.com/plantuml/proxy?cache=no&src=https://raw.githubusercontent.com/attzonko/plantuml_test/main/test.puml)

#### State diagram

The UML state diagram depicted below represents the behavior of the mailbox state machine. The notation follows the UML conventions:

![alternative text](http://www.plantuml.com/plantuml/proxy?cache=no&src=https://raw.githubusercontent.com/rusty1968/rust_documentation/main/docs/mb_state_diagram.puml)
