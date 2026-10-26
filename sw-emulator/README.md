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

### SHA3/SHAKE

The driver uses the 2.2 `SHA3_CTRL.ZEROIZE` pulse at `0x10041010` after
digest completion, when abandoning an operation, and during fatal cleanup.
Unlike `CMD.Done`, zeroize aborts from any engine state and clears the message
and digest datapath. The driver waits for `STATUS.sha3_idle` before starting
another operation; fatal cleanup issues the pulse without waiting.

The emulator maps the wrapper control register to the same SHA3 engine as the
KMAC operation registers. Zeroize clears buffered input, the hash context,
digest output and pending command, returning to idle while retaining
configuration. These tests validate software-visible behavior, not
cycle-accurate RTL timing or physical erasure of host memory.

### Boot integrity

The boot-flow monitor and automatic ICCM-write measurement are enabled only in
subsystem mode; debug unlock disables the monitor there. ICCM reads, including
instruction fetches, drive boot-phase transitions. ROM authenticates staged
payloads and copies them into ICCM without data readback in either mode. It sets
the ICCM write lock but does not compare PCR values or wait for measurement
completion. The staging buffer must remain protected through the copy.
Passive mode disables monitoring regardless of debug-lock state, modeling the
intended passive integration contract.
The pinned RTL's passive monitor-enable behavior is a hardware bug awaiting the
hardware team's fix; no RTL source or hardware pin is changed by this model.

### Mailbox

#### Class diagram

![alternative text](http://www.plantuml.com/plantuml/proxy?cache=no&src=https://raw.githubusercontent.com/attzonko/plantuml_test/main/test.puml)

#### State diagram

The UML state diagram depicted below represents the behavior of the mailbox state machine. The notation follows the UML conventions:

![alternative text](http://www.plantuml.com/plantuml/proxy?cache=no&src=https://raw.githubusercontent.com/rusty1968/rust_documentation/main/docs/mb_state_diagram.puml)
