# rom-2.0.2

## Caliptra ROM 2.0.2 Release Notes

Release notes for changes introduced since ROM 2.0.1 (`3824083e`) through `473ae255` on the `caliptra-2.0` branch.

### Fixes

- **Randomize AES ENTROPY_IF_SEED on reset** ([#3487](https://github.com/chipsalliance/caliptra-sw/pull/3487), [#3495](https://github.com/chipsalliance/caliptra-sw/pull/3495))
- **Handle mailbox FSM error state and unexpected DataReady** ([#3393](https://github.com/chipsalliance/caliptra-sw/pull/3393), [#3516](https://github.com/chipsalliance/caliptra-sw/pull/3516))
- **Add MLDSA pairwise consistency test (PCT)** ([#TODO](https://github.com/chipsalliance/caliptra-sw/pull/TODO))
- **Refactor x509 TBS to be split around public key** ([#TODO](https://github.com/chipsalliance/caliptra-sw/pull/TODO))

# rom-2.0.1

## Caliptra ROM 2.0.1 Release Notes

Release notes for changes introduced since ROM 2.0.0 (`62c8009d`) through `3824083e` on the `caliptra-2.0` branch.

### Features

- **Add CM_SHA command** ([#3162](https://github.com/chipsalliance/caliptra-sw/pull/3162))

### Fixes

- **Allow configuration of entropy_src for low-entropy sources and lock configuration** ([#3270](https://github.com/chipsalliance/caliptra-sw/pull/3270))
- **Fix SHA ACC lock release during debug unlock causing KAT failure** ([#3268](https://github.com/chipsalliance/caliptra-sw/pull/3268))
- **Initialize IDEVID CSR envelope marker and size fields** ([#3156](https://github.com/chipsalliance/caliptra-sw/pull/3156))
  Properly initializes the marker and size fields of the IDEVID CSR envelope.
- **Fix ProductionAuthDebugUnlockChallenge length calculation** ([#3103](https://github.com/chipsalliance/caliptra-sw/pull/3103))
- **Use block size of 64 for DMA I3C transfers** ([#2959](https://github.com/chipsalliance/caliptra-sw/pull/2959))
- **Reset INDIRECT_FIFO_CTRL FIFO after activating** ([#3172](https://github.com/chipsalliance/caliptra-sw/pull/3172))

# fw-2.0.1

## Caliptra FW 2.0.1 Release Notes

Release notes for changes introduced since FW 2.0.0 (`8efce033`) through `1a77f868` on the `caliptra-2.0` branch.

### Features

- **Implement MCU hitless firmware update reset sequence** ([#3128](https://github.com/chipsalliance/caliptra-sw/pull/3128))

### Fixes

- **Use a block size of 64 for DMA I3C transfers** ([#2959](https://github.com/chipsalliance/caliptra-sw/pull/2959))
- **Initialize kek_next_iv to a random value** ([#3215](https://github.com/chipsalliance/caliptra-sw/pull/3215))
- **Reset RECOVERY_CTRL to inactivate state after image authentication** ([#2972](https://github.com/chipsalliance/caliptra-sw/pull/2972))
- **Reset INDIRECT_FIFO_CTRL FIFO after activating** ([#3172](https://github.com/chipsalliance/caliptra-sw/pull/3172))
- **Set RESET_REASON before clearing FW_EXEC_CTRL during FW activation** ([#3174](https://github.com/chipsalliance/caliptra-sw/pull/3174))
- **Set FW_EXEC_CTRL value before resetting MCU** ([#3200](https://github.com/chipsalliance/caliptra-sw/pull/3200))

# fw-2.0.0

## Caliptra FW 2.0.0 Release Notes

Official release of Caliptra Core FMC and Runtime version 2.0.0 (`8efce033`).

This is a major release introducing Caliptra 2.0 FMC and Runtime firmware support with MLDSA87 post-quantum cryptography, subsystem mode, streaming boot over I3C, the cryptographic mailbox (including new support for hardware AES and ECDH), and larger FW size and mailbox sizes.

# rom-2.0.0

## Caliptra ROM 2.0.0 Release Notes

Official release of Caliptra Core ROM version 2.0.0 (`62c8009d`).

This is a major release introducing Caliptra 2.0 architecture support with MLDSA87 post-quantum cryptography, subsystem mode, streaming boot over I3C, and larger ROM, FW, and mailbox sizes.
