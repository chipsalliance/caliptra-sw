# fw-2.0.2

## Caliptra FW 2.0.2 Release Notes

Release notes for changes introduced since FW 2.0.1.

### Features

- **DPE Upgrades**:
  - DPE core upgrades including support for SVN in `DeriveContext`, a new Crypto API, and unified environment creation ([99c1d64a](https://github.com/chipsalliance/caliptra-sw/commit/99c1d64ad3b15595f6604dd211676e16256d6911))
  - Support DPE ML-DSA hybrid mode ([#3622](https://github.com/chipsalliance/caliptra-sw/pull/3622))
  - Add a new command to chunk DPE certificates (`CertifyKeyChunksReq`) ([#3765](https://github.com/chipsalliance/caliptra-sw/pull/3765))
- **Attested CSR**:
  - Add Attested CSR support for Runtime Alias key ([#3406](https://github.com/chipsalliance/caliptra-sw/pull/3406)) and FMC Alias key ([#3405](https://github.com/chipsalliance/caliptra-sw/pull/3405))
  - Add `GET_ATTESTED_ECC384_CSR` and `GET_ATTESTED_MLDSA87_CSR` mailbox commands ([#3339](https://github.com/chipsalliance/caliptra-sw/pull/3339))
- **Cryptographic & Drivers**:
  - Add ML-DSA pairwise consistency test (PCT) ([#3547](https://github.com/chipsalliance/caliptra-sw/pull/3547))
  - Add ECDH pairwise consistency test (PCT) ([#3546](https://github.com/chipsalliance/caliptra-sw/pull/3546))
  - Add MLDSA-87 SigVer KAT and CTR_DRBG-AES-256 KAT coverage ([#3795](https://github.com/chipsalliance/caliptra-sw/pull/3795), [#3706](https://github.com/chipsalliance/caliptra-sw/pull/3706))
  - Add hashing step to ECDSA KAT ([#3821](https://github.com/chipsalliance/caliptra-sw/pull/3821))
- **Runtime & Firmware Capabilities**:
  - Add more information about how firmware was verified to `fw_info` ([#3638](https://github.com/chipsalliance/caliptra-sw/pull/3638))
  - Modify `AuthorizeAndStash` command to not skip stash by default ([#3402](https://github.com/chipsalliance/caliptra-sw/pull/3402))
- **Optimizations**:
  - Skip Runtime journey PCR extension when booting the same firmware version ([#3055](https://github.com/chipsalliance/caliptra-sw/pull/3055))

### Fixes

- **Security & Debug Unlock**:
  - Fix some logic around production debug unlock ([#3694](https://github.com/chipsalliance/caliptra-sw/pull/3694), [#3766](https://github.com/chipsalliance/caliptra-sw/pull/3766), [#3628](https://github.com/chipsalliance/caliptra-sw/pull/3628), [#3636](https://github.com/chipsalliance/caliptra-sw/pull/3636))
  - Fix TAP mailbox availability after debug unlock ([#3848](https://github.com/chipsalliance/caliptra-sw/pull/3848))
  - Fix WDT stop after production debug unlock ([#3675](https://github.com/chipsalliance/caliptra-sw/pull/3675), [#3676](https://github.com/chipsalliance/caliptra-sw/pull/3676))
  - Re-derive dummy FMC key pairs on warm reset in debug unlocked mode as a workaround for key vault reset ([143b72ec](https://github.com/chipsalliance/caliptra-sw/commit/143b72ec47c1b9c9728e95c30e0b79dd163fa323))
- **Boot & Recovery**:
  - Populate Runtime recovery reason on boot failures and synchronize recovery codes ([852d1e25](https://github.com/chipsalliance/caliptra-sw/commit/852d1e252809f9bbe5390cf9c2c8579196a0b549))
  - Advertise recovery capabilities (PROT_CAP_2) and clean up recovery reason mapping ([25eed8c5](https://github.com/chipsalliance/caliptra-sw/commit/25eed8c57d029e2510bdf042401639346bf041dd))
- **Robustness & Bug Fixes**:
  - Bound authority manifest metadata lookup by `entry_count` ([#3732](https://github.com/chipsalliance/caliptra-sw/pull/3732))
  - Implement address-based authorize-and-stash measurement ([#3688](https://github.com/chipsalliance/caliptra-sw/pull/3688))
  - Fix AES-GCM streaming GHASH save/restore bug in drivers ([#3790](https://github.com/chipsalliance/caliptra-sw/pull/3790))
  - Fix mailbox packet handling to validate packet length (`dlen`) against mailbox SRAM size ([#3414](https://github.com/chipsalliance/caliptra-sw/pull/3414), [#3571](https://github.com/chipsalliance/caliptra-sw/pull/3571))
  - Handle mailbox FSM error state and unexpected DataReady in drivers ([#3393](https://github.com/chipsalliance/caliptra-sw/pull/3393), [#3516](https://github.com/chipsalliance/caliptra-sw/pull/3516))
  - Mark hash-based ECDSA/LMS verification as FIPS non-approved ([#3803](https://github.com/chipsalliance/caliptra-sw/pull/3803))
  - Add missing DICE EKU extension to Runtime alias certificates ([#3202](https://github.com/chipsalliance/caliptra-sw/pull/3202))
  - Use configurable OTP status offset for UDS/FE programming ([#3723](https://github.com/chipsalliance/caliptra-sw/pull/3723))

# rom-2.0.3

## Caliptra ROM 2.0.3 Release Notes

Release notes for changes introduced since ROM 2.0.2 (`473ae255`) through `c1e3ff2e` on the `caliptra-2.0` branch.

### Features

- **Use SS_STRAP_GENERIC[2] to configure entropy_src single-bit mode during CSRNG initialization** ([#3809](https://github.com/chipsalliance/caliptra-sw/pull/3809))
- **Add CTR_DRBG-AES-256 and MLDSA-87 SigVer KAT coverage** ([#3706](https://github.com/chipsalliance/caliptra-sw/pull/3706), [#3795](https://github.com/chipsalliance/caliptra-sw/pull/3795))

### Fixes

- **Zeroize ROM state before acknowledging SHUTDOWN** ([#3807](https://github.com/chipsalliance/caliptra-sw/pull/3807))
- **Update CSRNG entropy source configuration and health-test behavior** ([#3788](https://github.com/chipsalliance/caliptra-sw/pull/3788), [#3836](https://github.com/chipsalliance/caliptra-sw/pull/3836))
- **Fix production debug unlock behavior** ([#3629](https://github.com/chipsalliance/caliptra-sw/pull/3629), [#3676](https://github.com/chipsalliance/caliptra-sw/pull/3676), [#3848](https://github.com/chipsalliance/caliptra-sw/pull/3848))
- **Bind production debug unlock tokens to the device UDI** ([#3694](https://github.com/chipsalliance/caliptra-sw/pull/3694))
- **Move production debug unlock token public-key hash check from mailbox SRAM to stack** ([#3766](https://github.com/chipsalliance/caliptra-sw/pull/3766))
- **Advertise recovery capabilities and report boot failure reasons** ([#3846](https://github.com/chipsalliance/caliptra-sw/pull/3846))
- **Use configurable OTP status offset for UDS/FE programming** ([#3723](https://github.com/chipsalliance/caliptra-sw/pull/3723))
- **Mark hash-based ECDSA/LMS verify as FIPS non-approved and add ECDSA KAT hashing coverage** ([#3803](https://github.com/chipsalliance/caliptra-sw/pull/3803), [#3821](https://github.com/chipsalliance/caliptra-sw/pull/3821))

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
