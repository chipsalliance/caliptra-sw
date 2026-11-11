# fw-2.0.4

## Caliptra Firmware 2.0.4 Release Notes

Release notes for changes introduced since Firmware 2.0.3.

### Features

- **Runtime, Authorization & Attestation**:
  - Support owner-only authorization manifests and backward-compatible manifest selection for firmware activation (#4233, #3720)
  - Bind original/vendor SoC manifests to an optional signed device UEID entry (#4213)
  - Support vendor-authorized debug artifacts and report active debug policy through `FW_INFO` (#4219)
  - Add the OCP EAT profile, ECC/ML-DSA algorithm selection, and CDDL-compliant attested CSR templates (#4181, #4223)
  - Support context-aware raw ML-DSA signing through DPE (#4314)
  - Add opt-in command-count-triggered FIPS self-tests with startup-latched configuration (#4351)
  - Add `CM_KEY_GEN` for internally generated encrypted AES, ECDSA, ML-DSA, and HMAC keys (#4188, #4397)
  - Report live FE provisioning status through `FW_INFO` using the native 2.0 OTP layout (#4366, #4397)
- **Host Library**:
  - Add `INSTALL_OWNER_PK_HASH` and `SET_OWNER_AUTH_MANIFEST` commands to libcaliptra (#4293, #4328)
  - Add streaming `CM_SHA_INIT`, `CM_SHA_UPDATE`, and `CM_SHA_FINAL` commands and `MLDSA87_VERIFY` to libcaliptra (#4357, #4373)

### Fixes

- **Runtime Security & Recovery**:
  - Extend the vendor+owner SoC manifest owner preamble signature to cover version, SVN, and flags as well as owner public keys (#4343)
  - Bind MCU activation to the signed installation destination and validate complete destination/staging ranges and SRAM capacity before modifying state (#4323)
  - Enforce the maximum firmware SVN of 128 during image verification independently of lifecycle and anti-rollback settings (#4251)
  - Preserve named `RTMR`, `CCIV`, `SOMV`, `SOMO`, and `MCFW` TCI identifier bytes in DPE attestation (#4338)
  - Reserve PCRs and enforce PL0 access for privileged mailbox operations and `EXTEND_PCR` (#4138, #4175, #4170, #4197)
  - Enforce key-usage checks for cryptographic mailbox AES operations and clear temporary plaintext AES, AES-GCM, and ECDH contexts (#4164, #4367)
  - Wait for recovery payload deassertion between images and report device healthy after recovery completes (#4236)
  - Honor configured 64-bit mailbox watchdog timeouts while enforcing a 20-million-cycle minimum (#4275, watchdog subset only)
- **FMC & Drivers**:
  - Run FMC fatal-error cleanup when firmware handoff table validation fails and report ML-DSA-specific FMC alias CSR errors (#4304, #4306)
  - Wait for CSRNG command readiness and completion and zeroize cryptographic hardware on driver errors (#4322, #3346)
  - Fix the libcaliptra Zephyr include path and ML-DSA verification declaration (#4184)

### Compatibility Notes

- **`FW_INFO`**: Responses are now 400 bytes in both subsystem and standalone modes. Update consumers accordingly. FE status value `2` is reserved and never returned on Caliptra 2.0; standalone mode reports all partitions as error/indeterminate (#4366, #4397).
- **Key generation**: `CM_KEY_GEN` supports the native 2.0 key types listed above; ML-KEM remains unsupported (#4188, #4397).
- **Authorization manifests**: Re-sign vendor+owner SoC manifests to cover `version`, `svn`, `flags`, and owner public keys, and update pinned `SOMO` measurements. Owner-only manifests are unaffected (#4343).
- **DPE identities**: Corrected named TCI identifiers change affected certificate identifiers and derived keys. Perform a cold boot; retained contexts are not migrated (#4338).
- **Optional UEID binding**: Firmware ID `0xFFF` is reserved for the optional original/vendor-manifest UEID entry. Legacy manifests without that entry remain valid; owner-only manifests retain ordinary firmware-ID semantics (#4213).
- **Autonomous self-tests**: RT samples `CPTRA_GENERIC_INPUT_WIRES[1]` at every startup. Keep bit 0 clear unless enabling a valid configuration in a supported build. Invalid or unsupported enabled configurations fail startup with `RUNTIME_INVALID_SELF_TEST_CONFIG`. Tests are workload-triggered, not time-based; continuous mailbox traffic can defer them (#4351).
- **ROM-dependent fixes**: The boot and image-verification fixes in ROM 2.0.5 require newly built ROM artifacts; a firmware-only update cannot install them. ROM 2.0.5 requires offset-zero entry points and contiguous FMC/Runtime image payloads (#4280, #4271).

**Full Changelog**: https://github.com/chipsalliance/caliptra-sw/compare/fw-2.0.3...fw-2.0.4

# rom-2.0.5

## Caliptra ROM 2.0.5 Release Notes

Release notes for changes introduced since ROM 2.0.4.

The published [`rom-2.0.5rc1` release](https://github.com/chipsalliance/caliptra-sw/releases/tag/rom-2.0.5rc1)
was built from `c7ed8c09` with embedded ROM version 2.0.4 and FMC/Runtime
versions 2.0.2. ROM 2.0.5 and firmware 2.0.4 artifacts must be rebuilt with
the updated embedded versions. The RC1 tag and published artifacts remain
unchanged.

### Fixes

- **Boot & Image Verification**:
  - Verify firmware bytes after loading into ICCM and make post-load Runtime digest mismatches fatal during update reset (#3702, #4150)
  - Validate FMC/Runtime entry points against their authenticated image bounds and require entry points to equal load addresses (#4224, #4280)
  - Authenticate the protected manifest snapshot, reject image segments outside the supplied bundle, require contiguous FMC/Runtime data, and reject overflowing AXI source ranges (#4271)
  - Enforce the maximum firmware SVN of 128 independently of lifecycle and anti-rollback settings (#4251)
- **Cryptography & Self-Tests**:
  - Wait for CSRNG command readiness and completion, and zeroize cryptographic hardware on driver errors (#4322, #3346)
  - Report boot-time KAT failures as non-fatal and continue remaining tests in the Unprovisioned lifecycle. Preserve strict handling in provisioned lifecycles and explicit self-test requests; entropy-restoration errors remain fatal in every lifecycle (#4350).

### Compatibility Notes

- ROM 2.0.5 requires images whose entry points equal their load addresses and whose FMC/Runtime payloads are contiguous. Previously accepted signed images with nonzero in-image entry offsets are rejected (#4280, #4271).
- Rebuild ROM artifacts from this release preparation to obtain the embedded 2.0.5 version and updated logging/non-logging frozen hashes. Existing ROM 2.0.4 artifacts and tags are unchanged.

**Full Changelog**: https://github.com/chipsalliance/caliptra-sw/compare/rom-2.0.4...rom-2.0.5

# rom-2.0.4

## Caliptra ROM 2.0.4 Release Notes

Release notes for changes introduced since ROM 2.0.3 (`bf9ca633`) through `eb148980` on the `caliptra-2.0` branch.

The published [`rom-2.0.4rc1` release](https://github.com/chipsalliance/caliptra-sw/releases/tag/release_v20260928_0-2.0) was built from `b5198fc0` with the embedded ROM version still set to 2.0.3. ROM 2.0.4 artifacts must be rebuilt from a commit containing this version bump; the already-published RC artifacts are unchanged.

### Features

- **Support vendor-authorized debug artifacts with fuse-controlled enforcement** ([#4219](https://github.com/chipsalliance/caliptra-sw/pull/4219))
- **Record subsystem mode in ROM DeviceStatus measurements** ([#3930](https://github.com/chipsalliance/caliptra-sw/pull/3930))
- **Add the OCP EAT profile and ECC/ML-DSA algorithm selection to DICE certificate generation** ([#4181](https://github.com/chipsalliance/caliptra-sw/pull/4181))

### Fixes

- **Validate FMC image offsets and bounds before cold-boot and update-reset loading** ([#4215](https://github.com/chipsalliance/caliptra-sw/pull/4215), [#4236](https://github.com/chipsalliance/caliptra-sw/pull/4236))
- **Run the CSRNG KAT before CFI initialization consumes entropy** ([#4106](https://github.com/chipsalliance/caliptra-sw/pull/4106), [#4236](https://github.com/chipsalliance/caliptra-sw/pull/4236))
- **Handle dynamic entropy-source power state during CSRNG use** ([#4072](https://github.com/chipsalliance/caliptra-sw/pull/4072))
- **Chunk DMA image hashing to support images larger than 1 MiB** ([#3940](https://github.com/chipsalliance/caliptra-sw/pull/3940))

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
  - Fix runtime FIPS shutdown zeroization ([#3908](https://github.com/chipsalliance/caliptra-sw/pull/3908))

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
