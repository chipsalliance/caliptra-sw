# fw-2.1.3

This is a combined runtime and FMC release.

## Caliptra Firmware 2.1.3 Release Notes

Release notes for changes introduced since Firmware 2.1.2.

### Features

- **Authorization, Attestation & DPE**:
  - Support vendor-authorized debug artifacts and report active debug policy in `FW_INFO` (#4210)
  - Update `caliptra-dpe` references, error codes, and crypto APIs to reduce stack usage in `SIGN_WITH_EXPORTED_*` (#4113)
- **Runtime, Drivers & Cryptography**:
  - Add `LOAD_KAT_MEK` mailbox command for Encryption Engine self-tests (#4143)
  - Allow 32-byte ML-KEM keys in `CM_HKDF` (#4205)
  - Shrink ML-KEM-1024 KAT `.rodata` footprint by replacing full decapsulation vectors with a digest check (#4142)
  - Add `libcaliptra` C bindings for the OCP-LOCK API (#4165)
- **FPGA, Hardware Model & Tooling**:
  - Add `cargo xtask build recovery-images` command for OCP recovery testing (#4140)
  - Make FPGA `flash-boot` a compile-time flag (#4128)
  - Add external I3C host boot test for FPGA (#4139)
  - Add Mjolnir GitHub workflow and configuration (#4159)
  - Update Rust toolchain to 1.96.1 (#4063, #4198)
  - Test ML-KEM with Wycheproof vectors in runtime integration tests (#4122)

### Fixes

- **Runtime, Security & Cryptography**:
  - Enforce AES-XTS key half distinctness during key generation and decryption (#4141)
  - Enforce `key_usage` checks in cryptographic mailbox AES operations (#4111)
  - Consolidate and expand PL0 privilege checks across runtime mailbox commands (#4131)
  - Reserve PCRs and restrict `EXTEND_PCR` to PL0 callers (#4138, #4197)
  - Mark device healthy after encrypted firmware recovery (#4214)
- **Library, CI & Tests**:
  - Fix `libcaliptra` Zephyr include path and `caliptra_mldsa_verify_req` forward declaration (#4184)
  - Update MCU firmware revision and flash image test expectations (#4129)
- **Documentation & Release Info**:
  - Fix runtime mailbox command discrepancies, AES command codes, and stable key command encoding in documentation (#4157, #4172, #4173)

**Full Changelog**: https://github.com/chipsalliance/caliptra-sw/compare/fw-2.1.2...fw-2.1.3

# fw-2.1.2

This is a combined runtime and FMC release.

## Caliptra Firmware 2.1.2 Release Notes

Release notes for changes introduced since Firmware 2.1.1.

### Features

- **Authorization, Attestation & DPE**:
  - Add owner authorization manifest support (#3824)
  - Record subsystem mode in ROM `DeviceStatus` measurements (#3930)
  - Anchor MCU runtime and SoC manifest measurements in Caliptra-managed DPE contexts and harden DPE index handling across hitless updates (#4070)
  - Report tagged DPE context SVN through `DPE_GET_TAGGED_TCI` (#4083)
  - Expose manifest SVN state through `FW_INFO` (#4082)
  - Allow PL1 callers to use `AUTHORIZE_AND_STASH` with `SKIP_STASH` (#4077)
- **Runtime, Drivers & Firmware Images**:
  - Chunk DMA image hashing to support images larger than 1 MiB (#3940)
  - Skip ELF metadata segments when constructing firmware images (#3970)
  - Reduce stack usage in `SIGN_WITH_EXPORTED_MLDSA` (#4019)
  - Add dynamic power handling for `entropy_src` (#4038)
- **FPGA, Hardware Model & Emulator**:
  - Auto-generate FPGA OTP fuse aliases from caliptra-mcu-sw fuse definitions (#3909)
  - Add an OpenOCD JTAG `load_image` command (#3937)
  - Add feature gates for multiple hardware revisions (#3935)
  - Generate a stable FPGA MAC address from the boot SD serial number (#3979)
  - Support downloading prebuilt Caliptra artifacts in the builder (#3999)
  - Add `ProvisioningStage` to subsystem initialization parameters (#4007)
  - Support running the emulator with 2.0 and 2.1 firmware (#4012)
  - Remove CFI from the hardware model dependency tree (#4039)
  - Add the `SpareI3cControlSts` register (#4086)
  - Add a boot sequence for an external I3C host (#4091)
- **Build, Test & Documentation**:
  - Automate merging new bitstreams (#3896)
  - Add stable key derivation diagrams (#3934)
  - Update the ROM IDevID CSR specification to match the implementation (#3951)
  - Add standard PKCS#8 and SPKI fake-key assets (#4025)
  - Enable multiple hardware revisions in build, test, and nightly workflows (#4078)

### Fixes

- **Subsystem, FPGA & Emulator**:
  - Fix FPGA MCU smoke tests for the latest caliptra-mcu-sw ROM (#3900)
  - Remove the OTP status offset fallback (#3921)
  - Correct the emulator MCU SRAM size (#3976)
  - Fix a subsystem-mode smoke test assertion (#4006)
  - Fix latching of SoC IFC interrupt lines and expose CPU halt state (#4020)
  - Restore `caliptra-builder` as a development dependency of the hardware model (#4035)
- **Authorization, Runtime & Security**:
  - Expand libcaliptra PAUSER checks and fix request setup (#3932)
  - Update OCP-LOCK error codes for HPKE failure paths (#4045)
  - Fall back to owner metadata in `GET_IMAGE_INFO` (#4088)
  - Reject the reserved MCU runtime firmware ID in `STASH_MEASUREMENT` (#4097)
  - Clean up the AES-GCM DMA handler (#4084)
- **CI & Test Compatibility**:
  - Correct MCU commit checks for workflow dispatch and caliptra-mcu-sw smoke tests (#3914, #3918, #3920)
  - Make ML-DSA the default for firmware verification tests (#3955)
  - Fix nightly subsystem-mode TCB info and PCR0 derivation expectations (#4065)
  - Support older ROMs in nightly DICE and PCR0 derivation tests (#4112)
- **Documentation & Maintenance**:
  - Rename DICE diagram HKDF labels to KBKDF (#3933)
  - Fix spelling errors in the runtime README (#3991)
  - Format ECC fake-key PEM files for RFC 7468 compliance (#4034)
  - Fix typos across ROM, FMC, emulator, and X.509 documentation (#4053)
  - Add `@parvathib` to CODEOWNERS (#4094)

**Full Changelog**: https://github.com/chipsalliance/caliptra-sw/compare/fw-2.1.1...fw-2.1.2

# fw-2.1.1

This is a combined runtime and FMC release.

## Caliptra Firmware 2.1.1 Release Notes

Release notes for changes introduced since Firmware 2.1.0.

### Features

- **DPE & Certification**:
  - Add support for `SIGN_WITH_EXPORTED_MLDSA` (#3679)
  - Add a new command to chunk DPE certificates (`CertifyKeyChunks`) (#3765)
- **Runtime/FMC Functionality**:
  - Add `ACTIVATE_FIRMWARE` `INITIAL_ACTIVATE` flag (#3720)
  - Add more telemetry to `fw_info` (#3631)

### Fixes

- **Mailbox & Debug Unlock**:
  - Fix TAP mailbox availability after debug unlock (#3848)
  - Bind debug unlock token to device UDI (#3694)
  - Fix WDT stop after production debug unlock (#3675)
  - Set `PROD_DBG_UNLOCK_IN_PROGRESS` bit in runtime to match ROM (#3628)
  - Require non-zeroized SEK & DPK for OCP-LOCK (#3606)
- **Firmware Activation & Auth**:
  - Fix `ActivateFirmware` to call `AuthorizeAndStash` correctly (#3719)
  - Fix `ACTIVATE_FIRMWARE` to use `exec_bit` instead of `fw_id` for activate bitmap (#3619)
  - Bound auth manifest metadata lookup by `entry_count` (#3732)
  - Address-based authorize-and-stash measurement (#3688)
- **FIPS & Cryptography**:
  - Fix AES-GCM streaming GHASH save/restore bug (#3790)
  - Add missing KATs in runtime start up (#3799)
  - Add ML-KEM, ML-DSA, and ECDH pairwise consistency tests (PCT) (#3548, #3547, #3546)
  - Fix runtime FIPS shutdown zeroization (#3808)
- **General**:
  - Expand PAUSER checks for mailbox operations (#3734, #3864, & #3841)

# rom-2.1.2

## Caliptra ROM 2.1.2 Release Notes

Release notes for changes introduced since ROM 2.1.1 through `45de392f` on the `main` branch.

### Features

- Add Stable Owner Key derivation from HEK seed (#3625)
- Gate fatal error reporting on recovery reset strap (#3887)

### Fixes

- Verify firmware after loading to ICCM (#3702)
- Use SS_STRAP_GENERIC[2] to configure entropy_src single-bit mode during CSRNG initialization (#3809)
- Disable entropy_src repcnts health test in ROM (#3836)
- Set CSRNG entropy_src CONF.THRESHOLD_SCOPE to false (#3788)
- Mark hash-based ECDSA/LMS verify as FIPS non-approved (#3803)
- Disallow UDS programming when debug intent is set (#3804)
- Reject prod debug unlock request if pk hash fuse is zeroized or uninitialized (#3602)
- Zeroize ROM state before acknowledging SHUTDOWN (#3807)
- Debug unlock token - move key hash check from mailbox SRAM to stack (#3766)
- Update OCP LOCK key ladder to use DOE (#3701)
- Use configurable OTP status offset for UDS/FE (#3723)
- Add MLDSA-87 SigVer KAT (#3795)
- Add CTR_DRBG-AES-256 KAT for CSRNG (#3706)
- Add Hashing step to ECDSA KAT (#3821)
- MLDSA pairwise consistency test (PCT) (#3547)
- Advertise recovery capabilities and report boot failure reasons (#3846)
- Fix TAP mailbox availability after debug unlock (#3848)
- Raise OTP error result on zeroization (#3858)
- Write lock stable keys (#3873)

# rom-2.1.1

## Caliptra ROM 2.1.1 Release Notes

Release notes for changes introduced since ROM 2.1.0.

### Fixes

- rom: Seed ABR_ENTROPY on startup for SCA protection (#3507)
- rom: Randomize AES ENTROPY_IF_SEED on reset (#3487)
- drivers: Add MLDSA pairwise consistency test (#3547)
- drivers: handle mailbox FSM error state and unexpected DataReady (#3393)
- Consolidate ABR register usage across MLDSA and MLKEM drivers (#3447)
- Remove duplicate CFI Git library to reduce code size (#3368)
- [drivers]: Zeroize hardware on error (#3346)
- [OCP-LOCK]: Add more CFI to ROM flow (#3265)
- [OCP-LOCK]: Simplified HEK Seed States (#3541)

# fw-2.1.0

This is a combined runtime and FMC release.

## Caliptra Firmware 2.1.0 Release Notes

### Features

- OCP LOCK:
  - Support for [OCP LOCK v1.0rc2](https://github.com/chipsalliance/Caliptra/blob/main/doc/ocp_lock/releases/OCP_LOCK_Specification_v1.0_RC2.pdf).
    - The specification will be updated to match the implementation
  - Introduced 16 new mailbox commands to handle the complete OCP LOCK lifecycle:
    - MEK Management: INITIALIZE_MEK_SECRET, GENERATE_MEK, DERIVE_MEK, LOAD_MEK, UNLOAD_MEK
    - MPK Management: GENERATE_MPK, ENABLE_MPK, MIX_MPK, REWRAP_MPK
    - Access Control & HPKE: ENUMERATE_HPKE_HANDLES, GET_HPKE_PUB_KEY, ROTATE_HPKE_KEY, TEST_ACCESS_KEY
    - Hardware Engine & Status: CLEAR_KEY_CACHE, GET_STATUS, GET_ALGORITHMS
  - Encryption Engine: Integrates with the Encryption Engine to securely release keys over DMA, handle execution timeouts, and perform hardware-backed key zeroization.
  - OCP LOCK is gated behind the ocp-lock compile-time feature flag.
- Encrypted Firmware Support (Subsystem Mode):
  - CM_AES_GCM_DECRYPT_DMA command for in-place AES-256-GCM decryption of data at an AXI address, with SHA384 integrity check of ciphertext before decryption.
  - Works with the ROM RI_DOWNLOAD_ENCRYPTED_FIRMWARE command to support encrypted MCU firmware booting.
- DPE:
  - Full MLDSA87 certificate chain: GET_IDEV_MLDSA87_CERT, POPULATE_IDEV_MLDSA87_CERT, GET_IDEV_MLDSA87_INFO, GET_LDEV_MLDSA87_CERT, GET_FMC_ALIAS_MLDSA87_CERT, GET_RT_ALIAS_MLDSA87_CERT, and ML-DSA DPE leaf certificates and CSRs through INVOKE_DPE_MLDSA87.
  - INVOKE_DPE_MLDSA87 command for all DPE operations with ML-DSA-87 support.
  - CERTIFY_KEY_EXTENDED_MLDSA87 command for producing ML-DSA-87 DPE leaf certificates or CSRs with custom extensions.
  - Increased the maximum number of DPE contexts from 32 to 64.
- MLKEM & SHAKE Mailbox Commands:
  - ML-KEM-1024 (FIPS 203): CM_MLKEM_KEY_GEN, CM_MLKEM_ENCAPSULATE, CM_MLKEM_DECAPSULATE for post-quantum key encapsulation.
  - SHAKE256 streaming hash: CM_SHAKE256_INIT, CM_SHAKE256_UPDATE, CM_SHAKE256_FINAL for extendable-output hashing with encrypted session context.
- External Mailbox Commands (Subsystem Mode):
  - EXTERNAL_MAILBOX_CMD allows executing mailbox commands larger than the mailbox size by referencing an external command buffer via AXI address.

# rom-2.1.0

## Caliptra ROM 2.1.0 Release Notes

Release notes for changes introduced since ROM 2.0.0 (62c8009d) through a72a76f2 on the main branch.

### Features
- Support for smaller 16 KB mailbox size in subsystem mode (#2719)
- OCP LOCK preparation (most of the features will be in the runtime)
- UDS & FE zeroization (#2841)
- CM_SHA command (#3097)
- RI_DOWNLOAD_ENCRYPTED_FIRMWARE command to support encrypted MCU firmware booting (#3043, #3225)
- Fixes
- Allow configuration of entropy_src for low-entropy sources and lock configuration (#3194 and #3256)
- Fix SHA ACC lock release during debug unlock causing KAT failure (#3179)
- Use block size of 64 for DMA I3C transfers (#2938)
- Move AES KATs to drivers and run lazily on first use (#3205). Part of a larger initiative to move more KATs out of ROM and into the FMC/runtime.
- Fixing ProductionAuthDebugUnlockChallenge length calculation (#2913)
- Restore FMC & RT Firmware Versions on Warm Reset (#2528)
- ROM: After programming UDS, set response correctly (#2733)
- Write UDS fuse granularity to its new register (#3227)
- Read OTP DAI Idle bit and direct access cmd reg offset from generic straps (#2817)
- Move stacks to beginning of DCCM (#2933) for hardware protection against stack overflows
- Certificate & Attestation
- Add missing DICE extensions to IDEVID, LDEVID, FMC and RT certs (#3202)
- Separate FMC Cert/CSR Owner and Vendor Info (#2837)
- Adding TCB info to FMC Alias CSR (#2738)
- Increase cert chain path length (#2912)
- Initialize IDEVID CSR envelope marker and size fields (#3091)
