# rom-2.1.1

## Caliptra ROM 2.1.1 Release Notes

Release notes for changes introduced since ROM 2.1.0.

### Fixes

- rom: Seed ABR_ENTROPY on startup for SCA protection (#3507)
- rom: Randomize AES ENTROPY_IF_SEED on reset (#3487)
- drivers: handle mailbox FSM error state and unexpected DataReady (#3393)
- Consolidate ABR register usage across MLDSA and MLKEM drivers (#3447)
- Remove duplicate CFI Git library to reduce code size (#3368)
- [drivers]: Zeroize hardware on error (#3346)
- [OCP-LOCK]: Add more CFI to ROM flow (#3265)

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
