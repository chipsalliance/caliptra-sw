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
