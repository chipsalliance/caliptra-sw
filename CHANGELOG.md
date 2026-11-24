# rt-1.2.4
## Caliptra Runtime/FMC 1.2.4 Release Notes

Release notes for changes introduced since rt-1.2.3

### Features
- Added GET_PCR_LOG command
- RT journey measurement is now reported in DPE in addition to the current
- Changed "MBVP" measurement to "CCIV" and added several fields from FW bundle manifest
- Removed manifest hash from RT alias CDI
- Corrected Integrity Registers TCB Info index to 11
- Limited POPULATE_IDEV_ID to PL0 callers
- Fixed issue with warm resets when debug unlocked

# fw-1.2.5
## Caliptra Runtime/FMC 1.2.5 Release Notes

Release notes for changes introduced since fw-1.2.4

### Features
- Updated FIPS CMVP Test Suite
- Included DPE Cert fixes
- Various instruction memory optimizations

# fw-1.3.0
## Caliptra Runtime/FMC 1.3.0 Release Notes

Release nots for changes introduced since fw-1.2.5

### Features
 - Implemented software support for PQC(MLDSA) including:
    * Initialization of PQC Seed
    * MLDSA signature verification
    * Attestation for firmware downstream of Caliptra Core
 - Updated to rust toolchain 1.95

# fw-1.3.1
## Caliptra Runtime/FMC 1.3.1 Release Notes

Release notes for changes introduced since fw-1.3.0

### Features
- Added `GET_ATTESTED_PQ_CSR` mailbox command
- Restricted `EXTEND_PCR` to PL0 callers and permitted PL0 callers to extend PCR31
- Updated DPE to version 0.14 and included TCB info size fix
- Added dynamic power handling of `entropy_src` and CSRNG command readiness/completion synchronization fixes
- Updated `libcaliptra` register access APIs to return `void` under `LIBCALIPTRA_MMIO_API_V2`
- Various instruction memory optimizations

# rom-1.2.1
## Caliptra ROM 1.2.1 Release Notes

Release notes for changes introduced since rom-1.2.0

### Features
- Added option to force the external TRNG (eTRNG) on devices with the internal TRNG enabled (#4457)
- Added internal TRNG single-bit RO filter selection (#4457)

### Fixes
- **Boot & Image Loading**:
  - Additional FMC bounds checks in ROM (#4215)
  - Validate FMC and Runtime entry points against image bounds (#4224)
  - Authenticate firmware manifest fields from the protected in-memory snapshot (#4271)
  - Reject firmware segments that extend beyond the declared bundle size (#4271)
  - Require FMC and Runtime image data to be contiguous in the bundle (#4271)
  - Require FMC and Runtime entry points to equal their load addresses (#4280)

### Build & Toolchain
- Updated to rust toolchain 1.95 (#3749)
- Switched to the unified CFI library shared with other Caliptra projects (#3778)
- Shortened ROM log messages, including reformatting watchdog timeout logging, to reduce code size of the ROM with logging

### Compatibility Notes
- **Firmware**: FW 1.3.2 or newer must be used with this ROM due to the boot and image loading hardening

# fw-1.3.2
## Caliptra Runtime/FMC 1.3.2 Release Notes

Release notes for changes introduced since fw-1.3.1

### Features
- Added option to force the external TRNG (eTRNG) on devices with the internal TRNG enabled (#4457)

### Fixes
- **Build Changes**:
  - Force FMC and RT entry points to offset 0 in the binary (#4280)
