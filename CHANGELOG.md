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

