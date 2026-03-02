// Licensed under the Apache-2.0 license

use super::MAX_CSR_SIZE;
use crate::Drivers;
use caliptra_drivers::FmcAliasCsrs;
use caliptra_error::{CaliptraError, CaliptraResult};

/// Retrieve the FMC Alias ECC384 CSR from persistent data.
pub fn generate_fmc_alias_ecc_csr(
    drivers: &mut Drivers,
    csr_buf: &mut [u8; MAX_CSR_SIZE],
) -> CaliptraResult<usize> {
    let csr_persistent_mem = &drivers.persistent_data.get().fw.fmc_alias_csr;

    match csr_persistent_mem.get_ecc_csr_len() {
        FmcAliasCsrs::UNPROVISIONED_CSR => Err(CaliptraError::RUNTIME_GET_FMC_CSR_UNPROVISIONED),
        0 => Err(CaliptraError::RUNTIME_GET_FMC_CSR_UNSUPPORTED_FMC),
        _ => {
            let csr = csr_persistent_mem
                .get_ecc_csr()
                .ok_or(CaliptraError::RUNTIME_GET_FMC_CSR_UNPROVISIONED)?;
            csr_buf[..csr.len()].copy_from_slice(csr);
            Ok(csr.len())
        }
    }
}

/// Retrieve the FMC Alias ML-DSA87 CSR from persistent data.
pub fn generate_fmc_alias_mldsa_csr(
    drivers: &mut Drivers,
    csr_buf: &mut [u8; MAX_CSR_SIZE],
) -> CaliptraResult<usize> {
    let csr_persistent_mem = &drivers.persistent_data.get().fw.fmc_alias_csr;

    match csr_persistent_mem.get_mldsa_csr_len() {
        FmcAliasCsrs::UNPROVISIONED_CSR => Err(CaliptraError::RUNTIME_GET_FMC_CSR_UNPROVISIONED),
        0 => Err(CaliptraError::RUNTIME_GET_FMC_CSR_UNSUPPORTED_FMC),
        _ => {
            let csr = csr_persistent_mem
                .get_mldsa_csr()
                .ok_or(CaliptraError::RUNTIME_GET_FMC_CSR_UNPROVISIONED)?;
            csr_buf[..csr.len()].copy_from_slice(csr);
            Ok(csr.len())
        }
    }
}
