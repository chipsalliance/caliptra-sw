// Licensed under the Apache-2.0 license

use crate::{mutrefbytes, Drivers};

use caliptra_cfi_derive_git::cfi_impl_fn;

use caliptra_common::mailbox_api::{GetFmcAliasCsrResp, MailboxRespHeader, ResponseVarSize};
use caliptra_error::{CaliptraError, CaliptraResult};

use caliptra_drivers::FmcAliasCsrs;

/// Retrieves the FMC Alias ECC CSR data from persistent memory and copies it into the provided buffer.
/// Returns the number of bytes written to the buffer.
pub(crate) fn get_fmc_alias_ecc_csr_data(
    drivers: &Drivers,
    buffer: &mut [u8],
) -> CaliptraResult<usize> {
    let csr_persistent_mem = &drivers.persistent_data.get().fw.fmc_alias_csr;

    match csr_persistent_mem.get_ecc_csr_len() {
        FmcAliasCsrs::UNPROVISIONED_CSR => Err(CaliptraError::RUNTIME_GET_FMC_CSR_UNPROVISIONED),
        0 => Err(CaliptraError::RUNTIME_GET_FMC_CSR_UNSUPPORTED_FMC),
        _ => {
            let csr = csr_persistent_mem
                .get_ecc_csr()
                .ok_or(CaliptraError::RUNTIME_GET_FMC_CSR_UNPROVISIONED)?;

            if buffer.len() < csr.len() {
                return Err(CaliptraError::RUNTIME_INSUFFICIENT_MEMORY);
            }

            buffer[..csr.len()].copy_from_slice(csr);
            Ok(csr.len())
        }
    }
}

pub struct GetFmcAliasCsrCmd;
impl GetFmcAliasCsrCmd {
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    #[inline(never)]
    pub(crate) fn execute(drivers: &mut Drivers, mbox_resp: &mut [u8]) -> CaliptraResult<usize> {
        let resp = mutrefbytes::<GetFmcAliasCsrResp>(mbox_resp)?;
        resp.hdr = MailboxRespHeader::default();
        let data_len = get_fmc_alias_ecc_csr_data(drivers, &mut resp.data)?;
        resp.data_size = data_len as u32;
        Ok(resp.partial_len()?)
    }
}

/// Retrieves the FMC Alias ML-DSA CSR data from persistent memory and copies it into the provided buffer.
/// Returns the number of bytes written to the buffer.
pub(crate) fn get_fmc_alias_mldsa_csr_data(
    drivers: &Drivers,
    buffer: &mut [u8],
) -> CaliptraResult<usize> {
    let csr_persistent_mem = &drivers.persistent_data.get().fw.fmc_alias_csr;

    match csr_persistent_mem.get_mldsa_csr_len() {
        FmcAliasCsrs::UNPROVISIONED_CSR => Err(CaliptraError::RUNTIME_GET_FMC_CSR_UNPROVISIONED),
        0 => Err(CaliptraError::RUNTIME_GET_FMC_CSR_UNSUPPORTED_FMC),
        _ => {
            let csr = csr_persistent_mem
                .get_mldsa_csr()
                .ok_or(CaliptraError::RUNTIME_GET_FMC_CSR_UNPROVISIONED)?;

            if buffer.len() < csr.len() {
                return Err(CaliptraError::RUNTIME_INSUFFICIENT_MEMORY);
            }

            buffer[..csr.len()].copy_from_slice(csr);
            Ok(csr.len())
        }
    }
}

pub struct GetFmcAliasMldsaCsrCmd;
impl GetFmcAliasMldsaCsrCmd {
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    #[inline(never)]
    pub(crate) fn execute(drivers: &mut Drivers, mbox_resp: &mut [u8]) -> CaliptraResult<usize> {
        let resp = mutrefbytes::<GetFmcAliasCsrResp>(mbox_resp)?;
        resp.hdr = MailboxRespHeader::default();
        let data_len = get_fmc_alias_mldsa_csr_data(drivers, &mut resp.data)?;
        resp.data_size = data_len as u32;
        Ok(resp.partial_len()?)
    }
}
