// Licensed under the Apache-2.0 license

use crate::{mutrefbytes, Drivers};

use caliptra_cfi_derive::cfi_impl_fn;

use caliptra_common::mailbox_api::{GetFmcAliasCsrResp, MailboxRespHeader, ResponseVarSize};
use caliptra_error::{CaliptraError, CaliptraResult};

use caliptra_drivers::FmcAliasCsrs;

pub struct GetFmcAliasCsrCmd;
impl GetFmcAliasCsrCmd {
    #[cfg_attr(feature = "cfi", cfi_impl_fn)]
    #[inline(never)]
    pub(crate) fn execute(drivers: &mut Drivers, mbox_resp: &mut [u8]) -> CaliptraResult<usize> {
        let csr_persistent_mem = &drivers.persistent_data.get().fw.fmc_alias_csr;

        match csr_persistent_mem.get_ecc_csr_len() {
            FmcAliasCsrs::UNPROVISIONED_CSR => {
                Err(CaliptraError::RUNTIME_GET_FMC_CSR_UNPROVISIONED)
            }
            0 => Err(CaliptraError::RUNTIME_GET_FMC_CSR_UNSUPPORTED_FMC),
            _ => {
                // the compiler has trouble understanding that csr.len() is the same
                // as csr_persistent_mem.get_csr_len()
                let csr = csr_persistent_mem
                    .get_ecc_csr()
                    .ok_or(CaliptraError::RUNTIME_GET_FMC_CSR_UNPROVISIONED)?;
                let resp = mutrefbytes::<GetFmcAliasCsrResp>(mbox_resp)?;
                resp.hdr = MailboxRespHeader::default();
                resp.data_size = csr.len() as u32;
                resp.data[..csr.len()].copy_from_slice(csr);
                Ok(resp.partial_len()?)
            }
        }
    }
}

pub struct GetFmcAliasMldsaCsrCmd;
impl GetFmcAliasMldsaCsrCmd {
    #[cfg_attr(feature = "cfi", cfi_impl_fn)]
    #[inline(never)]
    pub(crate) fn execute(drivers: &mut Drivers, mbox_resp: &mut [u8]) -> CaliptraResult<usize> {
        let csr_persistent_mem = &drivers.persistent_data.get().fw.fmc_alias_csr;

        match csr_persistent_mem.get_mldsa_csr_len() {
            FmcAliasCsrs::UNPROVISIONED_CSR => {
                Err(CaliptraError::RUNTIME_GET_FMC_CSR_UNPROVISIONED)
            }
            0 => Err(CaliptraError::RUNTIME_GET_FMC_CSR_UNSUPPORTED_FMC),
            _ => {
                // the compiler has trouble understanding that csr.len() is the same
                // as csr_persistent_mem.get_csr_len()
                let csr = csr_persistent_mem
                    .get_mldsa_csr()
                    .ok_or(CaliptraError::RUNTIME_GET_FMC_CSR_UNPROVISIONED)?;
                let resp = mutrefbytes::<GetFmcAliasCsrResp>(mbox_resp)?;
                resp.hdr = MailboxRespHeader::default();
                resp.data_size = csr.len() as u32;
                resp.data[..csr.len()].copy_from_slice(csr);
                Ok(resp.partial_len()?)
            }
        }
    }
}
