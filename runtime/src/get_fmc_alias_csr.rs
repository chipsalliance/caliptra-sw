// Licensed under the Apache-2.0 license

use crate::Drivers;

use caliptra_cfi_derive_git::cfi_impl_fn;
use caliptra_cfi_lib_git::cfi_launder;

use caliptra_common::{
    cprintln,
    mailbox_api::{GetFmcAliasCsrReq, GetFmcAliasCsrResp, MailboxResp, MailboxRespHeader},
};
use caliptra_error::{CaliptraError, CaliptraResult};

use caliptra_drivers::{FmcAliasCsr, IdevIdCsr};

use zerocopy::{FromBytes, IntoBytes};

pub struct GetFmcAliasCsrCmd;
impl GetFmcAliasCsrCmd {
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    #[inline(never)]
    pub(crate) fn execute(drivers: &mut Drivers, cmd_args: &[u8]) -> CaliptraResult<MailboxResp> {
        let csr_persistent_mem = &drivers.persistent_data.get().fmc_alias_csr;

        match csr_persistent_mem.get_csr_len() {
            FmcAliasCsr::UNPROVISIONED_CSR => Err(CaliptraError::RUNTIME_GET_FMC_CSR_UNPROVISIONED),
            0 => Err(CaliptraError::RUNTIME_GET_FMC_CSR_UNSUPPORTED_FMC),
            len => {
                let mut resp = GetFmcAliasCsrResp {
                    data_size: len,
                    ..Default::default()
                };

                let csr = csr_persistent_mem
                    .get()
                    .ok_or(CaliptraError::RUNTIME_GET_FMC_CSR_UNPROVISIONED)?;

                // NOTE: This code will not panic.
                //
                // csr is guranteed to be the same size as `len`, and therefore
                // `resp.data_size` by the `FmcAliasCsr::get` API.
                //
                // A valid `FmcAliasCsr` cannot be larger than `MAX_CSR_SIZE`, which is the max
                // size of the buffer in `GetIdevCsrResp`
                resp.data[..resp.data_size as usize].copy_from_slice(csr);

                Ok(MailboxResp::GetFmcAliasCsr(resp))
            }
            _ => Err(CaliptraError::RUNTIME_INTERNAL),
        }
    }
}
