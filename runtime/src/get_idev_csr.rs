// Licensed under the Apache-2.0 license

use crate::packet::{copy_req_hdr_from_mbox, copy_to_mbox};
use crate::Drivers;

use caliptra_cfi_derive::cfi_mod_fn;

use caliptra_common::mailbox_api::{GetFmcAliasCsrResp, GetIdevCsrResp};
use caliptra_drivers::IdevIdCsr;
use caliptra_error::{CaliptraError, CaliptraResult};

use zerocopy::{FromZeros, IntoBytes};

pub struct GetIdevCsrCmd;
impl GetIdevCsrCmd {
    pub(crate) fn execute(drivers: &mut Drivers) -> CaliptraResult<()> {
        send_csr_resp(drivers, false)
    }
}

#[cfg_attr(feature = "cfi", cfi_mod_fn)]
#[inline(never)]
pub(crate) fn send_csr_resp(drivers: &mut Drivers, is_fmc_alias: bool) -> CaliptraResult<()> {
    copy_req_hdr_from_mbox(drivers)?;
    let pdata = drivers.persistent_data.get();
    let (csr_len, csr, unprovisioned_err, unsupported_err) = if is_fmc_alias {
        (
            pdata.fmc_alias_csr.get_csr_len(),
            pdata.fmc_alias_csr.get(),
            CaliptraError::RUNTIME_GET_FMC_CSR_UNPROVISIONED,
            CaliptraError::RUNTIME_GET_FMC_CSR_UNSUPPORTED_FMC,
        )
    } else {
        (
            pdata.idevid_csr.get_csr_len(),
            pdata.idevid_csr.get(),
            CaliptraError::RUNTIME_GET_IDEV_ID_UNPROVISIONED,
            CaliptraError::RUNTIME_GET_IDEV_ID_UNSUPPORTED_ROM,
        )
    };

    match csr_len {
        IdevIdCsr::UNPROVISIONED_CSR => Err(unprovisioned_err),
        0 => Err(unsupported_err),
        len => {
            let csr = csr.ok_or(unprovisioned_err)?;

            // NOTE: This code will not panic.
            //
            // csr is guaranteed to be the same size as `len`, and therefore
            // `resp.data_size` by the `IDevIDCsr::get` / `FmcAliasCsr::get` API.
            //
            // `GetFmcAliasCsrResp` has the larger 768-byte `data` buffer and an identical
            // header + `data_size` prefix to `GetIdevCsrResp` (512-byte `data` buffer).
            let mut resp = GetFmcAliasCsrResp::new_zeroed();
            resp.data_size = len;
            resp.data
                .get_mut(..csr.len())
                .ok_or(unprovisioned_err)?
                .copy_from_slice(csr);
            let resp_len = if is_fmc_alias {
                core::mem::size_of::<GetFmcAliasCsrResp>()
            } else {
                core::mem::size_of::<GetIdevCsrResp>()
            };
            copy_to_mbox(drivers, &mut resp.as_mut_bytes()[..resp_len])
        }
    }
}
