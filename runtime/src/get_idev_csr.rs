// Licensed under the Apache-2.0 license

use crate::Drivers;

use caliptra_cfi_derive_git::cfi_impl_fn;
use caliptra_cfi_lib_git::cfi_launder;

use caliptra_common::{
    cprintln,
    mailbox_api::{GetIdevCsrReq, GetIdevCsrResp, MailboxResp, MailboxRespHeader},
};
use caliptra_error::{CaliptraError, CaliptraResult};

use caliptra_drivers::IdevIdCsr;

use zerocopy::{FromBytes, IntoBytes};

pub struct GetIdevCsrCmd;
impl GetIdevCsrCmd {
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    #[inline(never)]
    pub(crate) fn execute(drivers: &mut Drivers, cmd_args: &[u8]) -> CaliptraResult<MailboxResp> {
        let cmd = GetIdevCsrReq::ref_from_bytes(cmd_args)
            .map_err(|_| CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;
        let csr_persistent_mem = &drivers.persistent_data.get().idevid_csr;

        match csr_persistent_mem.get_csr_len() {
            IdevIdCsr::UNPROVISIONED_CSR => Err(CaliptraError::RUNTIME_GET_IDEV_ID_UNPROVISIONED),
            0 => Err(CaliptraError::RUNTIME_GET_IDEV_ID_UNSUPPORTED_ROM),
            len => {
                let csr = csr_persistent_mem
                    .get()
                    .ok_or(CaliptraError::RUNTIME_GET_IDEV_ID_UNPROVISIONED)?;

                let mut resp = GetIdevCsrResp {
                    data_size: len,
                    ..Default::default()
                };
                // NOTE: This code will not panic.
                //
                // csr is guranteed to be the same size as `len`, and therefore
                // `resp.data_size` by the `IDevIDCsr::get` API.
                //
                // A valid `IDevIDCsr` cannot be larger than `MAX_CSR_SIZE`, which is the max
                // size of the buffer in `GetIdevIdCsrResp`
                resp.data[..resp.data_size as usize].copy_from_slice(csr);

                Ok(MailboxResp::GetIdevCsr(resp))
            }
        }
    }
}
