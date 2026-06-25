// Licensed under the Apache-2.0 license

use crate::packet::{copy_from_mbox, copy_to_mbox};
use crate::Drivers;

use caliptra_cfi_derive::cfi_impl_fn;

use caliptra_common::mailbox_api::{GetIdevCsrReq, GetIdevCsrResp};
use caliptra_drivers::IdevIdCsr;
use caliptra_error::{CaliptraError, CaliptraResult};

use zerocopy::{FromZeros, IntoBytes};

pub struct GetIdevCsrCmd;
impl GetIdevCsrCmd {
    #[cfg_attr(feature = "cfi", cfi_impl_fn)]
    #[inline(never)]
    pub(crate) fn execute(drivers: &mut Drivers) -> CaliptraResult<()> {
        copy_from_mbox(drivers, GetIdevCsrReq::new_zeroed().as_mut_bytes())?;
        let csr_persistent_mem = &drivers.persistent_data.get().idevid_csr;

        match csr_persistent_mem.get_csr_len() {
            IdevIdCsr::UNPROVISIONED_CSR => Err(CaliptraError::RUNTIME_GET_IDEV_ID_UNPROVISIONED),
            0 => Err(CaliptraError::RUNTIME_GET_IDEV_ID_UNSUPPORTED_ROM),
            len => {
                let csr = csr_persistent_mem
                    .get()
                    .ok_or(CaliptraError::RUNTIME_GET_IDEV_ID_UNPROVISIONED)?;

                // NOTE: This code will not panic.
                //
                // csr is guranteed to be the same size as `len`, and therefore
                // `resp.data_size` by the `IDevIDCsr::get` API.
                //
                // A valid `IDevIDCsr` cannot be larger than `MAX_IDEVID_CSR_SIZE`, which is the max
                // size of the buffer in `GetIdevIdCsrResp`
                let mut resp = GetIdevCsrResp::new_zeroed();
                resp.data_size = len;
                resp.data[..len as usize].copy_from_slice(csr);
                copy_to_mbox(drivers, resp.as_mut_bytes())
            }
        }
    }
}
