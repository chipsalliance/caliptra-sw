// Licensed under the Apache-2.0 license

use crate::{mutrefbytes, Drivers};

use caliptra_cfi_derive::cfi_impl_fn;
use caliptra_common::mailbox_api::{GetIdevCsrResp, MailboxRespHeader, ResponseVarSize};
use caliptra_error::{CaliptraError, CaliptraResult};

use caliptra_drivers::{Ecc384IdevIdCsr, Mldsa87IdevIdCsr};

pub struct GetIdevCsrCmd;
impl GetIdevCsrCmd {
    #[cfg_attr(feature = "cfi", cfi_impl_fn)]
    #[inline(never)]
    pub(crate) fn execute(drivers: &mut Drivers, resp: &mut [u8]) -> CaliptraResult<usize> {
        let csr_persistent_mem = &drivers.persistent_data.get().rom.idevid_csr_envelop.ecc_csr;

        match csr_persistent_mem.get_csr_len() {
            Ecc384IdevIdCsr::UNPROVISIONED_CSR => {
                Err(CaliptraError::RUNTIME_GET_IDEV_ID_UNPROVISIONED)
            }
            0 => Err(CaliptraError::RUNTIME_GET_IDEV_ID_UNSUPPORTED_ROM),
            len => {
                let csr = csr_persistent_mem
                    .get()
                    .ok_or(CaliptraError::RUNTIME_GET_IDEV_ID_UNPROVISIONED)?;

                let resp = mutrefbytes::<GetIdevCsrResp>(resp)?;
                resp.hdr = MailboxRespHeader::default();
                resp.data_size = len;
                // NOTE: This code will not panic.
                //
                // csr is guranteed to be the same size as `len`, and therefore
                // `resp.data_size` by the `IDevIDCsr::get` API.
                //
                // A valid `IDevIDCsr` cannot be larger than `ECC384_MAX_IDEVID_CSR_SIZE`, which is less
                // than the the max size of the buffer in `GetIdevCsrResp`
                resp.data[..resp.data_size as usize].copy_from_slice(csr);

                Ok(resp.partial_len()?)
            }
        }
    }
}

pub struct GetIdevMldsaCsrCmd;
impl GetIdevMldsaCsrCmd {
    #[cfg_attr(feature = "cfi", cfi_impl_fn)]
    #[inline(never)]
    pub(crate) fn execute(drivers: &mut Drivers, resp: &mut [u8]) -> CaliptraResult<usize> {
        let csr_persistent_mem = &drivers
            .persistent_data
            .get()
            .rom
            .idevid_csr_envelop
            .mldsa_csr;

        match csr_persistent_mem.get_csr_len() {
            Mldsa87IdevIdCsr::UNPROVISIONED_CSR => {
                Err(CaliptraError::RUNTIME_GET_IDEV_ID_UNPROVISIONED)
            }
            0 => Err(CaliptraError::RUNTIME_GET_IDEV_ID_UNSUPPORTED_ROM),
            len => {
                let csr = csr_persistent_mem
                    .get()
                    .ok_or(CaliptraError::RUNTIME_GET_IDEV_ID_UNPROVISIONED)?;

                let resp = mutrefbytes::<GetIdevCsrResp>(resp)?;
                resp.hdr = MailboxRespHeader::default();
                resp.data_size = len;
                // NOTE: This code will not panic.
                //
                // csr is guranteed to be the same size as `len`, and therefore
                // `resp.data_size` by the `IDevIDCsr::get` API.
                //
                // A valid `IDevIDCsr` cannot be larger than `MLDSA87_MAX_CSR_SIZE`, which is less
                // than the the max size of the buffer in `GetIdevCsrResp`
                resp.data[..resp.data_size as usize].copy_from_slice(csr);

                Ok(resp.partial_len()?)
            }
        }
    }
}
