// Licensed under the Apache-2.0 license

use crate::Drivers;

#[cfg(feature = "cfi")]
use caliptra_cfi_derive::cfi_impl_fn;
#[cfg(feature = "cfi")]
use caliptra_cfi_lib::{cfi_assert, cfi_assert_bool};

use caliptra_common::mailbox_api::{RevokeExportedCdiHandleReq, RevokeExportedCdiHandleResp};
use caliptra_drivers::ExportedCdiEntry;
use caliptra_error::{CaliptraError, CaliptraResult};

use constant_time_eq::constant_time_eq;
use dpe::U8Bool;
use zerocopy::{FromZeros, IntoBytes};
use zeroize::Zeroize;

pub struct RevokeExportedCdiHandleCmd;
impl RevokeExportedCdiHandleCmd {
    #[cfg_attr(feature = "cfi", cfi_impl_fn)]
    #[inline(never)]
    pub(crate) fn execute(drivers: &mut Drivers) -> CaliptraResult<()> {
        let mut cmd = RevokeExportedCdiHandleReq::new_zeroed();
        crate::packet::copy_from_mbox(drivers, cmd.as_mut_bytes())?;

        // REVOKE_EXPORTED_CDI_HANDLE MUST only be called from PL0
        drivers.ensure_pl0()?;

        for slot in drivers
            .persistent_data
            .get_mut()
            .exported_cdi_slots
            .entries
            .iter_mut()
        {
            match slot {
                ExportedCdiEntry {
                    key: _,
                    handle,
                    active,
                } if constant_time_eq(handle, &cmd.exported_cdi_handle) && active.get() => {
                    #[cfg(feature = "cfi")]
                    cfi_assert!(constant_time_eq(handle, &cmd.exported_cdi_handle));

                    // Setting to false is redundant with zeroize but included for clarity.
                    *active = U8Bool::new(false);
                    slot.zeroize();

                    let mut resp = RevokeExportedCdiHandleResp::default();
                    return crate::packet::copy_to_mbox(drivers, resp.as_mut_bytes());
                }
                _ => (),
            }
        }

        // An exported CDI handle may instead refer to an ML-DSA exported CDI,
        // which is held in its own single-entry slot in persistent data.
        #[cfg(feature = "mldsa_attestation")]
        {
            let slot = &mut drivers.persistent_data.get_mut().mldsa_exported_cdi_slots;
            if constant_time_eq(&slot.handle, &cmd.exported_cdi_handle) && slot.active.get() {
                #[cfg(feature = "cfi")]
                cfi_assert!(constant_time_eq(&slot.handle, &cmd.exported_cdi_handle));

                // Setting to false is redundant with zeroize but included for clarity.
                slot.active = U8Bool::new(false);
                slot.zeroize();

                let mut resp = RevokeExportedCdiHandleResp::default();
                return crate::packet::copy_to_mbox(drivers, resp.as_mut_bytes());
            }
        }

        Err(CaliptraError::RUNTIME_REVOKE_EXPORTED_CDI_HANDLE_NOT_FOUND)
    }
}
