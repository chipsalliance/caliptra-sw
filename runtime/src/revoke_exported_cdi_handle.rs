// Licensed under the Apache-2.0 license

use crate::{dpe_crypto::DpeCrypto, Drivers, PauserPrivileges};

#[cfg(not(feature = "no-cfi"))]
use caliptra_cfi_derive_git::cfi_impl_fn;
#[cfg(not(feature = "no-cfi"))]
use caliptra_cfi_lib_git::{cfi_assert, cfi_assert_eq, cfi_launder};

use caliptra_common::mailbox_api::{
    MailboxResp, MailboxRespHeader, RevokeExportedCdiHandleReq, RevokeExportedCdiHandleResp,
};
use caliptra_error::{CaliptraError, CaliptraResult};

use zerocopy::{FromBytes, IntoBytes};

pub struct RevokeExportedCdiHandleCmd;
impl RevokeExportedCdiHandleCmd {
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    #[inline(never)]
    pub(crate) fn execute(drivers: &mut Drivers, cmd_args: &[u8]) -> CaliptraResult<MailboxResp> {
        let cmd = RevokeExportedCdiHandleReq::ref_from_bytes(cmd_args)
            .map_err(|_| CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;

        match drivers.caller_privilege_level() {
            // REVOKE_EXPORTED_CDI_HANDLE MUST only be called from PL0
            PauserPrivileges::PL0 => (),
            PauserPrivileges::PL1 => {
                return Err(CaliptraError::RUNTIME_INCORRECT_PAUSER_PRIVILEGE_LEVEL);
            }
        }

        for slot in drivers.exported_cdi_slots.iter_mut() {
            match slot {
                Some((cdi, handle)) if *handle == cmd.exported_cdi_handle => {
                    #[cfg(not(feature = "no-cfi"))]
                    cfi_assert!(*handle == cmd.exported_cdi_handle);

                    *slot = None;
                    return Ok(MailboxResp::RevokeExportedCdiHandle(
                        RevokeExportedCdiHandleResp::default(),
                    ));
                }
                _ => (),
            }
        }
        Err(CaliptraError::RUNTIME_REVOKE_EXPORTED_CDI_HANDLE_NOT_FOUND)
    }
}
