// Licensed under the Apache-2.0 license

use crate::{Drivers, PauserPrivileges};

#[cfg(feature = "cfi")]
use caliptra_cfi_derive::cfi_impl_fn;

use caliptra_common::mailbox_api::SignWithExportedMldsaReq;
use caliptra_error::{CaliptraError, CaliptraResult};

use zerocopy::{FromZeros, IntoBytes};

pub struct SignWithExportedMldsaCmd;
impl SignWithExportedMldsaCmd {
    /// Sign a message with an ML-DSA-87 key pair derived from a previously
    /// exported CDI handle.
    ///
    /// The exported CDI is looked up in `mldsa_exported_cdi_slots`; the ML-DSA-87
    /// seed is re-derived from the stored CDI, and the request is signed either
    /// from a raw message (`SIGN_MODE_DATA`) or a caller-supplied external mu
    /// (`SIGN_MODE_EXTERNAL_MU`). The derived public key and signature are
    /// returned so the caller can verify the result.
    #[cfg_attr(feature = "cfi", cfi_impl_fn)]
    #[inline(never)]
    pub(crate) fn execute(drivers: &mut Drivers) -> CaliptraResult<()> {
        let mut cmd = SignWithExportedMldsaReq::new_zeroed();
        crate::packet::copy_from_mbox(drivers, cmd.as_mut_bytes())?;

        match drivers.caller_privilege_level() {
            // SIGN_WITH_EXPORTED_MLDSA MUST only be called from PL0
            PauserPrivileges::PL0 => (),
            PauserPrivileges::PL1 => {
                return Err(CaliptraError::RUNTIME_INCORRECT_PAUSER_PRIVILEGE_LEVEL);
            }
        }

        // TODO: implement key derivation and signing.
        Err(CaliptraError::RUNTIME_SIGN_WITH_EXPORTED_MLDSA_NOT_SUPPORTED)
    }
}
