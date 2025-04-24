// Licensed under the Apache-2.0 license

use crate::Drivers;
use caliptra_cfi_derive_git::cfi_impl_fn;
use caliptra_common::mailbox_api::MailboxResp;
use caliptra_error::{CaliptraError, CaliptraResult};

#[allow(dead_code)]
pub struct SignWithExportedMldsaCmd;

impl SignWithExportedMldsaCmd {
    #[allow(dead_code)]
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    #[inline(never)]
    pub(crate) fn execute(_drivers: &mut Drivers, _cmd_args: &[u8]) -> CaliptraResult<MailboxResp> {
        // [TODO][CAP2]
        Err(CaliptraError::RUNTIME_SIGN_WITH_EXPORTED_MLDSA_NOT_SUPPORTED)?
    }
}
