// Licensed under the Apache-2.0 license

use crate::Drivers;
use caliptra_cfi_derive_git::cfi_impl_fn;
use caliptra_common::cfi_check;
use caliptra_common::mailbox_api::MailboxResp;
use caliptra_error::{CaliptraError, CaliptraResult};

pub struct SignWithExportedMldsaCmd;
impl SignWithExportedMldsaCmd {
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    #[inline(never)]
    pub(crate) fn execute(drivers: &mut Drivers, cmd_args: &[u8]) -> CaliptraResult<MailboxResp> {
        // [TODO][CAP2]
        Err(CaliptraError::RUNTIME_SIGN_WITH_EXPORTED_MLDSA_NOT_SUPPORTED)?
    }
}
