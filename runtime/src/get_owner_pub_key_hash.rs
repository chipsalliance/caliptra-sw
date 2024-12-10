// Licensed under the Apache-2.0 license

use crate::Drivers;

use caliptra_cfi_derive_git::cfi_impl_fn;
use caliptra_cfi_lib_git::cfi_launder;

use caliptra_common::{
    cprintln,
    mailbox_api::{GetOwnerPubKeyHashReq, GetOwnerPubKeyHashResp, MailboxResp, MailboxRespHeader},
};
use caliptra_error::{CaliptraError, CaliptraResult};

use zerocopy::{AsBytes, FromBytes};

pub struct GetOwnerPubKeyHashCmd;
impl GetOwnerPubKeyHashCmd {
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    #[inline(never)]
    pub(crate) fn execute(drivers: &mut Drivers, cmd_args: &[u8]) -> CaliptraResult<MailboxResp> {
        if let Some(cmd) = GetOwnerPubKeyHashReq::read_from(cmd_args) {
            let mut resp = GetOwnerPubKeyHashResp::default();

            // Copy the pub key hash from the last cold boot from the data vault
            resp.key_hash
                .copy_from_slice(drivers.data_vault.owner_pk_hash().as_bytes());

            Ok(MailboxResp::GetOwnerPubKeyHash(resp))
        } else {
            Err(CaliptraError::RUNTIME_INSUFFICIENT_MEMORY)
        }
    }
}
