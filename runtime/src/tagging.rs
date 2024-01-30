/*++

Licensed under the Apache-2.0 license.

File Name:

    tagging.rs

Abstract:

    File contains mailbox commands dealing with tagging.

--*/

use caliptra_cfi_derive::cfi_impl_fn;
use caliptra_common::mailbox_api::{
    GetTaggedTciReq, GetTaggedTciResp, MailboxResp, MailboxRespHeader, TagTciReq,
};
use caliptra_drivers::cprintln;
use caliptra_error::{CaliptraError, CaliptraResult};
use dpe::{
    context::{ContextHandle, ContextState},
    dpe_instance::DpeEnv,
    U8Bool, MAX_HANDLES,
};
use zerocopy::FromBytes;

use crate::{dpe_crypto::DpeCrypto, CptraDpeTypes, DpePlatform, Drivers};

pub struct TagTciCmd;
impl TagTciCmd {
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    pub(crate) fn execute(drivers: &mut Drivers, cmd_args: &[u8]) -> CaliptraResult<MailboxResp> {
        if let Some(cmd) = TagTciReq::read_from(cmd_args) {
            let pdata_mut = drivers.persistent_data.get_mut();
            let mut dpe = &mut pdata_mut.dpe;
            let mut context_has_tag = &mut pdata_mut.context_has_tag;
            let mut context_tags = &mut pdata_mut.context_tags;

            // Make sure the tag isn't used by any other contexts.
            if (0..MAX_HANDLES).any(|i| {
                i < context_has_tag.len()
                    && i < context_tags.len()
                    && context_has_tag[i].get()
                    && context_tags[i] == cmd.tag
            }) {
                return Err(CaliptraError::RUNTIME_DUPLICATE_TAG);
            }

            let locality = drivers.mbox.user();
            let idx = dpe
                .get_active_context_pos(&ContextHandle(cmd.handle), locality)
                .map_err(|_| CaliptraError::RUNTIME_TAGGING_FAILURE)?;

            // Make sure the context doesn't already have a tag
            if context_has_tag[idx].get() {
                return Err(CaliptraError::RUNTIME_CONTEXT_ALREADY_TAGGED);
            }

            context_has_tag[idx] = U8Bool::new(true);
            context_tags[idx] = cmd.tag;

            Ok(MailboxResp::default())
        } else {
            Err(CaliptraError::RUNTIME_INSUFFICIENT_MEMORY)
        }
    }
}

pub struct GetTaggedTciCmd;
impl GetTaggedTciCmd {
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    #[inline(never)]
    pub(crate) fn execute(drivers: &Drivers, cmd_args: &[u8]) -> CaliptraResult<MailboxResp> {
        if let Some(cmd) = GetTaggedTciReq::read_from(cmd_args) {
            let persistent_data = drivers.persistent_data.get();
            let idx = (0..MAX_HANDLES)
                .find(|i| {
                    *i < persistent_data.context_has_tag.len()
                        && *i < persistent_data.context_tags.len()
                        && persistent_data.context_has_tag[*i].get()
                        && persistent_data.context_tags[*i] == cmd.tag
                })
                .ok_or(CaliptraError::RUNTIME_TAGGING_FAILURE)?;
            if idx >= persistent_data.dpe.contexts.len() {
                return Err(CaliptraError::RUNTIME_TAGGING_FAILURE);
            }
            let context = persistent_data.dpe.contexts[idx];

            Ok(MailboxResp::GetTaggedTci(GetTaggedTciResp {
                hdr: MailboxRespHeader::default(),
                tci_cumulative: context.tci.tci_cumulative.0,
                tci_current: context.tci.tci_current.0,
            }))
        } else {
            Err(CaliptraError::RUNTIME_INSUFFICIENT_MEMORY)
        }
    }
}
