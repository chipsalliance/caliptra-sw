/*++

Licensed under the Apache-2.0 license.

File Name:

    tagging.rs

Abstract:

    File contains mailbox commands dealing with tagging.

--*/

use crate::{mutrefbytes, Drivers};
use caliptra_cfi_derive_git::cfi_impl_fn;
use caliptra_common::mailbox_api::{
    GetTaggedTciReq, GetTaggedTciResp, MailboxRespHeader, TagTciReq,
};
use caliptra_error::{CaliptraError, CaliptraResult};
use dpe::{context::ContextHandle, U8Bool, MAX_HANDLES};
use zerocopy::FromBytes;

pub struct TagTciCmd;
impl TagTciCmd {
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    #[inline(never)]
    pub(crate) fn execute(drivers: &mut Drivers, cmd_args: &[u8]) -> CaliptraResult<usize> {
        let cmd = TagTciReq::ref_from_bytes(cmd_args)
            .map_err(|_| CaliptraError::RUNTIME_INSUFFICIENT_MEMORY)?;
        let pdata_mut = drivers.persistent_data.get_mut();
        let dpe = &mut pdata_mut.fw.dpe.state;
        let context_has_tag = &mut pdata_mut.fw.dpe.context_has_tag;
        let context_tags = &mut pdata_mut.fw.dpe.context_tags;

        // Make sure the tag isn't used by any other contexts.
        if (0..MAX_HANDLES).any(|i| {
            i < context_has_tag.len()
                && i < context_tags.len()
                && context_has_tag[i].get()
                && context_tags[i] == cmd.tag
        }) {
            return Err(CaliptraError::RUNTIME_DUPLICATE_TAG);
        }

        let locality = drivers.mbox.id();
        let idx = dpe
            .get_active_context_pos(&ContextHandle(cmd.handle), locality)
            .map_err(|_| CaliptraError::RUNTIME_TAGGING_FAILURE)?;

        // Make sure the context doesn't already have a tag
        if context_has_tag[idx].get() {
            return Err(CaliptraError::RUNTIME_CONTEXT_ALREADY_TAGGED);
        }

        context_has_tag[idx] = U8Bool::new(true);
        context_tags[idx] = cmd.tag;

        Ok(0)
    }
}

pub struct GetTaggedTciCmd;
impl GetTaggedTciCmd {
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    #[inline(never)]
    pub(crate) fn execute(
        drivers: &Drivers,
        cmd_args: &[u8],
        resp: &mut [u8],
    ) -> CaliptraResult<usize> {
        let cmd = GetTaggedTciReq::ref_from_bytes(cmd_args)
            .map_err(|_| CaliptraError::RUNTIME_INSUFFICIENT_MEMORY)?;
        let persistent_data = drivers.persistent_data.get();
        let context_has_tag = &persistent_data.fw.dpe.context_has_tag;
        let context_tags = &persistent_data.fw.dpe.context_tags;
        let idx = (0..MAX_HANDLES)
            .find(|i| {
                *i < context_has_tag.len()
                    && *i < context_tags.len()
                    && context_has_tag[*i].get()
                    && context_tags[*i] == cmd.tag
            })
            .ok_or(CaliptraError::RUNTIME_TAGGING_FAILURE)?;
        if idx >= persistent_data.fw.dpe.state.contexts.len() {
            return Err(CaliptraError::RUNTIME_TAGGING_FAILURE);
        }
        let context = persistent_data.fw.dpe.state.contexts[idx];

        let resp = mutrefbytes::<GetTaggedTciResp>(resp)?;
        resp.hdr = MailboxRespHeader::default();
        resp.tci_cumulative = context.tci.tci_cumulative.0;
        resp.tci_current = context.tci.tci_current.0;
        Ok(core::mem::size_of::<GetTaggedTciResp>())
    }
}
