/*++

Licensed under the Apache-2.0 license.

File Name:

    certify_key_chunks.rs

Abstract:

    File contains CertifyKeyChunks mailbox command.

--*/

use crate::PauserPrivileges;
use crate::{invoke_dpe::invoke_dpe_cmd, CaliptraDpeProfile, Drivers};
use caliptra_api::mailbox::CertifyKeyChunksRespInfo;
use caliptra_common::mailbox_api::{CertifyKeyChunksReq, CertifyKeyChunksResp};
use caliptra_dpe::commands::{CertifyKeyCommand, CertifyKeyMldsa87Cmd, CertifyKeyP384Cmd, Command};
use caliptra_dpe::response::{CertifyKeyMldsa87Resp, CertifyKeyP384Resp};
use caliptra_error::{CaliptraError, CaliptraResult};
use memoffset::span_of;
use zerocopy::FromBytes;

pub struct CertifyKeyChunksCmd;
impl CertifyKeyChunksCmd {
    #[inline(never)]
    pub(crate) fn execute(
        drivers: &mut Drivers,
        cmd_args: &[u8],
        mbox_resp: &mut [u8],
    ) -> CaliptraResult<usize> {
        let chunk_cmd = CertifyKeyChunksReq::ref_from_bytes(cmd_args)
            .map_err(|_| CaliptraError::RUNTIME_INSUFFICIENT_MEMORY)?;

        let profile = if chunk_cmd.flags.use_mldsa() {
            CaliptraDpeProfile::Mldsa87
        } else {
            CaliptraDpeProfile::Ecc384
        };

        let certify_key_cmd = match profile {
            CaliptraDpeProfile::Ecc384 => CertifyKeyCommand::from(
                CertifyKeyP384Cmd::ref_from_bytes(&chunk_cmd.certify_key_req[..]).or(Err(
                    CaliptraError::RUNTIME_DPE_COMMAND_DESERIALIZATION_FAILED,
                ))?,
            ),
            CaliptraDpeProfile::Mldsa87 => CertifyKeyCommand::from(
                CertifyKeyMldsa87Cmd::ref_from_bytes(&chunk_cmd.certify_key_req[..]).or(Err(
                    CaliptraError::RUNTIME_DPE_COMMAND_DESERIALIZATION_FAILED,
                ))?,
            ),
        };

        // Check if command can be executed
        // PL1 cannot request X509
        let caller_privilege_level = drivers.caller_privilege_level();
        if certify_key_cmd.format() == CertifyKeyCommand::FORMAT_X509
            && caller_privilege_level != PauserPrivileges::PL0
        {
            return Err(CaliptraError::RUNTIME_INCORRECT_PAUSER_PRIVILEGE_LEVEL);
        }

        let (resp_info, certify_key_resp_bytes) =
            CertifyKeyChunksRespInfo::mut_from_prefix(mbox_resp)
                .map_err(|_| CaliptraError::RUNTIME_INSUFFICIENT_MEMORY)?;

        let (min_resp_size, handle_range) = match profile {
            CaliptraDpeProfile::Ecc384 => (
                size_of::<CertifyKeyP384Resp>(),
                span_of!(CertifyKeyP384Resp, new_context_handle..derived_pubkey_x),
            ),
            CaliptraDpeProfile::Mldsa87 => (
                size_of::<CertifyKeyMldsa87Resp>(),
                span_of!(CertifyKeyMldsa87Resp, new_context_handle..pubkey),
            ),
        };

        if certify_key_resp_bytes.len() < min_resp_size {
            return Err(CaliptraError::RUNTIME_INSUFFICIENT_MEMORY);
        }

        // Get the full CertifyKey response
        let dpe_resp_len = invoke_dpe_cmd(
            profile,
            drivers,
            &Command::from(&certify_key_cmd),
            None,
            None,
            None,
            certify_key_resp_bytes,
        )
        .map_err(|e| {
            // If there is extended error info, populate CPTRA_FW_EXTENDED_ERROR_INFO
            if let Some(ext_err) = e.get_error_detail() {
                drivers.soc_ifc.set_fw_extended_error(ext_err);
            }
            CaliptraError::RUNTIME_CERTIFY_KEY_EXTENDED_FAILED
        })?;

        // If the offset is past the end of the response this will make it have nothing in the
        // chunk, but the caller will still get the handle back
        let offset = usize::min(chunk_cmd.offset as usize, dpe_resp_len);

        // Copy the new handle to the response header
        resp_info.context_handle = certify_key_resp_bytes[handle_range].try_into().unwrap();

        // Copy the chunk of the response to the beginning of the response buffer
        let max_chunk_size = CertifyKeyChunksResp::MAX_CHUNK_SIZE;
        let max_chunk_size = if chunk_cmd.max_size > 0 {
            usize::min(max_chunk_size, chunk_cmd.max_size as usize)
        } else {
            max_chunk_size
        };
        let total_remaining = dpe_resp_len.saturating_sub(offset);
        let chunk_len = core::cmp::min(total_remaining, max_chunk_size);
        copy_to_start(certify_key_resp_bytes, offset, chunk_len)?;

        // Fill in the rest of the response info
        resp_info.chunk_len = chunk_len as u32;
        resp_info.remaining = dpe_resp_len
            .saturating_sub(offset)
            .saturating_sub(chunk_len) as u32;

        Ok(core::mem::size_of::<CertifyKeyChunksRespInfo>() + chunk_len)
    }
}

fn copy_to_start(slice: &mut [u8], src_offset: usize, len: usize) -> CaliptraResult<()> {
    let slice_len = slice.len();

    if src_offset > slice_len || len > slice_len {
        return Err(CaliptraError::RUNTIME_INSUFFICIENT_MEMORY);
    }

    let src_end = src_offset
        .checked_add(len)
        .ok_or(CaliptraError::RUNTIME_INSUFFICIENT_MEMORY)?;
    if src_end > slice_len {
        return Err(CaliptraError::RUNTIME_INSUFFICIENT_MEMORY);
    }

    // Copy forwards (left to right) is always safe when copying to the start (dest = 0)
    for i in 0..len {
        let src_idx = src_offset + i;
        let val = *slice
            .get(src_idx)
            .ok_or(CaliptraError::RUNTIME_INSUFFICIENT_MEMORY)?;
        *slice
            .get_mut(i)
            .ok_or(CaliptraError::RUNTIME_INSUFFICIENT_MEMORY)? = val;
    }

    Ok(())
}
