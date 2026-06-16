/*++

Licensed under the Apache-2.0 license.

File Name:

    invoke_dpe.rs

Abstract:

    File contains InvokeDpe mailbox command.

--*/

use crate::{ec_dpe_env, mldsa_dpe_env, Drivers, PauserPrivileges};
use arrayvec::ArrayVec;
use caliptra_api::mailbox::{
    AxiResponseInfo, InvokeDpeMldsa87Flags, InvokeDpeMldsa87Req, MailboxReqHeader,
    MailboxRespHeader,
};
#[cfg(feature = "cfi")]
use caliptra_cfi_derive::cfi_impl_fn;
use caliptra_common::{
    checksum::verify_checksum,
    mailbox_api::{InvokeDpeReq, InvokeDpeResp},
};
use caliptra_dpe::{
    commands::{CertifyKeyCommand, Command, CommandExecution, InitCtxCmd},
    context::ContextState,
    response::{DpeErrorCode, ResponseHdr},
    DpeInstance, DpeProfile, U8Bool, MAX_HANDLES,
};
use caliptra_dpe_platform::MAX_OTHER_NAME_SIZE;
use caliptra_drivers::{okmutref, CaliptraError, CaliptraResult};
use core::mem::{size_of, size_of_val};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum CaliptraDpeProfile {
    Ecc384,
    Mldsa87,
}

impl From<CaliptraDpeProfile> for DpeProfile {
    fn from(profile: CaliptraDpeProfile) -> Self {
        match profile {
            CaliptraDpeProfile::Ecc384 => DpeProfile::P384Sha384,
            CaliptraDpeProfile::Mldsa87 => DpeProfile::Mldsa87,
        }
    }
}
pub struct InvokeDpeCmd;
impl InvokeDpeCmd {
    fn copy_from_mbox(drivers: &mut Drivers, staging_words: &mut [u32]) -> CaliptraResult<usize> {
        let mbox = &mut drivers.mbox;
        let cmd = mbox.cmd();
        let dlen = mbox.dlen() as usize;
        let dlen_words = mbox.dlen_words() as usize;

        if dlen_words > staging_words.len() {
            return Err(CaliptraError::RUNTIME_INSUFFICIENT_MEMORY);
        }
        if dlen < size_of::<MailboxReqHeader>() {
            return Err(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS);
        }

        mbox.copy_from_mbox(
            staging_words
                .get_mut(..dlen_words)
                .ok_or(CaliptraError::RUNTIME_INSUFFICIENT_MEMORY)?,
        );

        let staging_bytes = staging_words.as_bytes();
        let payload = staging_bytes
            .get(..dlen)
            .ok_or(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;
        let req_hdr = MailboxReqHeader::ref_from_bytes(
            payload
                .get(..size_of::<MailboxReqHeader>())
                .ok_or(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?,
        )
        .map_err(|_| CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;
        let checksum_data = payload
            .get(size_of_val(&req_hdr.chksum)..)
            .ok_or(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;

        if !verify_checksum(req_hdr.chksum, u32::from(cmd), checksum_data) {
            return Err(CaliptraError::RUNTIME_INVALID_CHECKSUM);
        }

        Ok(dlen)
    }

    #[cfg_attr(feature = "cfi", cfi_impl_fn)]
    #[inline(never)]
    pub(crate) fn execute_ecc384(
        drivers: &mut Drivers,
        mbox_resp: &mut [u8],
    ) -> CaliptraResult<usize> {
        // The mailbox SRAM has to be accessed in word alignment, copying the command locally to
        // avoid unaligned accesses.
        let mut staging_buffer_buf = [0u32; size_of::<InvokeDpeReq>() / 4];
        let dlen = Self::copy_from_mbox(drivers, &mut staging_buffer_buf)?;
        let staging_buffer = staging_buffer_buf
            .as_bytes()
            .get(..dlen)
            .ok_or(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;

        // Parse the header to get the DPE command size and buffer
        let (cmd, dpe_cmd_buf) = InvokeDpeEcc384Header::ref_from_prefix(staging_buffer)
            .map_err(|_| CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;
        let dpe_cmd_buf = dpe_cmd_buf
            .get(..cmd.data_size as usize)
            .ok_or(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;

        Self::execute(drivers, dpe_cmd_buf, mbox_resp, CaliptraDpeProfile::Ecc384)
    }

    #[cfg_attr(feature = "cfi", cfi_impl_fn)]
    #[inline(never)]
    pub(crate) fn execute_mldsa87(
        drivers: &mut Drivers,
        mbox_resp: &mut [u8],
    ) -> CaliptraResult<usize> {
        // The mailbox SRAM has to be accessed in word alignment, copying the command locally to
        // avoid unaligned accesses.
        let mut staging_buffer_buf = [0u32; size_of::<InvokeDpeMldsa87Req>() / 4];
        let dlen = Self::copy_from_mbox(drivers, &mut staging_buffer_buf)?;
        let staging_buffer = staging_buffer_buf
            .as_bytes()
            .get(..dlen)
            .ok_or(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;

        // Parse the header to get the DPE command size and buffer
        let (cmd, dpe_cmd_buf) = InvokeDpeMldsa87Header::ref_from_prefix(staging_buffer)
            .map_err(|_| CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;
        let dpe_cmd_buf = dpe_cmd_buf
            .get(..cmd.data_size as usize)
            .ok_or(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;

        Self::execute(drivers, dpe_cmd_buf, mbox_resp, CaliptraDpeProfile::Mldsa87)
    }

    #[cfg_attr(feature = "cfi", cfi_impl_fn)]
    #[inline(never)]
    fn execute(
        drivers: &mut Drivers,
        cmd_args: &[u8],
        mbox_resp: &mut [u8],
        profile: CaliptraDpeProfile,
    ) -> CaliptraResult<usize> {
        let caller_privilege_level = drivers.caller_privilege_level();

        let command = &Command::deserialize(profile.into(), cmd_args)
            .map_err(|_| CaliptraError::RUNTIME_DPE_COMMAND_DESERIALIZATION_FAILED)?;

        // Determine the target privilege level of a new context then check if we exceed thresholds
        let new_context_privilege_level = match command {
            Command::DeriveContext(cmd) if cmd.flags.changes_locality() => {
                drivers.privilege_level_from_locality(cmd.target_locality)
            }
            _ => caller_privilege_level,
        };
        let dpe_context_threshold_err =
            drivers.is_dpe_context_threshold_exceeded(new_context_privilege_level);

        let pdata = drivers.persistent_data.get_mut();
        let pl0_pauser = pdata.manifest1.header.pl0_pauser;

        // Check if command can be executed
        match command {
            Command::InitCtx(cmd) => {
                // InitCtx can only create new contexts if they are simulation contexts.
                if InitCtxCmd::flag_is_simulation(cmd) {
                    dpe_context_threshold_err?;
                }
            }
            Command::DeriveContext(cmd) => {
                let flags = cmd.flags;
                // If the recursive flag is not set, DeriveContext will generate a new context.
                // If recursive _is_ set, it will extend the existing one, which will not count
                // against the context threshold.
                if !flags.is_recursive() {
                    // Takes target locality into consideration if applicable. See above
                    dpe_context_threshold_err?;
                }
                if flags.changes_locality()
                    && cmd.target_locality == pl0_pauser
                    && caller_privilege_level != PauserPrivileges::PL0
                {
                    return Err(CaliptraError::RUNTIME_INCORRECT_PAUSER_PRIVILEGE_LEVEL);
                }

                if flags.exports_cdi() && caller_privilege_level != PauserPrivileges::PL0 {
                    return Err(CaliptraError::RUNTIME_INCORRECT_PAUSER_PRIVILEGE_LEVEL);
                }
            }
            Command::CertifyKey(cmd) => {
                // PL1 cannot request X509
                if cmd.format() == CertifyKeyCommand::FORMAT_X509
                    && caller_privilege_level != PauserPrivileges::PL0
                {
                    return Err(CaliptraError::RUNTIME_INCORRECT_PAUSER_PRIVILEGE_LEVEL);
                }
            }
            _ => (),
        };

        let ueid = Some(drivers.soc_ifc.fuse_bank().ueid());
        let (invoke_resp, data) = InvokeDpeRespHeader::mut_from_prefix(mbox_resp)
            .map_err(|_| CaliptraError::RUNTIME_INSUFFICIENT_MEMORY)?;
        if data.len() < core::mem::size_of::<ResponseHdr>() {
            return Err(CaliptraError::RUNTIME_INSUFFICIENT_MEMORY);
        }
        let result = invoke_dpe_cmd(profile, drivers, command, None, ueid, None, data);

        if let Command::DestroyCtx(_) = command {
            // clear tags for destroyed contexts
            let pdata = drivers.persistent_data.get_mut();
            let state = &mut pdata.state;
            let context_has_tag = &mut pdata.context_has_tag;
            let context_tags = &mut pdata.context_tags;
            Self::clear_tags_for_inactive_contexts(state, context_has_tag, context_tags);
        }

        // If DPE command failed, populate header with error code, but
        // don't fail the mailbox command.
        match result {
            Ok(data_size) => {
                invoke_resp.data_size = data_size as u32;
            }
            Err(ref e) => {
                // If there is extended error info, populate CPTRA_FW_EXTENDED_ERROR_INFO
                if let Some(ext_err) = e.get_error_detail() {
                    drivers.soc_ifc.set_fw_extended_error(ext_err);
                }
                let r = ResponseHdr::new(profile.into(), *e);
                data[..core::mem::size_of::<ResponseHdr>()].copy_from_slice(r.as_bytes());
                invoke_resp.data_size = r.as_bytes().len() as u32;
            }
        };

        Ok(size_of::<InvokeDpeResp>() - InvokeDpeResp::DATA_MAX_SIZE
            + invoke_resp.data_size as usize)
    }

    /// Remove context tags for all inactive DPE contexts
    ///
    /// # Arguments
    ///
    /// * `dpe` - DPE state
    /// * `context_has_tag` - Bool slice indicating if a DPE context has a tag
    /// * `context_tags` - Tags for each DPE context
    #[cfg_attr(feature = "cfi", cfi_impl_fn)]
    pub fn clear_tags_for_inactive_contexts(
        dpe: &mut caliptra_dpe::State,
        context_has_tag: &mut [U8Bool; MAX_HANDLES],
        context_tags: &mut [u32; MAX_HANDLES],
    ) {
        (0..MAX_HANDLES).for_each(|i| {
            if i < dpe.contexts.len()
                && i < context_has_tag.len()
                && i < context_tags.len()
                && dpe.contexts[i].state == ContextState::Inactive
            {
                context_has_tag[i] = U8Bool::new(false);
                context_tags[i] = 0;
            }
        });
    }
}

pub fn invoke_dpe_cmd(
    profile: CaliptraDpeProfile,
    drivers: &mut Drivers,
    command: &Command,
    dmtf_device_info: Option<ArrayVec<u8, { MAX_OTHER_NAME_SIZE }>>,
    ueid: Option<[u8; 17]>,
    locality: Option<u32>,
    out: &mut [u8],
) -> Result<usize, DpeErrorCode> {
    let locality = if let Some(locality) = locality {
        locality
    } else {
        drivers.mbox.id()
    };
    match profile {
        CaliptraDpeProfile::Ecc384 => {
            invoke_ecc_dpe_cmd(drivers, command, dmtf_device_info, ueid, locality, out)
        }
        CaliptraDpeProfile::Mldsa87 => {
            invoke_mldsa_dpe_cmd(drivers, command, dmtf_device_info, ueid, locality, out)
        }
    }
}

#[inline(never)]
fn invoke_ecc_dpe_cmd(
    drivers: &mut Drivers,
    command: &Command,
    dmtf_device_info: Option<ArrayVec<u8, { MAX_OTHER_NAME_SIZE }>>,
    ueid: Option<[u8; 17]>,
    locality: u32,
    out: &mut [u8],
) -> Result<usize, DpeErrorCode> {
    let mut env = ec_dpe_env(drivers, dmtf_device_info, ueid);
    let env = okmutref(&mut env).map_err(|_| DpeErrorCode::InternalError)?;
    let dpe = &mut DpeInstance::initialized(DpeProfile::P384Sha384);
    command.execute_serialized(dpe, env, locality, out)
}

#[inline(never)]
fn invoke_mldsa_dpe_cmd(
    drivers: &mut Drivers,
    command: &Command,
    dmtf_device_info: Option<ArrayVec<u8, { MAX_OTHER_NAME_SIZE }>>,
    ueid: Option<[u8; 17]>,
    locality: u32,
    out: &mut [u8],
) -> Result<usize, DpeErrorCode> {
    let mut env = mldsa_dpe_env(drivers, dmtf_device_info, ueid);
    let env = okmutref(&mut env).map_err(|_| DpeErrorCode::InternalError)?;
    let dpe = &mut DpeInstance::initialized(DpeProfile::Mldsa87);
    command.execute_serialized(dpe, env, locality, out)
}

#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, Immutable, KnownLayout, PartialEq, Eq)]
struct InvokeDpeEcc384Header {
    pub hdr: MailboxReqHeader,
    pub data_size: u32,
}

const _: () = assert!(
    size_of::<InvokeDpeEcc384Header>() == size_of::<InvokeDpeReq>() - InvokeDpeReq::DATA_MAX_SIZE
);

#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, Immutable, KnownLayout, PartialEq, Eq)]
struct InvokeDpeMldsa87Header {
    pub hdr: MailboxReqHeader,
    pub flags: InvokeDpeMldsa87Flags,
    pub axi_response: AxiResponseInfo,
    pub data_size: u32,
}

const _: () = assert!(
    size_of::<InvokeDpeMldsa87Header>()
        == size_of::<InvokeDpeMldsa87Req>() - InvokeDpeMldsa87Req::DATA_MAX_SIZE
);

#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, Immutable, KnownLayout, PartialEq, Eq)]
pub struct InvokeDpeRespHeader {
    pub hdr: MailboxRespHeader,
    pub data_size: u32,
}

const _: () = assert!(
    size_of::<InvokeDpeRespHeader>() == size_of::<InvokeDpeResp>() - InvokeDpeResp::DATA_MAX_SIZE
);
