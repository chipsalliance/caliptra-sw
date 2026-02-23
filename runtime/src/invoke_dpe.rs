/*++

Licensed under the Apache-2.0 license.

File Name:

    invoke_dpe.rs

Abstract:

    File contains InvokeDpe mailbox command.

--*/

use crate::{ec_dpe_env, mldsa_dpe_env, mutrefbytes, AxiAddr, Drivers, PauserPrivileges};
use arrayvec::ArrayVec;
use caliptra_api::mailbox::{
    populate_checksum, AxiResponseInfo, InvokeDpeMldsa87Flags, InvokeDpeMldsa87Req,
    MailboxReqHeader, MailboxRespHeader,
};
use caliptra_cfi_derive::cfi_impl_fn;
use caliptra_common::mailbox_api::{InvokeDpeReq, InvokeDpeResp, ResponseVarSize};
use caliptra_drivers::{okmutref, CaliptraError, CaliptraResult};
use dpe::{
    commands::{CertifyKeyCommand, Command, CommandExecution, InitCtxCmd},
    context::ContextState,
    response::{DpeErrorCode, ResponseHdr},
    DpeInstance, DpeProfile, U8Bool, MAX_HANDLES,
};
use platform::MAX_OTHER_NAME_SIZE;
use ufmt::derive::uDebug;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

#[derive(uDebug, Debug, Copy, Clone)]
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
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    #[inline(never)]
    pub(crate) fn execute_ecc384(
        drivers: &mut Drivers,
        cmd_args: &[u8],
        mbox_resp: &mut [u8],
    ) -> CaliptraResult<usize> {
        // The mailbox SRAM has to be accessed in word alignment, copying the command locally to
        // avoid unaligned accesses.
        let mut staging_buffer = [0u8; size_of::<InvokeDpeReq>()];
        if cmd_args.len() > staging_buffer.len() {
            return Err(CaliptraError::RUNTIME_INSUFFICIENT_MEMORY);
        }
        staging_buffer[..cmd_args.len()].copy_from_slice(cmd_args);

        // Parse the header to get the DPE command size and buffer
        let (cmd, dpe_cmd_buf) = InvokeDpeEcc384Header::ref_from_prefix(&staging_buffer)
            .map_err(|_| CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;
        let dpe_cmd_buf = dpe_cmd_buf
            .get(..cmd.data_size as usize)
            .ok_or(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;

        Self::execute(drivers, dpe_cmd_buf, mbox_resp, CaliptraDpeProfile::Ecc384)
    }

    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    #[inline(never)]
    pub(crate) fn execute_mldsa87(
        drivers: &mut Drivers,
        cmd_args: &[u8],
        mbox_resp: &mut [u8],
    ) -> CaliptraResult<usize> {
        // The mailbox SRAM has to be accessed in word alignment, copying the command locally to
        // avoid unaligned accesses.
        let mut staging_buffer = [0u8; size_of::<InvokeDpeMldsa87Req>()];
        if cmd_args.len() > staging_buffer.len() {
            return Err(CaliptraError::RUNTIME_INSUFFICIENT_MEMORY);
        }
        staging_buffer[..cmd_args.len()].copy_from_slice(cmd_args);

        // Parse the header to get the DPE command size and buffer
        let (cmd, dpe_cmd_buf) = InvokeDpeMldsa87Header::ref_from_prefix(&staging_buffer)
            .map_err(|_| CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;
        let dpe_cmd_buf = dpe_cmd_buf
            .get(..cmd.data_size as usize)
            .ok_or(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;

        // External responses can only be done in subsystem mode
        if cmd.flags.external_axi_response() && !drivers.soc_ifc.subsystem_mode() {
            return Err(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS);
        }

        // Execute the DPE command and get the length of the response that was written
        let len = Self::execute(drivers, dpe_cmd_buf, mbox_resp, CaliptraDpeProfile::Mldsa87)?;

        // We are done if the response is going over the mailbox
        let respond_to_mailbox = !cmd.flags.external_axi_response();
        if respond_to_mailbox {
            return Ok(len);
        }

        // Populate the checksum so the full response can be checked at the destination
        // Make sure there is at least enough space for the response header
        let len = usize::max(len, size_of::<MailboxRespHeader>());
        populate_checksum(
            mbox_resp
                .get_mut(..len)
                .ok_or(CaliptraError::RUNTIME_INSUFFICIENT_MEMORY)?,
        );

        // Get the number of words to send by rounding up to nearest word
        let num_words = len.next_multiple_of(4) / 4;
        let len = num_words * 4;
        if len > cmd.axi_response.max_size as usize {
            return Err(CaliptraError::RUNTIME_INSUFFICIENT_MEMORY);
        }

        // Get the buffer that will be sent over DMA. The DMA only supports sending words so we need
        // to convert the response buffer to a &[u32].
        let buffer = mbox_resp
            .get(..len)
            .ok_or(CaliptraError::RUNTIME_INSUFFICIENT_MEMORY)?;
        let buffer: &[u32] =
            FromBytes::ref_from_bytes(buffer).map_err(|_| CaliptraError::ADDRESS_MISALIGNED)?;

        // Send the response over DMA to the specified AXI address
        let axi_addr = AxiAddr {
            lo: cmd.axi_response.addr_lo,
            hi: cmd.axi_response.addr_hi,
        };
        drivers.dma.write_buffer(axi_addr, buffer);

        // Response is sent over DMA instead of the mailbox, so return 0 length
        Ok(0)
    }

    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
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
        let pl0_pauser = pdata.rom.manifest1.header.pl0_pauser;

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
        let invoke_resp = mutrefbytes::<InvokeDpeResp>(mbox_resp)?;
        let result = invoke_dpe_cmd(profile, drivers, command, None, ueid, &mut invoke_resp.data);

        if let Command::DestroyCtx(_) = command {
            // clear tags for destroyed contexts
            let pdata = drivers.persistent_data.get_mut();
            let state = &mut pdata.fw.dpe.state;
            let context_has_tag = &mut pdata.fw.dpe.context_has_tag;
            let context_tags = &mut pdata.fw.dpe.context_tags;
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
                invoke_resp.data[..core::mem::size_of::<ResponseHdr>()]
                    .copy_from_slice(r.as_bytes());
                let data_size = r.as_bytes().len();
                invoke_resp.data_size = data_size as u32;
            }
        };

        invoke_resp.partial_len()
    }

    /// Remove context tags for all inactive DPE contexts
    ///
    /// # Arguments
    ///
    /// * `dpe` - DPE state
    /// * `context_has_tag` - Bool slice indicating if a DPE context has a tag
    /// * `context_tags` - Tags for each DPE context
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    pub fn clear_tags_for_inactive_contexts(
        dpe: &mut dpe::State,
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
    out: &mut [u8],
) -> Result<usize, DpeErrorCode> {
    let locality = drivers.mbox.id();
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
