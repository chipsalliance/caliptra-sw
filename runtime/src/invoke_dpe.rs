/*++

Licensed under the Apache-2.0 license.

File Name:

    invoke_dpe.rs

Abstract:

    File contains InvokeDpe mailbox command.

--*/

use caliptra_dpe_response_buffer::{OffsetResponseBuffer, ResponseBuffer};

use crate::{ec_dpe_env, Drivers, MboxResponseWriter, PauserPrivileges};
use arrayvec::ArrayVec;
use caliptra_cfi_derive::{cfi_impl_fn, cfi_mod_fn};
use caliptra_common::mailbox_api::{InvokeDpeReq, MailboxRespHeader, MailboxRespHeaderVarSize};
use caliptra_drivers::{CaliptraError, CaliptraResult};
use dpe::{
    commands::{
        CertifyKeyCommand, Command, CommandExecution, CommandHdr, DeriveContextCmd,
        DeriveContextFlags, InitCtxCmd,
    },
    context::{ContextHandle, ContextState},
    error::DpeErrorCode,
    response::ResponseHdr,
    tci::TciMeasurement,
    DpeInstance, DpeProfile, State, U8Bool, MAX_HANDLES,
};
use platform::MAX_OTHER_NAME_SIZE;
use ufmt::derive::uDebug;
use zerocopy::{FromBytes, FromZeros, Immutable, IntoBytes, KnownLayout};
#[cfg(feature = "mldsa_attestation")]
use {crate::mldsa_dpe_env, caliptra_common::mailbox_api::InvokeDpeMldsa87Req};

#[derive(uDebug, Debug, Copy, Clone, PartialEq, Eq)]
pub enum CaliptraDpeProfile {
    Ecc384,
    #[cfg(feature = "mldsa_attestation")]
    Mldsa,
}

impl From<CaliptraDpeProfile> for DpeProfile {
    fn from(profile: CaliptraDpeProfile) -> Self {
        match profile {
            CaliptraDpeProfile::Ecc384 => DpeProfile::P384Sha384,
            #[cfg(feature = "mldsa_attestation")]
            CaliptraDpeProfile::Mldsa => DpeProfile::Mldsa87,
        }
    }
}

pub struct InvokeDpeCmd;
impl InvokeDpeCmd {
    #[cfg_attr(feature = "cfi", cfi_impl_fn)]
    #[inline(never)]
    pub(crate) fn execute(drivers: &mut Drivers) -> CaliptraResult<()> {
        let mut cmd = InvokeDpeReq::new_zeroed();
        crate::packet::copy_from_mbox(drivers, cmd.as_mut_bytes())?;
        execute(
            drivers,
            CaliptraDpeProfile::Ecc384,
            &mut cmd.data,
            cmd.data_size as usize,
        )
    }
}

pub fn invoke_dpe_cmd(
    profile: CaliptraDpeProfile,
    drivers: &mut Drivers,
    command: &Command<'_>,
    dmtf_device_info: Option<ArrayVec<u8, { MAX_OTHER_NAME_SIZE }>>,
    ueid: Option<[u8; 17]>,
    locality: Option<u32>,
    out: &mut dyn ResponseBuffer,
) -> Result<usize, DpeErrorCode> {
    let locality = locality.unwrap_or(drivers.mbox.user());
    // The DPE environment differs by identity (ECDSA RT alias vs ML-DSA
    // PQ.DevID), but the state and command execution are shared.
    let mut env = match profile {
        CaliptraDpeProfile::Ecc384 => ec_dpe_env(drivers, dmtf_device_info, ueid),
        #[cfg(feature = "mldsa_attestation")]
        CaliptraDpeProfile::Mldsa => mldsa_dpe_env(drivers, dmtf_device_info, ueid),
    };
    let env = match env.as_mut() {
        Ok(r) => r,
        Err(_) => {
            return Err(DpeErrorCode::InternalError(
                dpe::error::InternalErrorCode::ActiveContextNotFound,
            ))
        }
    };
    let dpe = &mut DpeInstance::initialized(profile.into());
    command.execute_serialized(dpe, env, locality, out)
}

#[cfg(feature = "mldsa_attestation")]
pub struct InvokeDpeMldsa87Cmd;

#[cfg(feature = "mldsa_attestation")]
impl InvokeDpeMldsa87Cmd {
    #[cfg_attr(feature = "cfi", cfi_impl_fn)]
    #[inline(never)]
    pub(crate) fn execute(drivers: &mut Drivers) -> CaliptraResult<()> {
        if !drivers.persistent_data.get().pqc_mode_enabled() {
            return Err(CaliptraError::RUNTIME_PQC_NOT_INITIALIZED);
        }

        let mut cmd = InvokeDpeMldsa87Req::new_zeroed();
        crate::packet::copy_from_mbox(drivers, cmd.as_mut_bytes())?;
        execute(
            drivers,
            CaliptraDpeProfile::Mldsa,
            &mut cmd.data,
            cmd.data_size as usize,
        )
    }
}

/// Bounds-check the request payload, deserialize the DPE command for `profile`,
/// and execute it. Non-generic over the request type so both entry points share
/// one copy, and takes the raw payload (rather than a deserialized `Command`) so
/// the large `Command` enum never crosses a call boundary by value.
///
/// Note: This function will also append a zeroed SVN to the command if it is a
/// DeriveContext command and the SVN is missing. This is to support older
/// versions of DPE that do not include the SVN in the DeriveContext command.
fn execute(
    drivers: &mut Drivers,
    profile: CaliptraDpeProfile,
    data: &mut [u8; InvokeDpeReq::DATA_MAX_SIZE],
    mut data_size: usize,
) -> CaliptraResult<()> {
    if data_size > data.len() {
        return Err(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS);
    }

    // Append a zeroed SVN to the command if it is a DeriveContext command and the SVN is
    // missing. This is to support older versions of DPE that do not include the SVN in the
    // DeriveContext command.
    if let Ok((hdr, _)) = CommandHdr::read_from_prefix(&data[..data_size]) {
        let expected_no_svn_len = size_of::<CommandHdr>() + size_of::<DeriveContextCmdV1>();

        let is_derive_context_cmd = hdr.cmd_id == Command::DERIVE_CONTEXT;
        let is_missing_svn = data_size == expected_no_svn_len;

        if is_derive_context_cmd && is_missing_svn {
            let cmd_start = size_of::<CommandHdr>();
            let (derive_context_v1, _) =
                DeriveContextCmdV1::read_from_prefix(&data[cmd_start..data_size])
                    .map_err(|_| CaliptraError::RUNTIME_DPE_COMMAND_DESERIALIZATION_FAILED)?;

            data_size = size_of::<CommandHdr>() + size_of::<DeriveContextCmd>();
            let (cmd, _) = DeriveContextCmd::mut_from_prefix(&mut data[cmd_start..data_size])
                .map_err(|_| CaliptraError::RUNTIME_DPE_COMMAND_DESERIALIZATION_FAILED)?;
            *cmd = derive_context_v1.into();
        }
    }

    let command = Command::deserialize(profile.into(), &data[..data_size])
        .map_err(|_| CaliptraError::RUNTIME_DPE_COMMAND_DESERIALIZATION_FAILED)?;
    let caller_privilege_level = drivers.caller_privilege_level();
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
        Command::InitCtx(cmd) if InitCtxCmd::flag_is_simulation(cmd) => {
            // InitCtx can only create new contexts if they are simulation contexts.
            dpe_context_threshold_err?;
        }
        Command::DeriveContext(cmd) => {
            // If the recursive flag is not set, DeriveContext will generate a new context.
            // If recursive _is_ set, it will extend the existing one, which will not count
            // against the context threshold.
            if !cmd.flags.is_recursive() {
                // Takes target locality into consideration if applicable. See above
                dpe_context_threshold_err?;
            }
            if cmd.flags.changes_locality()
                && cmd.target_locality == pl0_pauser
                && caller_privilege_level != PauserPrivileges::PL0
            {
                return Err(CaliptraError::RUNTIME_INCORRECT_PAUSER_PRIVILEGE_LEVEL);
            }

            if cmd.flags.exports_cdi() && caller_privilege_level != PauserPrivileges::PL0 {
                return Err(CaliptraError::RUNTIME_INCORRECT_PAUSER_PRIVILEGE_LEVEL);
            }
        }
        Command::CertifyKey(ref cmd)
            if cmd.format() == CertifyKeyCommand::FORMAT_X509
                && caller_privilege_level != PauserPrivileges::PL0 =>
        {
            // PL1 cannot request X509
            return Err(CaliptraError::RUNTIME_INCORRECT_PAUSER_PRIVILEGE_LEVEL);
        }
        _ => (),
    }

    let ueid = Some(drivers.soc_ifc.fuse_bank().ueid());

    let mut writer = MboxResponseWriter::from_mbox_base();
    let mut w = OffsetResponseBuffer::new(&mut writer, size_of::<MailboxRespHeaderVarSize>());

    let result = invoke_dpe_cmd(profile, drivers, &command, None, ueid, None, &mut w);

    if let Command::DestroyCtx(_) = command {
        // clear tags for destroyed contexts
        let pdata = drivers.persistent_data.get_mut();
        let state = &mut pdata.dpe;
        let context_has_tag = &mut pdata.context_has_tag;
        let context_tags = &mut pdata.context_tags;
        clear_tags_for_inactive_contexts(state, context_has_tag, context_tags);
    }

    let data_len: u32 = match result {
        Ok(n) => {
            // writer already populated data[0..n] in SRAM
            n as u32
        }
        Err(ref e) => {
            // Error: write a ResponseHdr into the data field.
            drivers.soc_ifc.set_fw_extended_error(e.get_error_code());
            let r = ResponseHdr::new(CaliptraDpeProfile::Ecc384.into(), *e);
            w.clear()
                .map_err(|_| CaliptraError::RUNTIME_DPE_RESPONSE_SERIALIZATION_FAILED)?;
            w.write_at(0, r.as_bytes())
                .map_err(|_| CaliptraError::RUNTIME_DPE_RESPONSE_SERIALIZATION_FAILED)?;
            size_of::<ResponseHdr>() as u32
        }
    };

    let header = MailboxRespHeaderVarSize {
        hdr: MailboxRespHeader::default(),
        data_len,
    };
    crate::packet::finalize_mbox_buffer(&mut drivers.mbox, &mut writer, header)?;
    Ok(())
}

/// Remove context tags for all inactive DPE contexts
///
/// # Arguments
///
/// * `dpe` - DpeInstance
/// * `context_has_tag` - Bool slice indicating if a DPE context has a tag
/// * `context_tags` - Tags for each DPE context
#[cfg_attr(feature = "cfi", cfi_mod_fn)]
fn clear_tags_for_inactive_contexts(
    dpe: &mut State,
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

#[repr(C, align(4))]
#[derive(Debug, PartialEq, Eq, FromBytes, IntoBytes, Immutable, KnownLayout)]
struct DeriveContextCmdV1 {
    handle: ContextHandle,
    data: TciMeasurement,
    flags: DeriveContextFlags,
    tci_type: u32,
    target_locality: u32,
}

impl From<DeriveContextCmdV1> for DeriveContextCmd {
    fn from(cmd: DeriveContextCmdV1) -> Self {
        Self {
            handle: cmd.handle,
            data: cmd.data,
            flags: cmd.flags,
            tci_type: cmd.tci_type,
            target_locality: cmd.target_locality,
            svn: 0,
        }
    }
}

const _: () = assert!(
    size_of::<DeriveContextCmdV1>() == size_of::<DeriveContextCmd>() - size_of::<u32>(),
    "DeriveContextCmd size changed, check if SVN compatibility logic needs updating"
);
