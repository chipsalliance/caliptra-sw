/*++

Licensed under the Apache-2.0 license.

File Name:

    invoke_dpe.rs

Abstract:

    File contains InvokeDpe mailbox command.

--*/

use crate::{ec_dpe_env, Drivers, PauserPrivileges};
use arrayvec::ArrayVec;
use caliptra_cfi_derive::cfi_impl_fn;
use caliptra_common::mailbox_api::{InvokeDpeReq, InvokeDpeResp, MailboxResp, MailboxRespHeader};
use caliptra_drivers::{CaliptraError, CaliptraResult};
use dpe::{
    commands::{CertifyKeyCommand, Command, CommandExecution, InitCtxCmd},
    context::ContextState,
    response::{DpeErrorCode, Response, ResponseHdr},
    DpeInstance, DpeProfile, State, U8Bool, MAX_HANDLES,
};
use platform::MAX_OTHER_NAME_SIZE;
use ufmt::derive::uDebug;
use zerocopy::IntoBytes;

#[derive(uDebug, Debug, Copy, Clone, PartialEq, Eq)]
pub enum CaliptraDpeProfile {
    Ecc384,
}

impl From<CaliptraDpeProfile> for DpeProfile {
    fn from(profile: CaliptraDpeProfile) -> Self {
        match profile {
            CaliptraDpeProfile::Ecc384 => DpeProfile::P384Sha384,
        }
    }
}

pub struct InvokeDpeCmd;
impl InvokeDpeCmd {
    #[cfg_attr(feature = "cfi", cfi_impl_fn)]
    #[inline(never)]
    pub(crate) fn execute(drivers: &mut Drivers, cmd_args: &[u8]) -> CaliptraResult<MailboxResp> {
        if cmd_args.len() <= core::mem::size_of::<InvokeDpeReq>() {
            let mut cmd = InvokeDpeReq::default();
            cmd.as_mut_bytes()[..cmd_args.len()].copy_from_slice(cmd_args);

            let caller_privilege_level = drivers.caller_privilege_level();

            // Validate data length
            if cmd.data_size as usize > cmd.data.len() {
                return Err(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS);
            }
            let command =
                Command::deserialize(DpeProfile::P384Sha384, &cmd.data[..cmd.data_size as usize])
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
            let mut invoke_resp = InvokeDpeResp::default();
            let result = invoke_dpe_cmd(drivers, &command, None, ueid, None, &mut invoke_resp.data);

            if let Command::DestroyCtx(_) = command {
                // clear tags for destroyed contexts
                let pdata = drivers.persistent_data.get_mut();
                let state = &mut pdata.dpe;
                let context_has_tag = &mut pdata.context_has_tag;
                let context_tags = &mut pdata.context_tags;
                InvokeDpeCmd::clear_tags_for_inactive_contexts(
                    state,
                    context_has_tag,
                    context_tags,
                );
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
                    let r = ResponseHdr::new(CaliptraDpeProfile::Ecc384.into(), *e);
                    invoke_resp.data[..core::mem::size_of::<ResponseHdr>()]
                        .copy_from_slice(r.as_bytes());
                    invoke_resp.data_size = r.as_bytes().len() as u32;
                }
            };

            Ok(MailboxResp::InvokeDpeCommand(invoke_resp))
        } else {
            Err(CaliptraError::RUNTIME_INSUFFICIENT_MEMORY)
        }
    }

    /// Remove context tags for all inactive DPE contexts
    ///
    /// # Arguments
    ///
    /// * `dpe` - DpeInstance
    /// * `context_has_tag` - Bool slice indicating if a DPE context has a tag
    /// * `context_tags` - Tags for each DPE context
    #[cfg_attr(feature = "cfi", cfi_impl_fn)]
    pub fn clear_tags_for_inactive_contexts(
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
}

pub fn invoke_dpe_cmd(
    drivers: &mut Drivers,
    command: &Command<'_>,
    dmtf_device_info: Option<ArrayVec<u8, { MAX_OTHER_NAME_SIZE }>>,
    ueid: Option<[u8; 17]>,
    locality: Option<u32>,
    out: &mut [u8],
) -> Result<usize, DpeErrorCode> {
    let locality = locality.unwrap_or(drivers.mbox.user());
    let mut env = ec_dpe_env(drivers, dmtf_device_info, ueid);
    let env = match env.as_mut() {
        Ok(r) => r,
        Err(_) => Err(DpeErrorCode::InternalError)?,
    };
    let dpe = &mut DpeInstance::initialized(DpeProfile::P384Sha384);
    command.execute_serialized(dpe, env, locality, out)
}
