/*++

Licensed under the Apache-2.0 license.

File Name:

    invoke_dpe.rs

Abstract:

    File contains InvokeDpe mailbox command.

--*/

use crate::{dpe_env, mutrefbytes, Drivers, PauserPrivileges};
use caliptra_cfi_derive_git::cfi_impl_fn;
use caliptra_common::mailbox_api::{InvokeDpeReq, InvokeDpeResp, ResponseVarSize};
use caliptra_drivers::{CaliptraError, CaliptraResult};
use dpe::{
    commands::{CertifyKeyCommand, Command, CommandExecution, InitCtxCmd},
    context::ContextState,
    response::{Response, ResponseHdr},
    DpeInstance, DpeProfile, U8Bool, MAX_HANDLES,
};
use zerocopy::IntoBytes;

pub struct InvokeDpeCmd;
impl InvokeDpeCmd {
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    #[inline(never)]
    pub(crate) fn execute(
        drivers: &mut Drivers,
        cmd_args: &[u8],
        mbox_resp: &mut [u8],
    ) -> CaliptraResult<usize> {
        if cmd_args.len() <= core::mem::size_of::<InvokeDpeReq>() {
            let mut cmd = InvokeDpeReq::default();
            cmd.as_mut_bytes()[..cmd_args.len()].copy_from_slice(cmd_args);

            let caller_privilege_level = drivers.caller_privilege_level();

            // Validate data length
            if cmd.data_size as usize > cmd.data.len() {
                return Err(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS);
            }
            let command =
                &Command::deserialize(DpeProfile::P384Sha384, &cmd.data[..cmd.data_size as usize])
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
            let ueid = drivers.soc_ifc.fuse_bank().ueid();
            let locality = drivers.mbox.id();
            let mut env = dpe_env(drivers, None, Some(ueid))?;

            let dpe = &mut DpeInstance::initialized(DpeProfile::P384Sha384);
            let resp = match command {
                Command::GetProfile => Ok(Response::GetProfile(
                    dpe.get_profile(&mut env.platform, env.state.support)
                        .map_err(|_| CaliptraError::RUNTIME_COULD_NOT_GET_DPE_PROFILE)?,
                )),
                Command::InitCtx(cmd) => {
                    // InitCtx can only create new contexts if they are simulation contexts.
                    if InitCtxCmd::flag_is_simulation(cmd) {
                        dpe_context_threshold_err?;
                    }
                    cmd.execute(dpe, &mut env, locality)
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

                    cmd.execute(dpe, &mut env, locality)
                }
                Command::CertifyKey(cmd) => {
                    // PL1 cannot request X509
                    if cmd.format() == CertifyKeyCommand::FORMAT_X509
                        && caller_privilege_level != PauserPrivileges::PL0
                    {
                        return Err(CaliptraError::RUNTIME_INCORRECT_PAUSER_PRIVILEGE_LEVEL);
                    }
                    cmd.execute(dpe, &mut env, locality)
                }
                Command::DestroyCtx(cmd) => cmd.execute(dpe, &mut env, locality),
                Command::Sign(cmd) => cmd.execute(dpe, &mut env, locality),
                Command::RotateCtx(cmd) => cmd.execute(dpe, &mut env, locality),
                Command::GetCertificateChain(cmd) => cmd.execute(dpe, &mut env, locality),
            };

            // Drop env so we can use the drivers again.
            drop(env);

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
            let invoke_resp = mutrefbytes::<InvokeDpeResp>(mbox_resp)?;

            match resp {
                Ok(ref r) => {
                    let resp_bytes = r.as_bytes();
                    let data_size = resp_bytes.len();
                    invoke_resp.data[..data_size].copy_from_slice(resp_bytes);
                    invoke_resp.data_size = data_size as u32;
                }
                Err(ref e) => {
                    // If there is extended error info, populate CPTRA_FW_EXTENDED_ERROR_INFO
                    if let Some(ext_err) = e.get_error_detail() {
                        drivers.soc_ifc.set_fw_extended_error(ext_err);
                    }
                    let r = dpe.response_hdr(*e);
                    invoke_resp.data[..core::mem::size_of::<ResponseHdr>()]
                        .copy_from_slice(r.as_bytes());
                    let data_size = r.as_bytes().len();
                    invoke_resp.data_size = data_size as u32;
                }
            };

            Ok(invoke_resp.partial_len()?)
        } else {
            Err(CaliptraError::RUNTIME_INSUFFICIENT_MEMORY)
        }
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
