/*++

Licensed under the Apache-2.0 license.

File Name:

    invoke_dpe.rs

Abstract:

    File contains InvokeDpe mailbox command.

--*/

use crate::{
    CptraDpeTypes, DpeCrypto, DpeEnv, DpePlatform, Drivers, PauserPrivileges, PL0_PAUSER_FLAG,
};
use caliptra_cfi_derive_git::cfi_impl_fn;
use caliptra_common::mailbox_api::{InvokeDpeReq, InvokeDpeResp, MailboxResp, MailboxRespHeader};
use caliptra_drivers::{CaliptraError, CaliptraResult};
use crypto::{AlgLen, Crypto};
use dpe::{
    commands::{
        CertifyKeyCmd, Command, CommandExecution, DeriveContextCmd, DeriveContextFlags, InitCtxCmd,
    },
    context::{Context, ContextState},
    response::{Response, ResponseHdr},
    DpeInstance, U8Bool, MAX_HANDLES,
};
use zerocopy::{FromBytes, IntoBytes, TryFromBytes};

pub struct InvokeDpeCmd;
impl InvokeDpeCmd {
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    #[inline(never)]
    pub(crate) fn execute(drivers: &mut Drivers, cmd_args: &[u8]) -> CaliptraResult<MailboxResp> {
        if cmd_args.len() <= core::mem::size_of::<InvokeDpeReq>() {
            let mut cmd = InvokeDpeReq::default();
            cmd.as_mut_bytes()[..cmd_args.len()].copy_from_slice(cmd_args);

            // Validate data length
            if cmd.data_size as usize > cmd.data.len() {
                return Err(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS);
            }

            let hashed_rt_pub_key = drivers.compute_rt_alias_sn()?;
            let key_id_rt_cdi = Drivers::get_key_id_rt_cdi(drivers)?;
            let key_id_rt_priv_key = Drivers::get_key_id_rt_priv_key(drivers)?;

            let caller_privilege_level = drivers.caller_privilege_level();
            let dpe_context_threshold_err = drivers.is_dpe_context_threshold_exceeded();

            let pdata = drivers.persistent_data.get_mut();
            let crypto = DpeCrypto::new(
                &mut drivers.sha384,
                &mut drivers.trng,
                &mut drivers.ecc384,
                &mut drivers.hmac384,
                &mut drivers.key_vault,
                &mut pdata.fht.rt_dice_pub_key,
                key_id_rt_cdi,
                key_id_rt_priv_key,
                &mut pdata.exported_cdi_slots,
            );
            let pl0_pauser = pdata.manifest1.header.pl0_pauser;
            let (nb, nf) = Drivers::get_cert_validity_info(&pdata.manifest1);
            let ueid = &drivers.soc_ifc.fuse_bank().ueid();
            let mut env = DpeEnv::<CptraDpeTypes> {
                crypto,
                platform: DpePlatform::new(
                    pl0_pauser,
                    &hashed_rt_pub_key,
                    &drivers.cert_chain,
                    &nb,
                    &nf,
                    None,
                    Some(ueid),
                ),
            };

            let locality = drivers.mbox.user();
            // This check already happened, but without it the compiler believes the below slice is
            // out of bounds.
            if cmd.data_size as usize > cmd.data.len() {
                return Err(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS);
            }
            let command = Command::deserialize(&cmd.data[..cmd.data_size as usize])
                .map_err(|_| CaliptraError::RUNTIME_DPE_COMMAND_DESERIALIZATION_FAILED)?;
            let flags = pdata.manifest1.header.flags;

            let mut dpe = &mut pdata.dpe;
            let mut context_has_tag = &mut pdata.context_has_tag;
            let mut context_tags = &mut pdata.context_tags;
            let resp = match command {
                Command::GetProfile => Ok(Response::GetProfile(
                    dpe.get_profile(&mut env.platform)
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
                    // If the recursive flag is not set, DeriveContext will generate a new context.
                    // If recursive _is_ set, it will extend the existing one, which will not count
                    // against the context threshold.
                    if !DeriveContextCmd::is_recursive(cmd) {
                        dpe_context_threshold_err?;
                    }
                    if DeriveContextCmd::changes_locality(cmd)
                        && cmd.target_locality == pl0_pauser
                        && caller_privilege_level != PauserPrivileges::PL0
                    {
                        return Err(CaliptraError::RUNTIME_INCORRECT_PAUSER_PRIVILEGE_LEVEL);
                    }

                    if DeriveContextCmd::exports_cdi(cmd)
                        && caller_privilege_level != PauserPrivileges::PL0
                    {
                        return Err(CaliptraError::RUNTIME_INCORRECT_PAUSER_PRIVILEGE_LEVEL);
                    }

                    cmd.execute(dpe, &mut env, locality)
                }
                Command::CertifyKey(cmd) => {
                    // PL1 cannot request X509
                    if cmd.format == CertifyKeyCmd::FORMAT_X509
                        && caller_privilege_level != PauserPrivileges::PL0
                    {
                        return Err(CaliptraError::RUNTIME_INCORRECT_PAUSER_PRIVILEGE_LEVEL);
                    }
                    cmd.execute(dpe, &mut env, locality)
                }
                Command::DestroyCtx(cmd) => {
                    let destroy_ctx_resp = cmd.execute(dpe, &mut env, locality);
                    // clear tags for destroyed contexts
                    Self::clear_tags_for_inactive_contexts(dpe, context_has_tag, context_tags);
                    destroy_ctx_resp
                }
                Command::Sign(cmd) => cmd.execute(dpe, &mut env, locality),
                Command::RotateCtx(cmd) => cmd.execute(dpe, &mut env, locality),
                Command::GetCertificateChain(cmd) => cmd.execute(dpe, &mut env, locality),
            };

            let mut invoke_resp = InvokeDpeResp {
                hdr: MailboxRespHeader::default(),
                data_size: 0,
                data: [0u8; InvokeDpeResp::DATA_MAX_SIZE],
            };

            // If DPE command failed, populate header with error code, but
            // don't fail the mailbox command.
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
                    let r = ResponseHdr::try_mut_from_bytes(
                        &mut invoke_resp.data[..core::mem::size_of::<ResponseHdr>()],
                    )
                    .map_err(|_| CaliptraError::RUNTIME_DPE_RESPONSE_SERIALIZATION_FAILED)?;
                    *r = ResponseHdr::new(*e);
                    let data_size = r.as_bytes().len();
                    invoke_resp.data_size = data_size as u32;
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
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    pub fn clear_tags_for_inactive_contexts(
        dpe: &mut DpeInstance,
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
