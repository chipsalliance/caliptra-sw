/*++

Licensed under the Apache-2.0 license.

File Name:

    invoke_dpe.rs

Abstract:

    File contains InvokeDpe mailbox command.

--*/

use crate::{CptraDpeTypes, DpeCrypto, DpeEnv, DpePlatform, Drivers, PL0_PAUSER_FLAG};
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
use zerocopy::{AsBytes, FromBytes};

pub struct InvokeDpeCmd;
impl InvokeDpeCmd {
    pub(crate) fn execute(drivers: &mut Drivers, cmd_args: &[u8]) -> CaliptraResult<MailboxResp> {
        if cmd_args.len() <= core::mem::size_of::<InvokeDpeReq>() {
            let mut cmd = InvokeDpeReq::default();
            cmd.as_bytes_mut()[..cmd_args.len()].copy_from_slice(cmd_args);

            // Validate data length
            if cmd.data_size as usize > cmd.data.len() {
                return Err(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS);
            }

            let hashed_rt_pub_key = drivers.compute_rt_alias_sn()?;
            let key_id_rt_cdi = Drivers::get_key_id_rt_cdi(drivers)?;
            let key_id_rt_priv_key = Drivers::get_key_id_rt_priv_key(drivers)?;
            let pdata = drivers.persistent_data.get();
            let mut crypto = DpeCrypto::new(
                &mut drivers.sha384,
                &mut drivers.trng,
                &mut drivers.ecc384,
                &mut drivers.hmac384,
                &mut drivers.key_vault,
                pdata.fht.rt_dice_pub_key,
                key_id_rt_cdi,
                key_id_rt_priv_key,
            );
            let pdata = drivers.persistent_data.get();
            let image_header = &pdata.manifest1.header;
            let pl0_pauser = pdata.manifest1.header.pl0_pauser;
            let mut env = DpeEnv::<CptraDpeTypes> {
                crypto,
                platform: DpePlatform::new(pl0_pauser, hashed_rt_pub_key, &mut drivers.cert_chain),
            };

            let locality = drivers.mbox.user();
            let command = Command::deserialize(&cmd.data[..cmd.data_size as usize])
                .map_err(|_| CaliptraError::RUNTIME_DPE_COMMAND_DESERIALIZATION_FAILED)?;
            let flags = pdata.manifest1.header.flags;

            let pdata_mut = drivers.persistent_data.get_mut();
            let mut dpe = &mut pdata_mut.dpe;
            let mut context_has_tag = &mut pdata_mut.context_has_tag;
            let mut context_tags = &mut pdata_mut.context_tags;
            let resp = match command {
                Command::GetProfile => Ok(Response::GetProfile(
                    dpe.get_profile(&mut env.platform)
                        .map_err(|_| CaliptraError::RUNTIME_COULD_NOT_GET_DPE_PROFILE)?,
                )),
                Command::InitCtx(cmd) => {
                    // InitCtx can only create new contexts if they are simulation contexts.
                    if InitCtxCmd::flag_is_simulation(&cmd) {
                        Drivers::is_dpe_context_threshold_exceeded(
                            pl0_pauser, flags, locality, dpe, false,
                        )?;
                    }
                    cmd.execute(dpe, &mut env, locality)
                }
                Command::DeriveContext(cmd) => {
                    // If the recursive flag is not set, DeriveContext will generate a new context.
                    // If recursive _is_ set, it will extend the existing one, which will not count
                    // against the context threshold.
                    if !DeriveContextCmd::is_recursive(&cmd) {
                        Drivers::is_dpe_context_threshold_exceeded(
                            pl0_pauser, flags, locality, dpe, false,
                        )?;
                    }
                    if DeriveContextCmd::changes_locality(&cmd)
                        && cmd.target_locality == pl0_pauser
                        && Drivers::is_caller_pl1(pl0_pauser, flags, locality)
                    {
                        return Err(CaliptraError::RUNTIME_INCORRECT_PAUSER_PRIVILEGE_LEVEL);
                    }
                    cmd.execute(dpe, &mut env, locality)
                }
                Command::CertifyKey(cmd) => {
                    // PL1 cannot request X509
                    if cmd.format == CertifyKeyCmd::FORMAT_X509
                        && Drivers::is_caller_pl1(pl0_pauser, flags, locality)
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

            // If DPE command failed, populate header with error code, but
            // don't fail the mailbox command.
            let resp_struct = match resp {
                Ok(r) => r,
                Err(e) => {
                    // If there is extended error info, populate CPTRA_FW_EXTENDED_ERROR_INFO
                    if let Some(ext_err) = e.get_error_detail() {
                        drivers.soc_ifc.set_fw_extended_error(ext_err);
                    }
                    Response::Error(ResponseHdr::new(e))
                }
            };

            let resp_bytes = resp_struct.as_bytes();
            let data_size = resp_bytes.len();
            let mut invoke_resp = InvokeDpeResp {
                hdr: MailboxRespHeader::default(),
                data_size: data_size as u32,
                data: [0u8; InvokeDpeResp::DATA_MAX_SIZE],
            };
            invoke_resp.data[..data_size].copy_from_slice(resp_bytes);

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
