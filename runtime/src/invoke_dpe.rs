// Licensed under the Apache-2.0 license

use crate::{CptraDpeTypes, DpeCrypto, DpeEnv, DpePlatform, Drivers, PL0_PAUSER_FLAG};
use caliptra_common::mailbox_api::{InvokeDpeReq, InvokeDpeResp, MailboxResp, MailboxRespHeader};
use caliptra_drivers::{CaliptraError, CaliptraResult};
use crypto::{AlgLen, Crypto};
use dpe::{
    commands::{
        CertifyKeyCmd, Command, CommandExecution, DeriveChildCmd, DeriveChildFlags, InitCtxCmd,
    },
    context::{Context, ContextState},
    response::{Response, ResponseHdr},
    DpeInstance, MAX_HANDLES,
};
use zerocopy::{AsBytes, FromBytes};

pub struct InvokeDpeCmd;
impl InvokeDpeCmd {
    pub const PL0_DPE_ACTIVE_CONTEXT_THRESHOLD: usize = 8;
    pub const PL1_DPE_ACTIVE_CONTEXT_THRESHOLD: usize = 16;

    pub(crate) fn execute(drivers: &mut Drivers, cmd_args: &[u8]) -> CaliptraResult<MailboxResp> {
        if cmd_args.len() <= core::mem::size_of::<InvokeDpeReq>() {
            let mut cmd = InvokeDpeReq::default();
            cmd.as_bytes_mut()[..cmd_args.len()].copy_from_slice(cmd_args);

            // Validate data length
            if cmd.data_size as usize > cmd.data.len() {
                return Err(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS);
            }

            let hashed_rt_pub_key = drivers.compute_rt_alias_sn()?;
            let pdata = drivers.persistent_data.get();
            let rt_pub_key = pdata.fht.rt_dice_pub_key;
            let mut crypto = DpeCrypto::new(
                &mut drivers.sha384,
                &mut drivers.trng,
                &mut drivers.ecc384,
                &mut drivers.hmac384,
                &mut drivers.key_vault,
                rt_pub_key,
            );
            let image_header = &pdata.manifest1.header;
            let pl0_pauser = pdata.manifest1.header.pl0_pauser;
            let mut env = DpeEnv::<CptraDpeTypes> {
                crypto,
                platform: DpePlatform::new(pl0_pauser, hashed_rt_pub_key, &mut drivers.cert_chain),
            };

            let locality = drivers.mbox.user();
            let command = Command::deserialize(&cmd.data[..cmd.data_size as usize])
                .map_err(|_| CaliptraError::RUNTIME_INVOKE_DPE_FAILED)?;
            let flags = pdata.manifest1.header.flags;

            let pdata_mut = drivers.persistent_data.get_mut();
            let mut dpe = &mut pdata_mut.dpe;
            let mut context_has_tag = &mut pdata_mut.context_has_tag;
            let mut context_tags = &mut pdata_mut.context_tags;
            let resp = match command {
                Command::GetProfile => Ok(Response::GetProfile(
                    dpe.get_profile(&mut env.platform)
                        .map_err(|_| CaliptraError::RUNTIME_INVOKE_DPE_FAILED)?,
                )),
                Command::InitCtx(cmd) => {
                    // InitCtx can only create new contexts if they are simulation contexts.
                    if InitCtxCmd::flag_is_simulation(&cmd) {
                        Drivers::is_dpe_context_threshold_exceeded(
                            pl0_pauser, flags, locality, dpe,
                        )?;
                    }
                    cmd.execute(dpe, &mut env, locality)
                }
                Command::DeriveChild(cmd) => {
                    Drivers::is_dpe_context_threshold_exceeded(pl0_pauser, flags, locality, dpe)?;
                    if DeriveChildCmd::changes_locality(&cmd)
                        && cmd.target_locality == pl0_pauser
                        && Drivers::is_caller_pl1(pl0_pauser, flags, locality)
                    {
                        return Err(CaliptraError::RUNTIME_INCORRECT_PAUSER_PRIVILEGE_LEVEL);
                    }
                    let derive_child_resp = cmd.execute(dpe, &mut env, locality);
                    // clear tags for retired contexts
                    Drivers::clear_tags_for_non_active_contexts(dpe, context_has_tag, context_tags);
                    derive_child_resp
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
                    Drivers::clear_tags_for_non_active_contexts(dpe, context_has_tag, context_tags);
                    destroy_ctx_resp
                }
                Command::Sign(cmd) => cmd.execute(dpe, &mut env, locality),
                Command::RotateCtx(cmd) => cmd.execute(dpe, &mut env, locality),
                Command::ExtendTci(cmd) => cmd.execute(dpe, &mut env, locality),
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
}
