// Licensed under the Apache-2.0 license

use crate::{CptraDpeTypes, DpeCrypto, DpeEnv, DpePlatform, Drivers};
use caliptra_common::mailbox_api::{InvokeDpeReq, InvokeDpeResp, MailboxResp, MailboxRespHeader};
use caliptra_drivers::{CaliptraError, CaliptraResult};
use crypto::{AlgLen, Crypto};
use dpe::{
    commands::{CertifyKeyCmd, Command, CommandExecution},
    response::Response,
};
use zerocopy::FromBytes;

pub struct InvokeDpeCmd;
impl InvokeDpeCmd {
    const PL0_PAUSER_FLAG: u32 = 1;

    pub(crate) fn execute(drivers: &mut Drivers, cmd_args: &[u8]) -> CaliptraResult<MailboxResp> {
        if let Some(cmd) = InvokeDpeReq::read_from(cmd_args) {
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
            let hashed_rt_pub_key = crypto
                .hash(AlgLen::Bit384, &rt_pub_key.to_der()[1..])
                .map_err(|_| CaliptraError::RUNTIME_INITIALIZE_DPE_FAILED)?;
            let image_header = &pdata.manifest1.header;
            let pl0_pauser = pdata.manifest1.header.pl0_pauser;
            let mut env = DpeEnv::<CptraDpeTypes> {
                crypto,
                platform: DpePlatform::new(pl0_pauser, hashed_rt_pub_key, &mut drivers.cert_chain),
            };

            let locality = drivers.mbox.user();
            let command = Command::deserialize(&cmd.data)
                .map_err(|_| CaliptraError::RUNTIME_INVOKE_DPE_FAILED)?;
            let flags = pdata.manifest1.header.flags;
            let mut dpe = &mut drivers.persistent_data.get_mut().dpe;
            let resp = match command {
                Command::GetProfile => Ok(Response::GetProfile(
                    dpe.get_profile(&mut env.platform)
                        .map_err(|_| CaliptraError::RUNTIME_INVOKE_DPE_FAILED)?,
                )),
                Command::InitCtx(cmd) => cmd.execute(dpe, &mut env, locality),
                Command::DeriveChild(cmd) => cmd.execute(dpe, &mut env, locality),
                Command::CertifyKey(cmd) => {
                    // PL1 cannot request X509
                    if cmd.format == CertifyKeyCmd::FORMAT_X509
                        && Self::is_caller_p1(pl0_pauser, flags, locality)
                    {
                        return Err(CaliptraError::RUNTIME_INCORRECT_PAUSER_PRIVILEGE_LEVEL);
                    }
                    cmd.execute(dpe, &mut env, locality)
                }
                Command::Sign(cmd) => cmd.execute(dpe, &mut env, locality),
                Command::RotateCtx(cmd) => cmd.execute(dpe, &mut env, locality),
                Command::DestroyCtx(cmd) => cmd.execute(dpe, &mut env, locality),
                Command::ExtendTci(cmd) => cmd.execute(dpe, &mut env, locality),
                Command::TagTci(cmd) => cmd.execute(dpe, &mut env, locality),
                Command::GetTaggedTci(cmd) => cmd.execute(dpe, &mut env, locality),
                Command::GetCertificateChain(cmd) => cmd.execute(dpe, &mut env, locality),
            };

            match resp {
                Ok(resp) => {
                    let resp_bytes = resp.as_bytes();
                    let data_size = resp_bytes.len();
                    let mut invoke_resp = InvokeDpeResp {
                        hdr: MailboxRespHeader::default(),
                        data_size: data_size as u32,
                        data: [0u8; InvokeDpeResp::DATA_MAX_SIZE],
                    };
                    invoke_resp.data[..data_size].copy_from_slice(resp_bytes);

                    Ok(MailboxResp::InvokeDpeCommand(invoke_resp))
                }
                _ => Err(CaliptraError::RUNTIME_INVOKE_DPE_FAILED),
            }
        } else {
            Err(CaliptraError::RUNTIME_INSUFFICIENT_MEMORY)
        }
    }

    fn is_caller_p1(pl0_pauser: u32, flags: u32, locality: u32) -> bool {
        flags & Self::PL0_PAUSER_FLAG == 0 && locality != pl0_pauser
    }
}
