// Licensed under the Apache-2.0 license

use crate::{CptraDpeTypes, DpeCrypto, DpeEnv, DpePlatform, Drivers};
use caliptra_common::mailbox_api::{InvokeDpeReq, InvokeDpeResp, MailboxResp, MailboxRespHeader};
use caliptra_drivers::{CaliptraError, CaliptraResult};
use crypto::{AlgLen, Crypto};
use zerocopy::FromBytes;

pub struct InvokeDpeCmd;
impl InvokeDpeCmd {
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
            let mut env = DpeEnv::<CptraDpeTypes> {
                crypto,
                platform: DpePlatform::new(
                    pdata.manifest1.header.pl0_pauser,
                    hashed_rt_pub_key,
                    &mut drivers.cert_chain,
                ),
            };

            match drivers
                .dpe
                .execute_serialized_command(&mut env, drivers.mbox.user(), &cmd.data)
            {
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
}
