// Licensed under the Apache-2.0 license

use crate::{CptraDpeTypes, DpeCrypto, DpeEnv, DpePlatform, Drivers};
use caliptra_common::mailbox_api::{InvokeDpeReq, InvokeDpeResp, MailboxResp, MailboxRespHeader};
use caliptra_drivers::{CaliptraError, CaliptraResult};
use zerocopy::FromBytes;

pub struct InvokeDpeCmd;
impl InvokeDpeCmd {
    pub(crate) fn execute(drivers: &mut Drivers, cmd_args: &[u8]) -> CaliptraResult<MailboxResp> {
        if let Some(cmd) = InvokeDpeReq::read_from(cmd_args) {
            let mut env = DpeEnv::<CptraDpeTypes> {
                crypto: DpeCrypto::new(&mut drivers.sha384, &mut drivers.trng),
                platform: DpePlatform::new(drivers.manifest.header.pl0_pauser),
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
