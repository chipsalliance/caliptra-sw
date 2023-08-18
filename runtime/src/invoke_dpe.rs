// Licensed under the Apache-2.0 license

use crate::{
    CptraDpeTypes, DpeCrypto, DpeEnv, DpePlatform, Drivers, InvokeDpeReq, InvokeDpeResp,
    MailboxResp, MailboxRespHeader,
};
use caliptra_drivers::{CaliptraError, CaliptraResult};
use zerocopy::FromBytes;

pub struct InvokeDpeCmd;
impl InvokeDpeCmd {
    pub(crate) fn execute(drivers: &mut Drivers, cmd_args: &[u8]) -> CaliptraResult<MailboxResp> {
        if let Some(cmd) = InvokeDpeReq::read_from(cmd_args) {
            let mut response_buf = [0u8; InvokeDpeResp::DATA_MAX_SIZE];
            let mut env = DpeEnv::<CptraDpeTypes> {
                crypto: DpeCrypto::new(&mut drivers.sha384),
                platform: DpePlatform,
            };
            match drivers
                .dpe
                .execute_serialized_command(&mut env, drivers.mbox.user(), &cmd.data)
            {
                Ok(resp) => {
                    let serialized_resp = resp.as_bytes();
                    let data_size = serialized_resp.len();
                    response_buf[..data_size].copy_from_slice(serialized_resp);
                    Ok(MailboxResp::InvokeDpeCommand(InvokeDpeResp {
                        hdr: MailboxRespHeader::default(),
                        data_size: data_size as u32,
                        data: response_buf,
                    }))
                }
                _ => Err(CaliptraError::RUNTIME_INVOKE_DPE_FAILED),
            }
        } else {
            Err(CaliptraError::RUNTIME_INSUFFICIENT_MEMORY)
        }
    }
}
