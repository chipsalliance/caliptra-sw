// Licensed under the Apache-2.0 license

use crate::{Drivers};
use caliptra_common::mailbox_api::{MailboxResp, ExtendPcrReq};
use caliptra_drivers::{CaliptraError, CaliptraResult, PcrId, Sha384};
use caliptra_registers::sha512::Sha512Reg;
use zerocopy::FromBytes;

pub struct ExtendPcrCmd;
impl ExtendPcrCmd {
    pub(crate) fn execute(drivers: &Drivers, cmd_args: &[u8]) -> CaliptraResult<MailboxResp> {
        if let Some(cmd) = ExtendPcrReq::read_from(cmd_args) {
            // let sha384_engine: &mut Sha384 = &mut drivers.sha384.;
            let pcr_sha384_engine: &mut Sha384 = unsafe { &mut Sha384::new(Sha512Reg::new())} ;
            let pcr_value: [u8; ExtendPcrReq::DATA_MAX_SIZE] = cmd.value;
            let pcr_index: PcrId = PcrId::try_from(u8::try_from(cmd.pcr_idx).unwrap()).unwrap();

            drivers.pcr_bank.extend_pcr( pcr_index, pcr_sha384_engine, &pcr_value)?;
        } else {
            return Err(CaliptraError::RUNTIME_INSUFFICIENT_MEMORY);
        }
        
        Ok(MailboxResp::default())
    }
}