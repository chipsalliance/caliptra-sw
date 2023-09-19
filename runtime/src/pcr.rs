// Licensed under the Apache-2.0 license

use crate::Drivers;
use caliptra_common::mailbox_api::{ExtendPcrReq, MailboxResp};
use caliptra_drivers::{cprint, CaliptraError, CaliptraResult, PcrId};
use zerocopy::FromBytes;

pub struct ExtendPcrCmd;
impl ExtendPcrCmd {
    pub(crate) fn execute(drivers: &mut Drivers, cmd_args: &[u8]) -> CaliptraResult<MailboxResp> {
        let cmd =
            ExtendPcrReq::read_from(cmd_args).ok_or(CaliptraError::RUNTIME_INSUFFICIENT_MEMORY)?;

        let idx =
            u8::try_from(cmd.pcr_idx).map_err(|_| CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;

        let pcr_index: PcrId =
            match PcrId::try_from(idx).map_err(|_| CaliptraError::RUNTIME_PCR_INVALID_INDEX)? {
                PcrId::PcrId0 | PcrId::PcrId1 | PcrId::PcrId2 | PcrId::PcrId3 => {
                    return Err(CaliptraError::RUNTIME_PCR_RESERVED)
                }
                pcr_id => pcr_id,
            };

        drivers.pcr_bank.extend_pcr(
            pcr_index,
            &mut drivers.sha384,
            &cmd.data[..cmd.data_size as usize],
        )?;

        Ok(MailboxResp::default())
    }
}
