// Licensed under the Apache-2.0 license

use crate::Drivers;
use caliptra_common::mailbox_api::{IncrementPcrResetCounterReq, MailboxResp, MailboxRespHeader};
use caliptra_drivers::{hand_off::DataStore, CaliptraError, CaliptraResult, PcrId};
use zerocopy::FromBytes;

pub struct IncrementPcrResetCounterCmd;
impl IncrementPcrResetCounterCmd {
    pub(crate) fn execute(drivers: &mut Drivers, cmd_args: &[u8]) -> CaliptraResult<MailboxResp> {
        let cmd = IncrementPcrResetCounterReq::read_from(cmd_args)
            .ok_or(CaliptraError::RUNTIME_INSUFFICIENT_MEMORY)?;

        let index =
            u8::try_from(cmd.index).map_err(|_| CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;

        let pcr =
            PcrId::try_from(index).map_err(|_| CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;

        if !drivers.persistent_data.get_mut().pcr_reset.increment(pcr) {
            return Err(CaliptraError::RUNTIME_INCREMENT_PCR_RESET_MAX_REACHED);
        }

        Ok(MailboxResp::default())
    }
}
