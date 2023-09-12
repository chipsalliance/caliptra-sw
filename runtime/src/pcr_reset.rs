// Licensed under the Apache-2.0 license

use crate::Drivers;
use caliptra_common::mailbox_api::{IncrementPcrResetCounterReq, MailboxResp};
use caliptra_drivers::{CaliptraError, CaliptraResult, PcrId};
use zerocopy::FromBytes;

pub struct PcrResetCounter {
    counter: [u32; 32],
}

impl Default for PcrResetCounter {
    fn default() -> Self {
        PcrResetCounter::new()
    }
}

impl PcrResetCounter {
    fn new() -> PcrResetCounter {
        PcrResetCounter { counter: [0; 32] }
    }

    pub fn get(&self, id: PcrId) -> u32 {
        self.counter[usize::from(id)]
    }

    pub fn increment(&mut self, id: PcrId) {
        self.counter[usize::from(id)] += 1;
    }
}

pub struct IncrementPcrResetCounter;
impl IncrementPcrResetCounter {
    pub(crate) fn execute(drivers: &mut Drivers, cmd_args: &[u8]) -> CaliptraResult<MailboxResp> {
        let cmd = IncrementPcrResetCounterReq::read_from(cmd_args).ok_or(CaliptraError::RUNTIME_INSUFFICIENT_MEMORY)?;

        let index = u8::try_from(cmd.index).map_err( |_| CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;

        let pcr = PcrId::try_from(index).map_err( |_| CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;
        drivers.pcr_reset.increment(pcr);

        Ok(MailboxResp::default())
    }
}
