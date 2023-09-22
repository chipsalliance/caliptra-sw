// Licensed under the Apache-2.0 license

#[allow(unused_imports)]
#[allow(dead_code)]
use crate::Drivers;
use caliptra_common::mailbox_api::{ExtendPcrReq, MailboxResp};
use caliptra_common::pcr::{PCR_ID_FMC_CURRENT, PCR_ID_FMC_JOURNEY};
use caliptra_common::{PcrLogEntry, PcrLogEntryId};
use caliptra_drivers::{cprint, CaliptraError, CaliptraResult, PcrId};
use zerocopy::{transmute, AsBytes, FromBytes};

pub struct ExtendPcrCmd;
impl ExtendPcrCmd {
    pub(crate) fn execute(drivers: &mut Drivers, cmd_args: &[u8]) -> CaliptraResult<MailboxResp> {
        // 1. Extend PCR
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

        // 2. Add log entry
        if PcrLogEntryId::from(idx as u16) == PcrLogEntryId::Invalid {
            return Err(CaliptraError::ROM_GLOBAL_PCR_LOG_INVALID_ENTRY_ID);
        }

        let pcr_log = drivers
            .persistent_data
            .get_mut()
            .pcr_log
            .get_mut(idx as usize)
            .ok_or(CaliptraError::ROM_GLOBAL_PCR_LOG_UNSUPPORTED_DATA_LENGTH)?;

        let pcr_bank = &mut drivers.pcr_bank;

        let mut pcr_log_entry = PcrLogEntry {
            id: idx as u16,
            pcr_ids: (1 << PCR_ID_FMC_CURRENT as u8) | 1 << PCR_ID_FMC_JOURNEY as u8,
            ..Default::default()
        };
        pcr_log_entry.pcr_data = pcr_bank.read_pcr(pcr_index).into();

        pcr_bank.log_index += 1;
        *pcr_log = pcr_log_entry;

        Ok(MailboxResp::default())
    }
}
