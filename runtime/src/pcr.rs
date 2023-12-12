// Licensed under the Apache-2.0 license

use crate::Drivers;
use caliptra_common::mailbox_api::{
    IncrementPcrResetCounterReq, MailboxResp, MailboxRespHeader, QuotePcrsReq, QuotePcrsResp,
};
use caliptra_drivers::{hand_off::DataStore, CaliptraError, CaliptraResult, PcrBank, PcrId};
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

pub struct GetPcrQuoteCmd;
impl GetPcrQuoteCmd {
    pub(crate) fn execute(drivers: &mut Drivers, cmd_bytes: &[u8]) -> CaliptraResult<MailboxResp> {
        let args: QuotePcrsReq = QuotePcrsReq::read_from(cmd_bytes)
            .ok_or(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;

        let pcr_hash = drivers.sha384.gen_pcr_hash(args.nonce.into())?;

        let signature = drivers.ecc384.pcr_sign_flow(&mut drivers.trng)?;

        let raw_pcrs = drivers.pcr_bank.read_all_pcrs();

        let pcrs_as_bytes = raw_pcrs
            .into_iter()
            .map(|raw_pcr_value| raw_pcr_value.into())
            .enumerate()
            .fold([[0; 48]; 32], |mut acc, (idx, pcr_value)| {
                acc[idx] = pcr_value;
                acc
            });

        Ok(MailboxResp::QuotePcrs(QuotePcrsResp {
            hdr: MailboxRespHeader::default(),
            nonce: args.nonce,
            pcrs: pcrs_as_bytes,
            reset_ctrs: drivers.persistent_data.get().pcr_reset.all_counters(),
            digest: pcr_hash.into(),
            signature_r: signature.r.into(),
            signature_s: signature.s.into(),
        }))
    }
}
