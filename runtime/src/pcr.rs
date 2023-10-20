// Licensed under the Apache-2.0 license

use crate::Drivers;
use caliptra_common::mailbox_api::{
    IncrementPcrResetCounterReq, MailboxResp, MailboxRespHeader, QuotePcrsReq, QuotePcrsResp,
};
use caliptra_drivers::{
    cprintln, hand_off::DataStore, CaliptraError, CaliptraResult, Ecc384PrivKeyIn, KeyReadArgs,
    PcrBank, PcrId,
};
use zerocopy::{transmute, FromBytes};

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
        let cmd = IncrementPcrResetCounterReq::read_from(cmd_args)
            .ok_or(CaliptraError::RUNTIME_INSUFFICIENT_MEMORY)?;

        let index =
            u8::try_from(cmd.index).map_err(|_| CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;

        let pcr =
            PcrId::try_from(index).map_err(|_| CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;
        drivers.pcr_reset.increment(pcr);

        Ok(MailboxResp::default())
    }
}

pub struct GetPcrQuoteCmd;
impl GetPcrQuoteCmd {
    pub(crate) fn execute(drivers: &mut Drivers, cmd_bytes: &[u8]) -> CaliptraResult<MailboxResp> {
        let args: QuotePcrsReq = QuotePcrsReq::read_from(cmd_bytes)
            .ok_or(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;

        let pcr_hash = drivers.sha384.gen_pcr_hash(args.nonce.into())?;

        let signature = drivers.ecc384.pcr_sign_flow(&pcr_hash, &mut drivers.trng)?;

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
            reset_ctrs: drivers.pcr_reset.counter,
            signature_r: signature.r.into(),
            signature_s: signature.s.into(),
        }))
    }
}
