// Licensed under the Apache-2.0 license

use crate::Drivers;
use caliptra_common::mailbox_api::{
    IncrementPcrResetCounterReq, MailboxResp, MailboxRespHeader, QuotePcrsReq, QuotePcrsResp,
};
use caliptra_drivers::{
    hand_off::DataStore, CaliptraError, CaliptraResult, Ecc384PrivKeyIn, KeyReadArgs, PcrBank,
    PcrId,
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

pub fn get_pcr_quote(drivers: &mut Drivers, cmd_bytes: &[u8]) -> CaliptraResult<MailboxResp> {
    let args: QuotePcrsReq =
        QuotePcrsReq::read_from(cmd_bytes).ok_or(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;

    let pcr_hash = drivers.sha512.gen_pcr_hash(args.nonce.into())?;

    let priv_key_datastore: DataStore = drivers
        .persistent_data
        .get()
        .fht
        .fmc_priv_key_kv_hdl
        .try_into()?;

    let DataStore::KeyVaultSlot(key_id) = priv_key_datastore else {
        return Err(CaliptraError::DRIVER_BAD_DATASTORE_VAULT_TYPE);
    };

    let pub_key = drivers.data_vault.fmc_pub_key();

    let priv_key_args = KeyReadArgs::new(key_id);
    let priv_key = Ecc384PrivKeyIn::Key(priv_key_args);

    let signature = drivers
        .ecc384
        .sign(&priv_key, &pub_key, &pcr_hash, &mut drivers.trng)?;

    let raw_pcrs = drivers.pcr_bank.read_all_pcrs();

    let pcrs_as_bytes = raw_pcrs
        .iter()
        .map(|raw_pcr_value| raw_pcr_value.into())
        .enumerate()
        .fold([[0; 48]; 32], |mut acc, (idx, pcr_value)| {
            acc[idx] = pcr_value;
            acc
        });

    let reset_ctrs = PcrBank::ALL_PCR_IDS
        .iter()
        .map(|pcr_id| drivers.pcr_reset.get(*pcr_id))
        .enumerate()
        .fold([0; 32], |mut acc, (idx, reset_cnt)| {
            acc[idx] = reset_cnt;
            acc
        });

    Ok(MailboxResp::QuotePcrs(QuotePcrsResp {
        hdr: MailboxRespHeader::default(),
        pcrs: pcrs_as_bytes,
        reset_ctrs,
        signature_r: signature.r.into(),
        signature_s: signature.s.into(),
    }))
}
