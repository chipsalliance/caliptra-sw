use caliptra_common::mailbox_api::{MailboxResp, MailboxRespHeader, QuotePcrsReq, QuotePcrsResp};
use caliptra_drivers::{hand_off::DataStore, Ecc384PrivKeyIn, KeyReadArgs};
use caliptra_error::{CaliptraError, CaliptraResult};
use zerocopy::{transmute, FromBytes};

use crate::Drivers;

pub fn get_pcr_quote(drivers: &mut Drivers, cmd_bytes: &[u8]) -> CaliptraResult<MailboxResp> {
    let args: QuotePcrsReq =
        QuotePcrsReq::read_from(cmd_bytes).ok_or(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;

    let pcr_hash = drivers.sha512.gen_pcr_hash(transmute!(args.nonce))?;

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

    let pcrs = drivers.pcr_bank.read_all_pcrs();

    Ok(MailboxResp::QuotePcrs(QuotePcrsResp {
        hdr: MailboxRespHeader::default(),
        pcrs,
        reset_ctrs: [0; 32], // TODO: implement and return reset counters
        signature_r: signature.r.into(),
        signature_s: signature.s.into(),
    }))
}
