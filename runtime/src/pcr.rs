/*++

Licensed under the Apache-2.0 license.

File Name:

    pcr.rs

Abstract:

    File contains mailbox commands that deal with PCRs.

--*/

use crate::Drivers;
use caliptra_cfi_derive_git::cfi_impl_fn;
use caliptra_common::mailbox_api::{
    ExtendPcrReq, IncrementPcrResetCounterReq, MailboxResp, MailboxRespHeader, QuotePcrsReq,
    QuotePcrsResp,
};
use caliptra_drivers::{hand_off::DataStore, CaliptraError, CaliptraResult, PcrBank, PcrId};
use zerocopy::FromBytes;

pub struct IncrementPcrResetCounterCmd;
impl IncrementPcrResetCounterCmd {
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    #[inline(never)]
    pub(crate) fn execute(drivers: &mut Drivers, cmd_args: &[u8]) -> CaliptraResult<MailboxResp> {
        let cmd = IncrementPcrResetCounterReq::ref_from_bytes(cmd_args)
            .map_err(|_| CaliptraError::RUNTIME_INSUFFICIENT_MEMORY)?;

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
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    #[inline(never)]
    pub(crate) fn execute(drivers: &mut Drivers, cmd_bytes: &[u8]) -> CaliptraResult<MailboxResp> {
        let args: &QuotePcrsReq = QuotePcrsReq::ref_from_bytes(cmd_bytes)
            .map_err(|_| CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;

        let pcr_hash = drivers.sha384.gen_pcr_hash(args.nonce.into())?;
        let signature = drivers.ecc384.pcr_sign_flow(&mut drivers.trng)?;
        let raw_pcrs = drivers.pcr_bank.read_all_pcrs();

        let mut pcrs = [[0u8; 48]; 32];
        for (i, p) in raw_pcrs.iter().enumerate() {
            pcrs[i] = p.into()
        }

        Ok(MailboxResp::QuotePcrs(QuotePcrsResp {
            hdr: MailboxRespHeader::default(),
            nonce: args.nonce,
            pcrs,
            reset_ctrs: drivers.persistent_data.get().pcr_reset.all_counters(),
            digest: pcr_hash.into(),
            signature_r: signature.r.into(),
            signature_s: signature.s.into(),
        }))
    }
}

pub struct ExtendPcrCmd;
impl ExtendPcrCmd {
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    #[inline(never)]
    pub(crate) fn execute(drivers: &mut Drivers, cmd_args: &[u8]) -> CaliptraResult<MailboxResp> {
        let cmd = ExtendPcrReq::ref_from_bytes(cmd_args)
            .map_err(|_| CaliptraError::RUNTIME_INSUFFICIENT_MEMORY)?;

        let idx =
            u8::try_from(cmd.pcr_idx).map_err(|_| CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;

        let pcr_index: PcrId =
            match PcrId::try_from(idx).map_err(|_| CaliptraError::RUNTIME_PCR_INVALID_INDEX)? {
                PcrId::PcrId0 | PcrId::PcrId1 | PcrId::PcrId2 | PcrId::PcrId3 => {
                    return Err(CaliptraError::RUNTIME_PCR_RESERVED)
                }
                pcr_id => pcr_id,
            };

        drivers
            .pcr_bank
            .extend_pcr(pcr_index, &mut drivers.sha384, &cmd.data)?;

        Ok(MailboxResp::default())
    }
}
