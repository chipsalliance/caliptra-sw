/*++

Licensed under the Apache-2.0 license.

File Name:

    pcr.rs

Abstract:

    File contains mailbox commands that deal with PCRs.

--*/

use crate::packet::{copy_from_mbox, copy_to_mbox};
use crate::Drivers;
use caliptra_cfi_derive::cfi_impl_fn;
use caliptra_common::mailbox_api::{
    ExtendPcrReq, GetPcrLogResp, IncrementPcrResetCounterReq, MailboxRespHeader, QuotePcrsReq,
    QuotePcrsResp,
};
use caliptra_drivers::{CaliptraError, CaliptraResult, PcrId};
use zerocopy::{FromZeros, IntoBytes};

pub struct IncrementPcrResetCounterCmd;
impl IncrementPcrResetCounterCmd {
    #[cfg_attr(feature = "cfi", cfi_impl_fn)]
    #[inline(never)]
    pub(crate) fn execute(drivers: &mut Drivers) -> CaliptraResult<()> {
        let mut cmd = IncrementPcrResetCounterReq::new_zeroed();
        copy_from_mbox(drivers, cmd.as_mut_bytes())?;

        let index =
            u8::try_from(cmd.index).map_err(|_| CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;

        let pcr =
            PcrId::try_from(index).map_err(|_| CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;

        if !drivers.persistent_data.get_mut().pcr_reset.increment(pcr) {
            return Err(CaliptraError::RUNTIME_INCREMENT_PCR_RESET_MAX_REACHED);
        }

        copy_to_mbox(drivers, MailboxRespHeader::default().as_mut_bytes())
    }
}

pub struct GetPcrQuoteCmd;
impl GetPcrQuoteCmd {
    #[cfg_attr(feature = "cfi", cfi_impl_fn)]
    #[inline(never)]
    pub(crate) fn execute(drivers: &mut Drivers) -> CaliptraResult<()> {
        let mut args = QuotePcrsReq::new_zeroed();
        copy_from_mbox(drivers, args.as_mut_bytes())?;

        let pcr_hash = drivers.sha384.gen_pcr_hash(args.nonce.into())?;
        let signature = drivers.ecc384.pcr_sign_flow(&mut drivers.trng)?;
        let raw_pcrs = drivers.pcr_bank.read_all_pcrs();

        let mut pcrs = [[0u8; 48]; 32];
        for (i, p) in raw_pcrs.iter().enumerate() {
            pcrs[i] = p.into()
        }

        let mut resp = QuotePcrsResp {
            hdr: MailboxRespHeader::default(),
            nonce: args.nonce,
            pcrs,
            reset_ctrs: drivers.persistent_data.get().pcr_reset.all_counters(),
            digest: pcr_hash.into(),
            signature_r: signature.r.into(),
            signature_s: signature.s.into(),
        };
        copy_to_mbox(drivers, resp.as_mut_bytes())
    }
}

pub struct ExtendPcrCmd;
impl ExtendPcrCmd {
    #[cfg_attr(feature = "cfi", cfi_impl_fn)]
    #[inline(never)]
    pub(crate) fn execute(drivers: &mut Drivers) -> CaliptraResult<()> {
        let mut cmd = ExtendPcrReq::new_zeroed();
        copy_from_mbox(drivers, cmd.as_mut_bytes())?;

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

        copy_to_mbox(drivers, MailboxRespHeader::default().as_mut_bytes())
    }
}

pub struct GetPcrLogCmd;
impl GetPcrLogCmd {
    #[cfg_attr(feature = "cfi", cfi_impl_fn)]
    #[inline(never)]
    pub(crate) fn execute(drivers: &mut Drivers) -> CaliptraResult<()> {
        let next_available = drivers.persistent_data.get().fht.pcr_log_index as usize;
        let Some(pcr_logs) = drivers.persistent_data.get().pcr_log.get(..next_available) else {
            return Err(CaliptraError::RUNTIME_PCR_INVALID_INDEX);
        };
        let pcr_log_bytes = pcr_logs.as_bytes();
        let mut resp = GetPcrLogResp::new_zeroed();
        resp.data_size = pcr_log_bytes.len() as u32;
        resp.data
            .get_mut(..pcr_log_bytes.len())
            .ok_or(CaliptraError::RUNTIME_PCR_INVALID_INDEX)?
            .copy_from_slice(pcr_log_bytes);
        copy_to_mbox(drivers, resp.as_mut_bytes())
    }
}
