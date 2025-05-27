/*++

Licensed under the Apache-2.0 license.

File Name:

    pcr.rs

Abstract:

    File contains mailbox commands that deal with PCRs.

--*/

use crate::{mutrefbytes, Drivers};
use caliptra_cfi_derive_git::cfi_impl_fn;
use caliptra_common::mailbox_api::{
    ExtendPcrReq, GetPcrLogResp, IncrementPcrResetCounterReq, MailboxRespHeader, QuotePcrsFlags,
    QuotePcrsReq, QuotePcrsResp,
};
use caliptra_drivers::{CaliptraError, CaliptraResult, PcrId};
use zerocopy::{FromBytes, IntoBytes};

pub struct IncrementPcrResetCounterCmd;
impl IncrementPcrResetCounterCmd {
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    #[inline(never)]
    pub(crate) fn execute(drivers: &mut Drivers, cmd_args: &[u8]) -> CaliptraResult<usize> {
        let cmd = IncrementPcrResetCounterReq::ref_from_bytes(cmd_args)
            .map_err(|_| CaliptraError::RUNTIME_INSUFFICIENT_MEMORY)?;

        let index =
            u8::try_from(cmd.index).map_err(|_| CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;

        let pcr =
            PcrId::try_from(index).map_err(|_| CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;

        if !drivers.persistent_data.get_mut().pcr_reset.increment(pcr) {
            return Err(CaliptraError::RUNTIME_INCREMENT_PCR_RESET_MAX_REACHED);
        }

        Ok(0)
    }
}

pub struct GetPcrQuoteCmd;
impl GetPcrQuoteCmd {
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    #[inline(never)]
    pub(crate) fn execute(
        drivers: &mut Drivers,
        cmd_bytes: &[u8],
        resp: &mut [u8],
    ) -> CaliptraResult<usize> {
        let args: &QuotePcrsReq = QuotePcrsReq::ref_from_bytes(cmd_bytes)
            .map_err(|_| CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;

        let pcr_hash = drivers.sha2_512_384.gen_pcr_hash(args.nonce.into())?;

        let mldsa_signature = if args.flags.contains(QuotePcrsFlags::MLDSA_SIGNATURE) {
            drivers.mldsa87.pcr_sign_flow(&mut drivers.trng)?
        } else {
            Default::default()
        };

        let ecc_signature = if args.flags.contains(QuotePcrsFlags::ECC_SIGNATURE) {
            drivers.ecc384.pcr_sign_flow(&mut drivers.trng)?
        } else {
            Default::default()
        };

        let raw_pcrs = drivers.pcr_bank.read_all_pcrs();

        let resp = mutrefbytes::<QuotePcrsResp>(resp)?;
        resp.hdr = MailboxRespHeader::default();
        resp.nonce = args.nonce;
        for (i, p) in raw_pcrs.iter().enumerate() {
            resp.pcrs[i] = p.into()
        }
        resp.reset_ctrs = drivers.persistent_data.get().pcr_reset.all_counters();
        resp.digest = pcr_hash.into();
        resp.ecc_signature_r = ecc_signature.r.into();
        resp.ecc_signature_s = ecc_signature.s.into();
        resp.mldsa_signature = mldsa_signature.into();

        Ok(core::mem::size_of::<QuotePcrsResp>())
    }
}

pub struct ExtendPcrCmd;
impl ExtendPcrCmd {
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    #[inline(never)]
    pub(crate) fn execute(drivers: &mut Drivers, cmd_args: &[u8]) -> CaliptraResult<usize> {
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
            .extend_pcr(pcr_index, &mut drivers.sha2_512_384, &cmd.data)?;

        Ok(0)
    }
}

pub struct GetPcrLogCmd;
impl GetPcrLogCmd {
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    #[inline(never)]
    pub(crate) fn execute(drivers: &mut Drivers, resp: &mut [u8]) -> CaliptraResult<usize> {
        let resp = mutrefbytes::<GetPcrLogResp>(resp)?;
        resp.hdr = MailboxRespHeader::default();
        let pcr_log = drivers.persistent_data.get().pcr_log.as_bytes();
        let len = pcr_log.len();
        resp.data_size = len as u32;
        resp.data[..len].copy_from_slice(&pcr_log[..len]);

        Ok(core::mem::size_of::<GetPcrLogResp>())
    }
}
