/*++

Licensed under the Apache-2.0 license.

File Name:

    debug_unlock.rs

Abstract:

    File contains the code to handle debug unlock

--*/

use core::mem::size_of;

use crate::flow::cold_reset::fw_processor::FirmwareProcessor;
use crate::CaliptraResult;
use caliptra_api::mailbox::{
    MailboxReqHeader, MailboxRespHeader, ManufDebugUnlockTokenReq,
    ProductionAuthDebugUnlockChallenge, ProductionAuthDebugUnlockReq,
    ProductionAuthDebugUnlockToken,
};
#[cfg(not(feature = "no-cfi"))]
use caliptra_cfi_derive::cfi_impl_fn;
use caliptra_cfi_lib::{cfi_launder, CfiCounter};
use caliptra_common::mailbox_api::CommandId;
use caliptra_drivers::{
    sha2_512_384::Sha2DigestOpTrait, Array4x12, Array4x16, Ecc384PubKey, Ecc384Result,
    Ecc384Scalar, Ecc384Signature, Lifecycle, Mldsa87PubKey, Mldsa87Result, Mldsa87Signature,
};
use caliptra_error::CaliptraError;
use zerocopy::AsBytes;

use crate::rom_env::RomEnv;

/// Debug unlock Flow
pub struct DebugUnlockFlow {}

impl DebugUnlockFlow {
    /// Debug Unlock Flow
    ///
    /// # Arguments
    ///
    /// * `env` - ROM Environment
    #[inline(never)]
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    pub fn debug_unlock(env: &mut RomEnv) -> CaliptraResult<()> {
        // Always false on passive mode
        if !env.soc_ifc.ss_debug_unlock_req()? {
            return Ok(());
        }

        crate::cprintln!("[state] debug unlock requested");

        // TODO how to handle early failures like wrong CMDs? Should failure bits be set or just return failure?
        let lifecycle = env.soc_ifc.lifecycle();
        match lifecycle {
            Lifecycle::Production => Self::handle_production(env),
            Lifecycle::Manufacturing => Self::handle_manufactoring(env),
            _ => Ok(()),
        }
    }

    fn handle_manufactoring(env: &mut RomEnv) -> CaliptraResult<()> {
        let mbox = &mut env.mbox;
        let txn = loop {
            // Random delay for CFI glitch protection.
            CfiCounter::delay();

            match mbox.peek_recv() {
                Some(txn) => break txn,
                None => continue,
            }
        };

        if CommandId::from(txn.cmd()) != CommandId::MANUF_DEBUG_UNLOCK_REQ_TOKEN {
            Err(CaliptraError::ROM_SS_DBG_UNLOCK_MANUF_INVALID_MBOX_CMD)?
        }

        let mut txn = txn.start_txn();
        let mut request = ManufDebugUnlockTokenReq::default();
        FirmwareProcessor::copy_req_verify_chksum(&mut txn, request.as_bytes_mut())?;

        env.soc_ifc.set_ss_dbg_unlock_in_progress(true);

        let result: CaliptraResult<()> = (|| {
            let nonce: [u8; 32] = env.trng.generate()?.as_bytes()[..32].try_into().unwrap();
            // The ROM then appends a 256-bit random nonce to the token and performs a SHA-512 operation to generate the expected token.
            let input_token = {
                let mut token: [u8; 64] = [0; 64];
                token[8..][..16].copy_from_slice(&request.token);
                token[32..].copy_from_slice(&nonce);
                env.sha2_512_384.sha512_digest(&token)?
            };

            // Same transformation as mbox input
            let fuse_token = {
                let mut token: [u8; 64] = [0; 64];
                let fuse = env.soc_ifc.fuse_bank().manuf_dbg_unlock_token();
                token[8..][..16].copy_from_slice(fuse.as_bytes());
                token[32..].copy_from_slice(&nonce);
                env.sha2_512_384.sha512_digest(&token)?
            };

            if cfi_launder(input_token) != fuse_token {
                Err(CaliptraError::ROM_SS_DBG_UNLOCK_MANUF_INVALID_TOKEN)?;
            } else {
                caliptra_cfi_lib::cfi_assert_eq_12_words(
                    &input_token.0[..12].try_into().unwrap(),
                    &fuse_token.0[..12].try_into().unwrap(),
                );
            }
            Ok(())
        })();

        env.soc_ifc.set_ss_dbg_unlock_in_progress(false);
        match result {
            Ok(()) => {
                env.soc_ifc.finish_ss_dbg_unluck(true);
                txn.set_uc_tap_unlock(true);
                let resp = MailboxRespHeader::default();
                txn.send_response(resp.as_bytes())?;
            }
            Err(_) => {
                env.soc_ifc.finish_ss_dbg_unluck(false);
                txn.set_uc_tap_unlock(false);
            }
        }
        result
    }

    fn handle_production(env: &mut RomEnv) -> CaliptraResult<()> {
        let mbox = &mut env.mbox;
        let txn = loop {
            // Random delay for CFI glitch protection.
            CfiCounter::delay();

            match mbox.peek_recv() {
                Some(txn) => break txn,
                None => continue,
            }
        };

        if CommandId::from(txn.cmd()) != CommandId::PRODUCTION_AUTH_DEBUG_UNLOCK_REQ {
            Err(CaliptraError::ROM_SS_DBG_UNLOCK_PROD_INVALID_REQ_MBOX_CMD)?
        }

        let mut txn = txn.start_txn();
        let mut request = ProductionAuthDebugUnlockReq::default();
        FirmwareProcessor::copy_req_verify_chksum(&mut txn, request.as_bytes_mut())?;

        let payload_length = |length: [u8; 3]| {
            let mut len: usize = 0;
            len |= length[0] as usize;
            len |= (length[1] as usize) << 8;
            len |= (length[2] as usize) << 16;
            len * size_of::<u32>()
        };

        // Validate payload
        if payload_length(request.length)
            != size_of::<ProductionAuthDebugUnlockReq>() - size_of::<MailboxReqHeader>()
        {
            Err(CaliptraError::ROM_SS_DBG_UNLOCK_PROD_INVALID_REQ)?
        }
        // [TODO][CAP2] what do these 3 bytes mean when only 4 bits are active?
        // Debug level
        let dbg_level = payload_length(request.unlock_category);
        if dbg_level & 0xf != dbg_level {
            Err(CaliptraError::ROM_SS_DBG_UNLOCK_PROD_INVALID_REQ)?
        }

        let length = (size_of::<ProductionAuthDebugUnlockChallenge>()
            - size_of::<MailboxReqHeader>())
            / size_of::<u32>();
        let challenge = env.trng.generate()?.as_bytes().try_into().unwrap();
        let challenge_resp = ProductionAuthDebugUnlockChallenge {
            vendor_id: request.vendor_id,
            object_data_type: request.object_data_type,
            length: length.to_ne_bytes()[..3].try_into().unwrap(),
            unique_device_identifier: {
                let mut id = [0u8; 32];
                id[..17].copy_from_slice(&env.soc_ifc.fuse_bank().ueid());
                id
            },
            challenge,
            ..Default::default()
        };
        txn.send_response(challenge_resp.as_bytes())?;
        core::mem::drop(txn);

        // AUTH_DEBUG_UNLOCK_TOKEN
        let txn = loop {
            // Random delay for CFI glitch protection.
            CfiCounter::delay();

            match mbox.peek_recv() {
                Some(txn) => break txn,
                None => continue,
            }
        };

        if CommandId::from(txn.cmd()) != CommandId::PRODUCTION_AUTH_DEBUG_UNLOCK_TOKEN {
            Err(CaliptraError::ROM_SS_DBG_UNLOCK_PROD_INVALID_TOKEN_MBOX_CMD)?
        }

        env.soc_ifc.set_ss_dbg_unlock_in_progress(true);

        let mut txn = txn.start_txn();
        let mut request = ProductionAuthDebugUnlockToken::default();
        FirmwareProcessor::copy_req_verify_chksum(&mut txn, request.as_bytes_mut())?;

        let result: CaliptraResult<()> = (|| {
            // Validate payload
            if payload_length(request.length)
                != size_of::<ProductionAuthDebugUnlockToken>() - size_of::<MailboxReqHeader>()
            {
                Err(CaliptraError::ROM_SS_DBG_UNLOCK_PROD_INVALID_TOKEN)?
            }
            // Debug level
            if payload_length(request.unlock_category) != dbg_level {
                Err(CaliptraError::ROM_SS_DBG_UNLOCK_PROD_INVALID_TOKEN)?
            }
            if request.challenge != challenge {
                Err(CaliptraError::ROM_SS_DBG_UNLOCK_PROD_INVALID_TOKEN)?
            }

            let debug_auth_pk_offset = env
                .soc_ifc
                .debug_unlock_pk_hash_offset(payload_length(request.unlock_category))?
                as u64;
            let mci_base = env.soc_ifc.ss_mci_axi_base();
            let debug_auth_pk_hash_base = mci_base + debug_auth_pk_offset.into();

            let dma = &mut env.dma;
            let mut fuse_digest = Array4x16::default();
            dma.read_buffer(debug_auth_pk_hash_base, fuse_digest.as_bytes_mut())?;

            let mut digest_op = env.sha2_512_384.sha512_digest_init()?;
            digest_op.update(&request.ecc_public_key)?;
            digest_op.update(&request.mldsa_public_key)?;
            let mut request_digest = Array4x16::default();
            digest_op.finalize(&mut request_digest)?;

            // Verify that digest of keys match
            if cfi_launder(request_digest) != fuse_digest {
                env.soc_ifc.finish_ss_dbg_unluck(false);
                txn.set_uc_tap_unlock(false);
                Err(CaliptraError::ROM_SS_DBG_UNLOCK_MANUF_INVALID_TOKEN)?;
            } else {
                caliptra_cfi_lib::cfi_assert_eq_12_words(
                    &request_digest.0[..12].try_into().unwrap(),
                    &fuse_digest.0[..12].try_into().unwrap(),
                );
            }

            // Verify that the challenge is properly signed by the keys
            let pubkey = Ecc384PubKey {
                x: Ecc384Scalar::from(<[u8; 48]>::try_from(&request.ecc_public_key[..48]).unwrap()),
                y: Ecc384Scalar::from(<[u8; 48]>::try_from(&request.ecc_public_key[48..]).unwrap()),
            };
            let signature = Ecc384Signature {
                r: Ecc384Scalar::from(<[u8; 48]>::try_from(&request.ecc_signature[..48]).unwrap()),
                s: Ecc384Scalar::from(<[u8; 48]>::try_from(&request.ecc_signature[48..]).unwrap()),
            };
            let mut digest_op = env.sha2_512_384.sha384_digest_init()?;
            digest_op.update(&request.challenge)?;
            digest_op.update(&request.unique_device_identifier)?;
            digest_op.update(&request.unlock_category)?;
            let mut ecc_msg = Array4x12::default();
            digest_op.finalize(&mut ecc_msg)?;
            let result = env.ecc384.verify(&pubkey, &ecc_msg, &signature)?;
            if result == Ecc384Result::SigVerifyFailed {
                env.soc_ifc.finish_ss_dbg_unluck(false);
                txn.set_uc_tap_unlock(false);
                Err(CaliptraError::ROM_SS_DBG_UNLOCK_MANUF_INVALID_TOKEN)?;
            }

            let mut digest_op = env.sha2_512_384.sha512_digest_init()?;
            digest_op.update(&request.challenge)?;
            digest_op.update(&request.unique_device_identifier)?;
            digest_op.update(&request.unlock_category)?;
            let mut mldsa_msg = Array4x16::default();
            digest_op.finalize(&mut mldsa_msg)?;

            let result = env.mldsa87.verify(
                &Mldsa87PubKey::from(&request.mldsa_public_key),
                &mldsa_msg,
                &Mldsa87Signature::from(&request.mldsa_signature),
            )?;

            if result == Mldsa87Result::SigVerifyFailed {
                Err(CaliptraError::ROM_SS_DBG_UNLOCK_MANUF_INVALID_TOKEN)?;
            }
            Ok(())
        })();

        env.soc_ifc.set_ss_dbg_unlock_in_progress(false);

        match result {
            Ok(()) => {
                env.soc_ifc.finish_ss_dbg_unluck(true);
                txn.set_uc_tap_unlock(true);
                let resp = MailboxRespHeader::default();
                txn.send_response(resp.as_bytes())?;
            }
            Err(_) => {
                env.soc_ifc.finish_ss_dbg_unluck(false);
                txn.set_uc_tap_unlock(false);
            }
        }
        result
    }
}
