/*++

Licensed under the Apache-2.0 license.

File Name:

    verify.rs

Abstract:

    File contains EcdsaVerify mailbox command and HmacVerify test-only mailbox command.

--*/

use crate::Drivers;
use caliptra_cfi_derive_git::cfi_impl_fn;
use caliptra_common::mailbox_api::{EcdsaVerifyReq, LmsVerifyReq, MailboxResp};
use caliptra_drivers::{
    Array4x12, CaliptraError, CaliptraResult, Ecc384PubKey, Ecc384Result, Ecc384Scalar,
    Ecc384Signature, LmsResult,
};
use caliptra_lms_types::{
    LmotsAlgorithmType, LmotsSignature, LmsAlgorithmType, LmsPublicKey, LmsSignature,
};
use zerocopy::{BigEndian, FromBytes, LittleEndian, U32};

pub struct EcdsaVerifyCmd;
impl EcdsaVerifyCmd {
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    #[inline(never)]
    pub(crate) fn execute(drivers: &mut Drivers, cmd_args: &[u8]) -> CaliptraResult<MailboxResp> {
        let cmd = EcdsaVerifyReq::read_from(cmd_args)
            .ok_or(CaliptraError::RUNTIME_INSUFFICIENT_MEMORY)?;
        // Won't panic, full_digest is always larger than digest
        let full_digest = drivers.sha_acc.regs().digest().read();
        let mut digest = Array4x12::default();
        for (i, target_word) in digest.0.iter_mut().enumerate() {
            *target_word = full_digest[i];
        }

        let pubkey = Ecc384PubKey {
            x: Ecc384Scalar::from(cmd.pub_key_x),
            y: Ecc384Scalar::from(cmd.pub_key_y),
        };

        let sig = Ecc384Signature {
            r: Ecc384Scalar::from(cmd.signature_r),
            s: Ecc384Scalar::from(cmd.signature_s),
        };

        let success = drivers.ecc384.verify(&pubkey, &digest, &sig)?;
        if success != Ecc384Result::Success {
            return Err(CaliptraError::RUNTIME_ECDSA_VERIFY_FAILED);
        }

        Ok(MailboxResp::default())
    }
}

pub struct LmsVerifyCmd;
impl LmsVerifyCmd {
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    #[inline(never)]
    pub(crate) fn execute(drivers: &mut Drivers, cmd_args: &[u8]) -> CaliptraResult<MailboxResp> {
        // Re-run LMS KAT once (since LMS is more SW-based than other crypto)
        if let Err(e) =
            caliptra_kat::LmsKat::default().execute_once(&mut drivers.sha256, &mut drivers.lms)
        {
            // KAT failures must be fatal errors
            caliptra_common::handle_fatal_error(e.into());
        }

        // Constants from fixed LMS param set
        const LMS_N: usize = 6;
        const LMS_P: usize = 51;
        const LMS_H: usize = 15;
        const LMS_ALGORITHM_TYPE: LmsAlgorithmType = LmsAlgorithmType::new(12);
        const LMOTS_ALGORITHM_TYPE: LmotsAlgorithmType = LmotsAlgorithmType::new(7);

        let cmd =
            LmsVerifyReq::read_from(cmd_args).ok_or(CaliptraError::RUNTIME_INSUFFICIENT_MEMORY)?;
        // Get the digest from the SHA accelerator
        let msg_digest_be = drivers.sha_acc.regs().digest().truncate::<12>().read();
        // Flip the endianness since LMS treats this as raw message bytes
        let mut msg_digest = [0u8; 48];
        for (i, src_word) in msg_digest_be.iter().enumerate() {
            msg_digest[i * 4..][..4].copy_from_slice(&src_word.to_be_bytes());
        }

        let lms_pub_key: LmsPublicKey<LMS_N> = LmsPublicKey {
            id: cmd.pub_key_id,
            digest: <[U32<LittleEndian>; LMS_N]>::read_from(&cmd.pub_key_digest[..])
                .ok_or(CaliptraError::RUNTIME_INSUFFICIENT_MEMORY)?,
            tree_type: LmsAlgorithmType::new(cmd.pub_key_tree_type),
            otstype: LmotsAlgorithmType::new(cmd.pub_key_ots_type),
        };

        let lms_sig: LmsSignature<LMS_N, LMS_P, LMS_H> = LmsSignature {
            q: <U32<BigEndian>>::from(cmd.signature_q),
            ots: <LmotsSignature<LMS_N, LMS_P>>::read_from(&cmd.signature_ots[..])
                .ok_or(CaliptraError::RUNTIME_INSUFFICIENT_MEMORY)?,
            tree_type: LmsAlgorithmType::new(cmd.signature_tree_type),
            tree_path: <[[U32<LittleEndian>; LMS_N]; LMS_H]>::read_from(
                &cmd.signature_tree_path[..],
            )
            .ok_or(CaliptraError::RUNTIME_INSUFFICIENT_MEMORY)?,
        };

        // Check that fixed params are correct
        if lms_pub_key.tree_type != LMS_ALGORITHM_TYPE {
            return Err(CaliptraError::RUNTIME_LMS_VERIFY_INVALID_LMS_ALGORITHM);
        }
        if lms_pub_key.otstype != LMOTS_ALGORITHM_TYPE {
            return Err(CaliptraError::RUNTIME_LMS_VERIFY_INVALID_LMOTS_ALGORITHM);
        }
        if lms_sig.tree_type != LMS_ALGORITHM_TYPE {
            return Err(CaliptraError::RUNTIME_LMS_VERIFY_INVALID_LMS_ALGORITHM);
        }

        let success = drivers.lms.verify_lms_signature(
            &mut drivers.sha256,
            &msg_digest,
            &lms_pub_key,
            &lms_sig,
        )?;
        if success != LmsResult::Success {
            return Err(CaliptraError::RUNTIME_LMS_VERIFY_FAILED);
        }

        Ok(MailboxResp::default())
    }
}
