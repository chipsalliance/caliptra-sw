/*++

Licensed under the Apache-2.0 license.

File Name:

    verify.rs

Abstract:

    File contains EcdsaVerify mailbox command and HmacVerify test-only mailbox command.

--*/

use crate::packet::copy_from_mbox;
use crate::Drivers;
use caliptra_cfi_derive::cfi_impl_fn;
#[cfg(feature = "mldsa_attestation")]
use caliptra_common::mailbox_api::Mldsa87VerifyReq;
use caliptra_common::mailbox_api::{EcdsaVerifyReq, LmsVerifyReq, MailboxResp};
use caliptra_drivers::{
    Array4x12, CaliptraError, CaliptraResult, Ecc384PubKey, Ecc384Result, Ecc384Scalar,
    Ecc384Signature, LmsResult,
};
#[cfg(feature = "mldsa_attestation")]
use caliptra_drivers::{Mldsa87, Mldsa87PubKey, Mldsa87Result, Mldsa87Signature};
use caliptra_lms_types::{
    LmotsAlgorithmType, LmotsSignature, LmsAlgorithmType, LmsPublicKey, LmsSignature,
};
use zerocopy::{BigEndian, FromBytes, FromZeros, IntoBytes, LittleEndian, U32};

pub struct EcdsaVerifyCmd;
impl EcdsaVerifyCmd {
    #[cfg_attr(feature = "cfi", cfi_impl_fn)]
    #[inline(never)]
    pub(crate) fn execute(drivers: &mut Drivers) -> CaliptraResult<MailboxResp> {
        let mut cmd = EcdsaVerifyReq::new_zeroed();
        copy_from_mbox(drivers, cmd.as_mut_bytes())?;

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
    #[cfg_attr(feature = "cfi", cfi_impl_fn)]
    #[inline(never)]
    pub(crate) fn execute(drivers: &mut Drivers) -> CaliptraResult<MailboxResp> {
        let mut cmd = LmsVerifyReq::new_zeroed();
        copy_from_mbox(drivers, cmd.as_mut_bytes())?;

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

        // Get the digest from the SHA accelerator
        let msg_digest_be = drivers.sha_acc.regs().digest().truncate::<12>().read();
        // Flip the endianness since LMS treats this as raw message bytes
        let mut msg_digest = [0u8; 48];
        for (i, src_word) in msg_digest_be.iter().enumerate() {
            msg_digest[i * 4..][..4].copy_from_slice(&src_word.to_be_bytes());
        }

        let lms_pub_key: LmsPublicKey<LMS_N> = LmsPublicKey {
            id: cmd.pub_key_id,
            digest: <[U32<LittleEndian>; LMS_N]>::read_from_bytes(&cmd.pub_key_digest[..])
                .map_err(|_| CaliptraError::RUNTIME_INSUFFICIENT_MEMORY)?,
            tree_type: LmsAlgorithmType::new(cmd.pub_key_tree_type),
            otstype: LmotsAlgorithmType::new(cmd.pub_key_ots_type),
        };

        let lms_sig: LmsSignature<LMS_N, LMS_P, LMS_H> = LmsSignature {
            q: <U32<BigEndian>>::from(cmd.signature_q),
            ots: <LmotsSignature<LMS_N, LMS_P>>::read_from_bytes(&cmd.signature_ots[..])
                .map_err(|_| CaliptraError::RUNTIME_INSUFFICIENT_MEMORY)?,
            tree_type: LmsAlgorithmType::new(cmd.signature_tree_type),
            tree_path: <[[U32<LittleEndian>; LMS_N]; LMS_H]>::read_from_bytes(
                &cmd.signature_tree_path[..],
            )
            .map_err(|_| CaliptraError::RUNTIME_INSUFFICIENT_MEMORY)?,
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

#[cfg(feature = "mldsa_attestation")]
pub struct Mldsa87VerifyCmd;
#[cfg(feature = "mldsa_attestation")]
impl Mldsa87VerifyCmd {
    #[cfg_attr(feature = "cfi", cfi_impl_fn)]
    #[inline(never)]
    pub(crate) fn execute(drivers: &mut Drivers) -> CaliptraResult<MailboxResp> {
        let mut cmd = Mldsa87VerifyReq::new_zeroed();
        copy_from_mbox(drivers, cmd.as_mut_bytes())?;

        // Pull the SHA-384 digest from the SHA accelerator (same pattern as
        // ECDSA384_VERIFY and LMS_VERIFY). The caller is expected to have
        // streamed the message through the accelerator before dispatching
        // this command. Keeping the hashing inside the SHA accelerator
        // preserves the FIPS module boundary for this verify operation.
        let msg_digest_be = drivers.sha_acc.regs().digest().truncate::<12>().read();
        // The accelerator exposes the digest as big-endian u32 words; flip
        // them back to a raw byte stream so ML-DSA verifies against the
        // canonical SHA-384 byte ordering.
        let mut msg_digest = [0u8; 48];
        for (i, src_word) in msg_digest_be.iter().enumerate() {
            msg_digest[i * 4..][..4].copy_from_slice(&src_word.to_be_bytes());
        }

        let result = Mldsa87::verify(
            Mldsa87PubKey::ref_from_bytes(&cmd.pub_key)
                .map_err(|_| CaliptraError::RUNTIME_INSUFFICIENT_MEMORY)?,
            Mldsa87Signature::ref_from_bytes(&cmd.signature)
                .map_err(|_| CaliptraError::RUNTIME_INSUFFICIENT_MEMORY)?,
            &msg_digest,
        )?;
        if result != Mldsa87Result::Success {
            return Err(CaliptraError::RUNTIME_MLDSA87_VERIFY_FAILED);
        }

        Ok(MailboxResp::default())
    }
}
