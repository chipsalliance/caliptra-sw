/*++

Licensed under the Apache-2.0 license.

File Name:

    verify.rs

Abstract:

    File contains EcdsaVerify mailbox command and HmacVerify test-only mailbox command.

--*/

use crate::Drivers;
use caliptra_cfi_derive_git::cfi_impl_fn;
use caliptra_common::mailbox_api::LmsVerifyReq;
use caliptra_drivers::{CaliptraError, CaliptraResult, LmsResult};
use caliptra_lms_types::{
    LmotsAlgorithmType, LmotsSignature, LmsAlgorithmType, LmsPublicKey, LmsSignature,
};
use zerocopy::{BigEndian, FromBytes, LittleEndian, U32};

pub struct LmsVerifyCmd;
impl LmsVerifyCmd {
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    #[inline(never)]
    pub(crate) fn execute(drivers: &mut Drivers, cmd_args: &[u8]) -> CaliptraResult<usize> {
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

        let cmd = LmsVerifyReq::ref_from_bytes(cmd_args)
            .map_err(|_| CaliptraError::MBOX_PAYLOAD_INVALID_SIZE)?;

        let lms_pub_key: LmsPublicKey<LMS_N> = LmsPublicKey {
            id: cmd.pub_key_id,
            digest: <[U32<LittleEndian>; LMS_N]>::read_from_bytes(&cmd.pub_key_digest[..])
                .map_err(|_| CaliptraError::MBOX_PAYLOAD_INVALID_SIZE)?,
            tree_type: LmsAlgorithmType::new(cmd.pub_key_tree_type),
            otstype: LmotsAlgorithmType::new(cmd.pub_key_ots_type),
        };

        let lms_sig: LmsSignature<LMS_N, LMS_P, LMS_H> = LmsSignature {
            q: <U32<BigEndian>>::from(cmd.signature_q),
            ots: <LmotsSignature<LMS_N, LMS_P>>::read_from_bytes(&cmd.signature_ots[..])
                .map_err(|_| CaliptraError::MBOX_PAYLOAD_INVALID_SIZE)?,
            tree_type: LmsAlgorithmType::new(cmd.signature_tree_type),
            tree_path: <[[U32<LittleEndian>; LMS_N]; LMS_H]>::read_from_bytes(
                &cmd.signature_tree_path[..],
            )
            .map_err(|_| CaliptraError::MBOX_PAYLOAD_INVALID_SIZE)?,
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
            &cmd.hash,
            &lms_pub_key,
            &lms_sig,
        )?;
        if success != LmsResult::Success {
            return Err(CaliptraError::RUNTIME_LMS_VERIFY_FAILED);
        }

        Ok(0)
    }
}
