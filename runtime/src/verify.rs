/*++

Licensed under the Apache-2.0 license.

File Name:

    verify.rs

Abstract:

    File contains EcdsaVerify mailbox command and HmacVerify test-only mailbox command.

--*/

use crate::Drivers;
use caliptra_cfi_derive::cfi_impl_fn;
use caliptra_common::mailbox_api::LmsVerifyReq;
use caliptra_drivers::{CaliptraError, CaliptraResult, LmsResult};
use caliptra_lms_types::{
    LmotsAlgorithmType, LmotsSignature, LmsAlgorithmType, LmsPublicKey, LmsSignature,
};
use zerocopy::{BigEndian, FromBytes, LittleEndian, U32};

pub struct LmsVerifyCmd;
impl LmsVerifyCmd {
    #[cfg_attr(feature = "cfi", cfi_impl_fn)]
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
            .map_err(|_| CaliptraError::RUNTIME_INSUFFICIENT_MEMORY)?;

        // Somehow doing a memcopy of 24 bytes results in unaligned access on the mbox SRAM MMIO
        // Avoid this doing manual u32 reads
        let digest = cmd.pub_key_digest.chunks_exact(4).enumerate().fold(
            [U32::<LittleEndian>::new(0); LMS_N],
            |mut acc, (i, chunk)| {
                let dword = u32::from_le_bytes(chunk.try_into().unwrap());
                acc[i] = U32::<LittleEndian>::from(dword);
                acc
            },
        );

        let lms_pub_key: LmsPublicKey<LMS_N> = LmsPublicKey {
            id: cmd.pub_key_id,
            digest,
            tree_type: LmsAlgorithmType::new(cmd.pub_key_tree_type),
            otstype: LmotsAlgorithmType::new(cmd.pub_key_ots_type),
        };

        // Somehow doing a memcopy of 360 bytes results in unaligned access on the mbox SRAM MMIO
        // Avoid this doing manual u32 reads
        let tree_path = cmd.signature_tree_path.chunks_exact(4).enumerate().fold(
            [[U32::<LittleEndian>::new(0); LMS_N]; LMS_H],
            |mut acc, (i, chunk)| {
                let h = i / LMS_N;
                let n = i % LMS_N;
                let dword = u32::from_le_bytes(chunk.try_into().unwrap());
                acc[h][n] = U32::<LittleEndian>::new(dword);
                acc
            },
        );

        // Somehow doing a memcopy of 1252 bytes results in unaligned access on the mbox SRAM MMIO
        // Avoid this doing manual u32 reads
        let ots_buf = cmd.signature_ots.chunks_exact(4).enumerate().fold(
            [0u8; size_of::<LmotsSignature<LMS_N, LMS_P>>()],
            |mut acc, (i, chunk)| {
                let offset = i * 4;
                acc[offset..offset + 4].copy_from_slice(chunk);
                acc
            },
        );
        let ots = <LmotsSignature<LMS_N, LMS_P>>::read_from_bytes(&ots_buf[..])
            .map_err(|_| CaliptraError::RUNTIME_INSUFFICIENT_MEMORY)?;

        let lms_sig: LmsSignature<LMS_N, LMS_P, LMS_H> = LmsSignature {
            q: <U32<BigEndian>>::from(cmd.signature_q),
            ots,
            tree_type: LmsAlgorithmType::new(cmd.signature_tree_type),
            tree_path,
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
