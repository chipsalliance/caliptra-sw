// Licensed under the Apache-2.0 license

use crate::{CommandId, Drivers, EcdsaVerifyCmd};
use caliptra_drivers::{
    Array4x12, CaliptraError, CaliptraResult, Ecc384PubKey, Ecc384Scalar, Ecc384Signature,
};
use zerocopy::FromBytes;

/// Start of payload (skips checksum field).
const PAYLOAD_OFFSET: usize = 4;

/// Handle the `ECDSA384_SIGNATURE_VERIFY` mailbox command
pub(crate) fn handle_ecdsa_verify(drivers: &mut Drivers, cmd_args: &[u8]) -> CaliptraResult<()> {
    if let Some(cmd) = EcdsaVerifyCmd::read_from(cmd_args) {
        if !caliptra_common::checksum::verify_checksum(
            cmd.chksum,
            CommandId::ECDSA384_VERIFY.into(),
            &cmd_args[PAYLOAD_OFFSET..],
        ) {
            return Err(CaliptraError::RUNTIME_INVALID_CHECKSUM);
        }
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

        let success = drivers.ecdsa.verify(&pubkey, &digest, &sig)?;
        if !success {
            return Err(CaliptraError::RUNTIME_ECDSA_VERIF_FAILED);
        }
    } else {
        return Err(CaliptraError::RUNTIME_INSUFFICIENT_MEMORY);
    };

    Ok(())
}
