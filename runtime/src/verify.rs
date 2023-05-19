// Licensed under the Apache-2.0 license

use crate::{EcdsaVerifyCmd, RuntimeErr};
use caliptra_drivers::{
    Array4x12, CaliptraResult, Ecc384, Ecc384PubKey, Ecc384Scalar, Ecc384Signature,
};
use caliptra_registers::{ecc::EccReg, sha512_acc};
use zerocopy::FromBytes;

/// Handle the `ECDSA384_SIGNATURE_VERIFY` mailbox command
pub fn handle_ecdsa_verify(cmd_args: &[u8]) -> CaliptraResult<()> {
    if let Some(cmd) = EcdsaVerifyCmd::read_from(cmd_args) {
        let sha_acc = sha512_acc::RegisterBlock::sha512_acc_csr();

        // Won't panic, full_digest is always larger than digest
        let full_digest = sha_acc.digest().read();
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

        // TODO: Don't do this
        let mut ecdsa = unsafe { Ecc384::new(EccReg::new()) };
        let success = ecdsa.verify(&pubkey, &digest, &sig)?;
        if !success {
            return Err(RuntimeErr::EcdsaVerificationFailed.into());
        }
    } else {
        return Err(RuntimeErr::InsufficientMemory.into());
    };

    Ok(())
}
