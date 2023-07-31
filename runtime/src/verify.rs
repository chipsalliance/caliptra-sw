// Licensed under the Apache-2.0 license

use crate::{CommandId, Drivers, EcdsaVerifyCmd, HmacVerifyCmd};
use caliptra_drivers::{
    Array4x12, CaliptraError, CaliptraResult, Ecc384PubKey, Ecc384Result, Ecc384Scalar,
    Ecc384Signature, Hmac384Data, Hmac384Key, Trng,
};
use caliptra_registers::csrng::CsrngReg;
use caliptra_registers::entropy_src::EntropySrcReg;
use caliptra_registers::soc_ifc::SocIfcReg;
use caliptra_registers::soc_ifc_trng::SocIfcTrngReg;
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
        if success != Ecc384Result::Success {
            return Err(CaliptraError::RUNTIME_ECDSA_VERIFY_FAILED);
        }
    } else {
        return Err(CaliptraError::RUNTIME_INSUFFICIENT_MEMORY);
    };

    Ok(())
}

/// Handle the `HMAC_SHA384_VERIFY` mailbox command
pub(crate) fn handle_hmac_verify(drivers: &mut Drivers, cmd_args: &[u8]) -> CaliptraResult<()> {
    if let Some(cmd) = HmacVerifyCmd::read_from(cmd_args) {
        if !caliptra_common::checksum::verify_checksum(
            cmd.chksum,
            CommandId::TEST_ONLY_HMAC384_VERIFY.into(),
            &cmd_args[PAYLOAD_OFFSET..],
        ) {
            return Err(CaliptraError::RUNTIME_INVALID_CHECKSUM);
        }
        let key = Array4x12::from(cmd.key);
        let key = Hmac384Key::from(&key);
        let mut out_tag = Array4x12::default();
        let len = usize::try_from(cmd.len).unwrap();
        if len > cmd.msg.len() {
            return Err(CaliptraError::RUNTIME_HMAC_VERIFY_FAILED);
        }
        let data = Hmac384Data::from(&cmd.msg[0..len]);
        let mut trng = unsafe {
            Trng::new(
                CsrngReg::new(),
                EntropySrcReg::new(),
                SocIfcTrngReg::new(),
                &SocIfcReg::new(),
            )
        }?;

        drivers
            .hmac
            .hmac(&key, &data, &mut trng, (&mut out_tag).into())?;

        if out_tag != Array4x12::from(cmd.tag) {
            return Err(CaliptraError::RUNTIME_HMAC_VERIFY_FAILED);
        }
    } else {
        return Err(CaliptraError::RUNTIME_INSUFFICIENT_MEMORY);
    };

    Ok(())
}
