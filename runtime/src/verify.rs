// Licensed under the Apache-2.0 license

use crate::Drivers;
#[cfg(feature = "test_only_commands")]
use caliptra_common::mailbox_api::HmacVerifyReq;
use caliptra_common::mailbox_api::{EcdsaVerifyReq, MailboxResp};
use caliptra_drivers::{
    Array4x12, CaliptraError, CaliptraResult, Ecc384PubKey, Ecc384Result, Ecc384Scalar,
    Ecc384Signature,
};

#[cfg(feature = "test_only_commands")]
use caliptra_drivers::{Hmac384Data, Hmac384Key, Trng};
#[cfg(feature = "test_only_commands")]
use caliptra_registers::{
    csrng::CsrngReg, entropy_src::EntropySrcReg, soc_ifc::SocIfcReg, soc_ifc_trng::SocIfcTrngReg,
};
use zerocopy::FromBytes;

pub struct EcdsaVerifyCmd;
impl EcdsaVerifyCmd {
    pub(crate) fn execute(drivers: &mut Drivers, cmd_args: &[u8]) -> CaliptraResult<MailboxResp> {
        if let Some(cmd) = EcdsaVerifyReq::read_from(cmd_args) {
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
        } else {
            return Err(CaliptraError::RUNTIME_INSUFFICIENT_MEMORY);
        };

        Ok(MailboxResp::default())
    }
}

/// Handle the `TEST_ONLY_HMAC_SHA384_VERIFY` mailbox command
#[cfg(feature = "test_only_commands")]
pub struct HmacVerifyCmd;
#[cfg(feature = "test_only_commands")]
impl HmacVerifyCmd {
    #[cfg(feature = "test_only_commands")]
    pub(crate) fn execute(drivers: &mut Drivers, cmd_args: &[u8]) -> CaliptraResult<MailboxResp> {
        if let Some(cmd) = HmacVerifyReq::read_from(cmd_args) {
            let key = Array4x12::from(cmd.key);
            let key = Hmac384Key::from(&key);
            let mut out_tag = Array4x12::default();
            let Ok(len) = usize::try_from(cmd.len) else {
                return Err(CaliptraError::RUNTIME_HMAC_VERIFY_FAILED);
            };
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
                .hmac384
                .hmac(&key, &data, &mut trng, (&mut out_tag).into())?;

            if out_tag != Array4x12::from(cmd.tag) {
                return Err(CaliptraError::RUNTIME_HMAC_VERIFY_FAILED);
            }
        } else {
            return Err(CaliptraError::RUNTIME_INSUFFICIENT_MEMORY);
        };

        Ok(MailboxResp::default())
    }
}
