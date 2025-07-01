/*++

Licensed under the Apache-2.0 license.

File Name:

    verify.rs

Abstract:

    File contains EcdsaVerify mailbox command.

--*/

use caliptra_api::mailbox::{EcdsaVerifyReq, MldsaVerifyReq};
use caliptra_cfi_derive_git::cfi_impl_fn;
use caliptra_drivers::{
    Array4x12, CaliptraError, CaliptraResult, Ecc384, Ecc384PubKey, Ecc384Result, Ecc384Scalar,
    Ecc384Signature, Mldsa87, Mldsa87PubKey, Mldsa87Result, Mldsa87Signature,
};
use zerocopy::FromBytes;

pub struct EcdsaVerifyCmd;
impl EcdsaVerifyCmd {
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    #[inline(never)]
    pub fn execute(ecc384: &mut Ecc384, cmd_args: &[u8]) -> CaliptraResult<usize> {
        let cmd = EcdsaVerifyReq::ref_from_bytes(cmd_args)
            .map_err(|_| CaliptraError::RUNTIME_INSUFFICIENT_MEMORY)?;
        let digest = Array4x12::from(cmd.hash);

        let pubkey = Ecc384PubKey {
            x: Ecc384Scalar::from(cmd.pub_key_x),
            y: Ecc384Scalar::from(cmd.pub_key_y),
        };

        let sig = Ecc384Signature {
            r: Ecc384Scalar::from(cmd.signature_r),
            s: Ecc384Scalar::from(cmd.signature_s),
        };

        let success = ecc384.verify(&pubkey, &digest, &sig)?;
        if success != Ecc384Result::Success {
            if cfg!(feature = "rom") {
                return Err(CaliptraError::ROM_ECDSA_VERIFY_FAILED);
            } else if cfg!(feature = "runtime") {
                return Err(CaliptraError::RUNTIME_ECDSA_VERIFY_FAILED);
            }
        }

        Ok(0)
    }
}

pub trait MailboxRawAccess {
    fn raw_mailbox_contents(&self) -> &[u8];
}

pub struct MldsaVerifyCmd;
impl MldsaVerifyCmd {
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    #[inline(never)]
    pub fn execute(mldsa87: &mut Mldsa87, mbox: &impl MailboxRawAccess) -> CaliptraResult<usize> {
        // To avoid placing Req on the stack do a rw zerocopy on the mailbox content
        // This is ok as we check the size of the input and message_size
        let mbox_raw = &mbox
            .raw_mailbox_contents()
            .get(..core::mem::size_of::<MldsaVerifyReq>())
            .ok_or(CaliptraError::RUNTIME_MAILBOX_API_REQUEST_DATA_LEN_TOO_LARGE)?;
        let cmd = MldsaVerifyReq::read_from_bytes(mbox_raw)
            .map_err(|_| CaliptraError::RUNTIME_MAILBOX_API_REQUEST_DATA_LEN_TOO_LARGE)?;

        let pubkey = Mldsa87PubKey::from(cmd.pub_key);
        let signature = Mldsa87Signature::from(cmd.signature);
        let message = cmd
            .message
            .get(..cmd.message_size as usize)
            .ok_or(CaliptraError::RUNTIME_INSUFFICIENT_MEMORY)?;

        let success = mldsa87.verify_var(&pubkey, message, &signature)?;
        if success != Mldsa87Result::Success {
            if cfg!(feature = "rom") {
                return Err(CaliptraError::ROM_MLDSA_VERIFY_FAILED);
            } else if cfg!(feature = "runtime") {
                return Err(CaliptraError::RUNTIME_MLDSA_VERIFY_FAILED);
            }
        }

        Ok(0)
    }
}
