// Licensed under the Apache-2.0 license

use caliptra_common::cprintln;
use caliptra_common::mailbox_api::{FipsVersionResp, MailboxResp, MailboxRespHeader};
use caliptra_drivers::CaliptraError;
use caliptra_drivers::CaliptraResult;
use caliptra_drivers::Ecc384;
use caliptra_drivers::Hmac384;
use caliptra_drivers::KeyVault;
use caliptra_drivers::Sha256;
use caliptra_drivers::Sha384;
use caliptra_drivers::Sha384Acc;
use caliptra_registers::mbox::enums::MboxStatusE;

use crate::Drivers;

pub struct FipsModule;

/// Fips command handler.
impl FipsModule {
    /// Clear data structures in DCCM.
    fn zeroize(env: &mut Drivers) {
        unsafe {
            // Zeroize the crypto blocks.
            Ecc384::zeroize();
            Hmac384::zeroize();
            Sha256::zeroize();
            Sha384::zeroize();
            Sha384Acc::zeroize();

            // Zeroize the key vault.
            KeyVault::zeroize();

            // Lock the SHA Accelerator.
            Sha384Acc::lock();
        }
        env.persistent_data.get_mut().zeroize();
    }
}

pub struct FipsVersionCmd;
impl FipsVersionCmd {
    pub const NAME: [u8; 12] = *b"Caliptra RTM";
    pub const MODE: u32 = 0x46495053;

    pub(crate) fn execute(_env: &mut Drivers) -> CaliptraResult<MailboxResp> {
        cprintln!("[rt] FIPS Version");

        let resp = FipsVersionResp {
            hdr: MailboxRespHeader::default(),
            mode: Self::MODE,
            // Just return all zeroes for now.
            fips_rev: [1, 0, 0],
            name: Self::NAME,
        };

        Ok(MailboxResp::FipsVersion(resp))
    }
}
#[cfg(feature = "fips_self_test")]
pub mod fips_self_test_cmd {
    use super::*;

    pub(crate) fn execute(env: &mut Drivers) -> CaliptraResult<MailboxResp> {
        cprintln!("[rt] FIPS self test");
        execute_kats(env)?;

        Ok(MailboxResp::default())
    }

    /// Execute KAT for cryptographic algorithms implemented in H/W.
    fn execute_kats(env: &mut Drivers) -> CaliptraResult<()> {
        let mut kats_env = caliptra_kat::KatsEnv {
            // SHA1 Engine
            sha1: &mut env.sha1,

            // sha256
            sha256: &mut env.sha256,

            // SHA2-384 Engine
            sha384: &mut env.sha384,

            // SHA2-384 Accelerator
            sha384_acc: &mut env.sha384_acc,

            // Hmac384 Engine
            hmac384: &mut env.hmac384,

            /// Cryptographically Secure Random Number Generator
            trng: &mut env.trng,

            // LMS Engine
            lms: &mut env.lms,

            /// Ecc384 Engine
            ecc384: &mut env.ecc384,
        };

        caliptra_kat::execute_kat(&mut kats_env)?;
        Ok(())
    }
}

pub struct FipsShutdownCmd;
impl FipsShutdownCmd {
    pub(crate) fn execute(env: &mut Drivers) -> CaliptraResult<MailboxResp> {
        FipsModule::zeroize(env);
        env.mbox.set_status(MboxStatusE::CmdComplete);

        Err(CaliptraError::RUNTIME_SHUTDOWN)
    }
}
