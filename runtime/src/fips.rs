// Licensed under the Apache-2.0 license

use caliptra_common::cprintln;
use caliptra_drivers::CaliptraError;
use caliptra_drivers::CaliptraResult;
use caliptra_kat::{Ecc384Kat, Hmac384Kat, Sha256Kat, Sha384AccKat, Sha384Kat};
use caliptra_registers::mbox::enums::MboxStatusE;

use crate::{Drivers, MailboxResp, MailboxRespHeader, FipsVersionResp};

impl FipsVersionResp {
    pub fn new() -> Self {
        Self {
            hdr: MailboxRespHeader::default(),
            mode: Self::MODE,
            // Just return all zeroes for now.
            fips_rev: [1, 0, 0],
            name: Self::NAME,
        }
    }
}

pub struct FipsModule;

/// Fips command handler.
impl FipsModule {
    pub fn version(_env: &Drivers) -> CaliptraResult<MailboxResp> {
        cprintln!("[rt] FIPS Version");

        Ok(MailboxResp::FipsVersion(FipsVersionResp::new()))
    }

    pub fn self_test(env: &mut Drivers) -> CaliptraResult<MailboxResp> {
        cprintln!("[rt] FIPS self test");
        Self::execute_kats(env)?;

        Ok(MailboxResp::default())
    }

    pub fn shutdown(env: &mut Drivers) -> CaliptraResult<MailboxResp> {
        Self::zeroize(env);
        env.mbox.set_status(MboxStatusE::CmdComplete);

        Err(CaliptraError::RUNTIME_SHUTDOWN)
    }

    /// Clear data structures in DCCM.  
    fn zeroize(env: &mut Drivers) {
        env.regions.zeroize();
    }

    /// Execute KAT for cryptographic algorithms implemented in H/W.
    fn execute_kats(env: &mut Drivers) -> CaliptraResult<()> {
        cprintln!("[kat] Executing SHA2-256 Engine KAT");
        Sha256Kat::default().execute(&mut env.sha256)?;

        cprintln!("[kat] Executing SHA2-384 Engine KAT");
        Sha384Kat::default().execute(&mut env.sha384)?;

        cprintln!("[kat] Executing SHA2-384 Accelerator KAT");
        Sha384AccKat::default().execute(&mut env.sha384_acc)?;

        cprintln!("[kat] Executing ECC-384 Engine KAT");
        Ecc384Kat::default().execute(&mut env.ecc384, &mut env.trng)?;

        cprintln!("[kat] Executing HMAC-384 Engine KAT");
        Hmac384Kat::default().execute(&mut env.hmac384, &mut env.trng)?;

        Ok(())
    }
}
