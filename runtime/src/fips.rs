// Licensed under the Apache-2.0 license

use caliptra_common::cprintln;
use caliptra_drivers::CaliptraError;
use caliptra_drivers::CaliptraResult;
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

    pub fn self_test(_env: &Drivers) -> CaliptraResult<MailboxResp> {
        cprintln!("[rt] FIPS self test");
        Err(CaliptraError::RUNTIME_FIPS_UNIMPLEMENTED)
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
}
