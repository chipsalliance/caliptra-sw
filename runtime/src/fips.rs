// Licensed under the Apache-2.0 license
use caliptra_common::cprintln;
use caliptra_drivers::CaliptraError;
use caliptra_drivers::CaliptraResult;
use caliptra_registers::mbox::enums::MboxStatusE;

use crate::Drivers;

/// Fips command handler.
pub struct FipsModule;

impl FipsModule {
    pub fn version(_env: &Drivers) -> CaliptraResult<MboxStatusE> {
        cprintln!("[rt] FIPS Version");
        Err(CaliptraError::RUNTIME_FIPS_UNIMPLEMENTED)
    }

    pub fn self_test(_env: &Drivers) -> CaliptraResult<MboxStatusE> {
        cprintln!("[rt] FIPS self test");
        Err(CaliptraError::RUNTIME_FIPS_UNIMPLEMENTED)
    }

    pub fn shutdown(env: &mut Drivers) -> CaliptraResult<MboxStatusE> {
        Self::zeroize(env);
        env.mbox.set_status(MboxStatusE::CmdComplete);

        Err(CaliptraError::RUNTIME_SHUTDOWN)
    }

    /// Clear data structures in DCCM.  
    fn zeroize(env: &mut Drivers) {
        env.regions.zeroize();
    }
}
