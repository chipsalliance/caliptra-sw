// Licensed under the Apache-2.0 license

use caliptra_common::cprintln;
use caliptra_drivers::CaliptraError;
use caliptra_drivers::CaliptraResult;
use caliptra_registers::mbox::enums::MboxStatusE;
use zerocopy::{AsBytes, FromBytes};

use crate::Drivers;

pub struct FipsModule;

#[repr(C)]
#[derive(Clone, Debug, Default, AsBytes, FromBytes)]
pub struct VersionResponse {
    pub mode: u32,
    pub fips_rev: [u32; 3],
    pub name: [u8; 12],
}

impl VersionResponse {
    pub const NAME: [u8; 12] = *b"Caliptra RTM";
    pub const MODE: u32 = 0x46495053;

    pub fn new(_env: &Drivers) -> Self {
        Self {
            mode: Self::MODE,
            // Just return all zeroes for now.
            fips_rev: [1, 0, 0],
            name: Self::NAME,
        }
    }
    pub fn copy_to_mbox(&self, env: &mut Drivers) -> CaliptraResult<()> {
        let mbox = &mut env.mbox;
        mbox.write_response(self.as_bytes())
    }
}

/// Fips command handler.
impl FipsModule {
    pub fn version(env: &mut Drivers) -> CaliptraResult<MboxStatusE> {
        cprintln!("[rt] FIPS Version");

        VersionResponse::new(env).copy_to_mbox(env)?;
        Ok(MboxStatusE::DataReady)
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
