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

    pub fn new(env: &Drivers) -> Self {
        let hw_rev: u32 = env.soc_ifc.regs().cptra_hw_rev_id().read();
        let fw_rev = env.soc_ifc.regs().cptra_fw_rev_id().read();

        let mut fips_rev: [u32; 3] = [0u32; 3];

        fips_rev[0] = hw_rev;
        fips_rev[1] = fw_rev[0];
        fips_rev[2] = fw_rev[1];

        Self {
            mode: Self::MODE,
            fips_rev,
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

    pub fn shutdown(_env: &Drivers) -> CaliptraResult<MboxStatusE> {
        cprintln!("[rt] FIPS shutdown");
        Err(CaliptraError::RUNTIME_FIPS_UNIMPLEMENTED)
    }
}
