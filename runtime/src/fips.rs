// Licensed under the Apache-2.0 license

use caliptra_drivers::CaliptraError;
use caliptra_drivers::CaliptraResult;
use core::convert::TryFrom;

use caliptra_drivers::KeyVault;
use caliptra_registers::mbox::enums::MboxStatusE;
/// FIPS module environment.
pub struct FipsEnv<'a> {
    pub key_vault: &'a mut KeyVault,
}

#[derive(PartialEq, Eq)]
pub struct FipsModuleApi(pub u32);

/// FIPS module commands.
impl FipsModuleApi {
    /// The status command.
    pub const VERSION: Self = Self(0x4650_5652); // "FPVR"
    /// The self-test command.
    pub const SELF_TEST: Self = Self(0x4650_4C54); // "FPST"
    /// The shutdown command.
    pub const SHUTDOWN: Self = Self(0x4650_5344); // "FPSD"
}

impl TryFrom<u32> for FipsModuleApi {
    type Error = CaliptraError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0x4650_5652 => Ok(Self::VERSION),   // "STAT"
            0x4650_4C54 => Ok(Self::SELF_TEST), // "SELF"
            0x4650_5344 => Ok(Self::SHUTDOWN),  // "SHDN"
            _ => Err(CaliptraError::RUNTIME_UNIMPLEMENTED_COMMAND),
        }
    }
}

/// Convert the FipsModuleApi to a u32.
impl From<FipsModuleApi> for u32 {
    fn from(api: FipsModuleApi) -> Self {
        api.0
    }
}

/// FIPS module trait.
pub trait FipsManagement {
    fn status(&self, fips_env: &FipsEnv) -> CaliptraResult<MboxStatusE>;
    fn self_test(&self, fips_env: &FipsEnv) -> CaliptraResult<MboxStatusE>;
    fn shutdown(&self, fips_env: &FipsEnv) -> CaliptraResult<MboxStatusE>;
}
