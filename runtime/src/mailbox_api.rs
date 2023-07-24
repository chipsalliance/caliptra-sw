// Licensed under the Apache-2.0 license

use caliptra_drivers::{CaliptraError, CaliptraResult};
use zerocopy::{AsBytes, FromBytes, LayoutVerified};

#[derive(PartialEq, Eq)]
pub struct CommandId(pub u32);

impl CommandId {
    pub const FIRMWARE_LOAD: Self = Self(0x46574C44); // "FWLD"
    pub const GET_IDEV_CSR: Self = Self(0x49444556); // "IDEV"
    pub const GET_LDEV_CERT: Self = Self(0x4C444556); // "LDEV"
    pub const ECDSA384_VERIFY: Self = Self(0x53494756); // "SIGV"
    pub const STASH_MEASUREMENT: Self = Self(0x4D454153); // "MEAS"
    pub const INVOKE_DPE: Self = Self(0x44504543); // "DPEC"

    pub const TEST_ONLY_GET_LDEV_CERT: Self = Self(0x4345524c); // "CERL"
    pub const TEST_ONLY_GET_FMC_ALIAS_CERT: Self = Self(0x43455246); // "CERF"

    /// FIPS module commands.
    /// The status command.
    pub const VERSION: Self = Self(0x4650_5652); // "FPVR"
    /// The self-test command.
    pub const SELF_TEST: Self = Self(0x4650_4C54); // "FPST"
    /// The shutdown command.
    pub const SHUTDOWN: Self = Self(0x4650_5344); // "FPSD"
}
impl From<u32> for CommandId {
    fn from(value: u32) -> Self {
        Self(value)
    }
}
impl From<CommandId> for u32 {
    fn from(value: CommandId) -> Self {
        value.0
    }
}

// Helpers
// Assumes given byte array is >= size_of T
// Will return CaliptraError::RUNTIME_INTERNAL otherwise
pub fn cast_bytes_to_struct<T: AsBytes + FromBytes>(bytes: &[u8]) -> CaliptraResult<&T> {
    Ok(
        LayoutVerified::<&[u8], T>::new(&bytes[..core::mem::size_of::<T>()])
        .ok_or(CaliptraError::RUNTIME_INTERNAL)?
        .into_ref()
    )
}
pub fn cast_bytes_to_struct_mut<T: AsBytes + FromBytes>(bytes: &mut [u8]) -> CaliptraResult<&mut T> {
    Ok(
        LayoutVerified::<&mut [u8], T>::new(&mut bytes[..core::mem::size_of::<T>()])
        .ok_or(CaliptraError::RUNTIME_INTERNAL)?
        .into_mut()
    )
}

// COMMON
#[repr(C)]
#[derive(AsBytes, FromBytes)]
pub struct MailboxReqCommon {
    pub chksum: i32,
}

#[repr(C)]
#[derive(AsBytes, FromBytes)]
pub struct MailboxRespCommon {
    pub chksum: i32,
    pub fips_status: u32,
}

pub const FIPS_STATUS_APPROVED: u32 = 0;

// CALIPTRA_FW_LOAD
#[repr(C)]
#[derive(AsBytes, FromBytes)]
pub struct CaliptraFwLoadReq {
    pub common: MailboxReqCommon,
    pub data: [u8; 0], // variable length
}
// No command-specific output args

// GET_IDEV_CSR
// No command-specific input args
#[repr(C)]
#[derive(AsBytes, FromBytes)]
pub struct GetIdevCsrResp {
    pub common: MailboxRespCommon,
    pub data: [u8; 0], // variable length
}

// GET_LDEV_CERT
// No command-specific input args
#[repr(C)]
#[derive(AsBytes, FromBytes)]
pub struct GetLdevCsrResp {
    pub common: MailboxRespCommon,
    pub data: [u8; 0], // variable length
}

// ECDSA384_SIGNATURE_VERIFY
#[repr(C)]
#[derive(AsBytes, FromBytes)]
pub struct EcdsaVerifyCmdReq {
    pub common: MailboxReqCommon,
    pub pub_key_x: [u8; 48],
    pub pub_key_y: [u8; 48],
    pub signature_r: [u8; 48],
    pub signature_s: [u8; 48],
}
// No command-specific output args

// STASH_MEASUREMENT
#[repr(C)]
#[derive(AsBytes, FromBytes)]
pub struct StashMeasurementReq {
    pub common: MailboxReqCommon,
    pub metadata: [u8; 4],
    pub measurement: [u8; 48],
}

#[repr(C)]
#[derive(AsBytes, FromBytes)]
pub struct StashMeasurementResp {
    pub common: MailboxRespCommon,
    pub dpe_result: u32,
}

// DISABLE_ATTESTATION
// No command-specific input args
// No command-specific output args

// INVOKE_DPE_COMMAND
#[repr(C)]
#[derive(AsBytes, FromBytes)]
pub struct InvokeDpeCommandReq {
    pub common: MailboxReqCommon,
    pub data: [u8; 0], // variable length
}

#[repr(C)]
#[derive(AsBytes, FromBytes)]
pub struct InvokeDpeCommandResp {
    pub common: MailboxRespCommon,
    pub data: [u8; 0], // variable length
}


