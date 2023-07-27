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

    // TODO: Remove this and merge with GET_LDEV_CERT once that is implemented
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

// Contains all the possible mailbox response structs
#[cfg_attr(test, derive(PartialEq, Debug, Eq))]
pub enum MailboxResp {
    Header(MailboxRespHeader),
    GetIdevCsr(GetIdevCsrResp),
    GetLdevCert(GetLdevCertResp),
    StashMeasurement(StashMeasurementResp),
    InvokeDpeCommand(InvokeDpeCommandResp),
    TestGetFmcAliasCert(TestGetFmcAliasCertResp),
    FipsVersion(FipsVersionResp),
}

impl MailboxResp {
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            MailboxResp::Header(resp) => resp.as_bytes(),
            MailboxResp::GetIdevCsr(resp) => resp.as_bytes(),
            MailboxResp::GetLdevCert(resp) => resp.as_bytes(),
            MailboxResp::StashMeasurement(resp) => resp.as_bytes(),
            MailboxResp::InvokeDpeCommand(resp) => resp.as_bytes(),
            MailboxResp::TestGetFmcAliasCert(resp) => resp.as_bytes(),
            MailboxResp::FipsVersion(resp) => resp.as_bytes(),
        }
    }

    pub fn as_bytes_mut(&mut self) -> &mut [u8] {
        match self {
            MailboxResp::Header(resp) => resp.as_bytes_mut(),
            MailboxResp::GetIdevCsr(resp) => resp.as_bytes_mut(),
            MailboxResp::GetLdevCert(resp) => resp.as_bytes_mut(),
            MailboxResp::StashMeasurement(resp) => resp.as_bytes_mut(),
            MailboxResp::InvokeDpeCommand(resp) => resp.as_bytes_mut(),
            MailboxResp::TestGetFmcAliasCert(resp) => resp.as_bytes_mut(),
            MailboxResp::FipsVersion(resp) => resp.as_bytes_mut(),
        }
    }

    /// Calculate and set the checksum for a response payload
    /// Takes into account the size override for variable-lenth payloads
    pub fn populate_chksum(&mut self) -> CaliptraResult<()> {
        // Calc checksum, use the size override if provided
        let checksum = caliptra_common::checksum::calc_checksum(0, &self.as_bytes()[4..]);

        // cast as header struct
        let hdr: &mut MailboxRespHeader =
            LayoutVerified::<&mut [u8], MailboxRespHeader>::new(&mut self.as_bytes_mut()[..core::mem::size_of::<MailboxRespHeader>()])
            .ok_or(CaliptraError::RUNTIME_INSUFFICIENT_MEMORY)?
            .into_mut();

        // Set the chksum field
        hdr.chksum = checksum;

        Ok(())
    }
}

impl Default for MailboxResp {
    fn default() -> Self {
        MailboxResp::Header(MailboxRespHeader::default())
    }
}

// HEADER
#[repr(C)]
#[derive(Debug, AsBytes, FromBytes, PartialEq, Eq)]
pub struct MailboxReqHeader {
    pub chksum: i32,
}

#[repr(C)]
#[derive(Debug, AsBytes, FromBytes, PartialEq, Eq)]
pub struct MailboxRespHeader {
    pub chksum: i32,
    pub fips_status: u32,
}

impl MailboxRespHeader {
    pub const FIPS_STATUS_APPROVED: u32 = 0;
}

impl Default for MailboxRespHeader {
    fn default() -> Self {
        Self {
            chksum: 0,
            fips_status: MailboxRespHeader::FIPS_STATUS_APPROVED,
        }
    }
}

// GET_IDEV_CSR
// No command-specific input args
#[repr(C)]
#[derive(Debug, AsBytes, FromBytes, PartialEq, Eq)]
pub struct GetIdevCsrResp {
    pub hdr: MailboxRespHeader,
    pub data_size: u32,
    pub data: [u8; GetIdevCsrResp::DATA_MAX_SIZE], // variable length
}
impl GetIdevCsrResp {
    pub const DATA_MAX_SIZE: usize = 1024;
}

// GET_LDEV_CERT
// No command-specific input args
#[repr(C)]
#[derive(Debug, AsBytes, FromBytes, PartialEq, Eq)]
pub struct GetLdevCertResp {
    pub hdr: MailboxRespHeader,
    pub data_size: u32,
    pub data: [u8; GetLdevCertResp::DATA_MAX_SIZE], // variable length
}
impl GetLdevCertResp {
    pub const DATA_MAX_SIZE: usize = 1024;
}

// ECDSA384_SIGNATURE_VERIFY
#[repr(C)]
#[derive(Debug, AsBytes, FromBytes, PartialEq, Eq)]
pub struct EcdsaVerifyCmdReq {
    pub hdr: MailboxReqHeader,
    pub pub_key_x: [u8; 48],
    pub pub_key_y: [u8; 48],
    pub signature_r: [u8; 48],
    pub signature_s: [u8; 48],
}
// No command-specific output args

// STASH_MEASUREMENT
#[repr(C)]
#[derive(Debug, AsBytes, FromBytes, PartialEq, Eq)]
pub struct StashMeasurementReq {
    pub hdr: MailboxReqHeader,
    pub metadata: [u8; 4],
    pub measurement: [u8; 48],
}

#[repr(C)]
#[derive(Debug, AsBytes, FromBytes, PartialEq, Eq)]
pub struct StashMeasurementResp {
    pub hdr: MailboxRespHeader,
    pub dpe_result: u32,
}

// DISABLE_ATTESTATION
// No command-specific input args
// No command-specific output args

// INVOKE_DPE_COMMAND
#[repr(C)]
#[derive(Debug, AsBytes, FromBytes, PartialEq, Eq)]
pub struct InvokeDpeCommandReq {
    pub hdr: MailboxReqHeader,
    pub data_size: u32,
    pub data: [u8; InvokeDpeCommandReq::DATA_MAX_SIZE], // variable length
}
impl InvokeDpeCommandReq {
    pub const DATA_MAX_SIZE: usize = 1024;
}

#[repr(C)]
#[derive(Debug, AsBytes, FromBytes, PartialEq, Eq)]
pub struct InvokeDpeCommandResp {
    pub hdr: MailboxRespHeader,
    pub data_size: u32,
    pub data: [u8; InvokeDpeCommandResp::DATA_MAX_SIZE], // variable length
}
impl InvokeDpeCommandResp {
    pub const DATA_MAX_SIZE: usize = 1024;
}

// TEST_ONLY_GET_FMC_ALIAS_CERT
// No command-specific input args
#[repr(C)]
#[derive(Debug, AsBytes, FromBytes, PartialEq, Eq)]
pub struct TestGetFmcAliasCertResp {
    pub hdr: MailboxRespHeader,
    pub data_size: u32,
    pub data: [u8; TestGetFmcAliasCertResp::DATA_MAX_SIZE], // variable length
}
impl TestGetFmcAliasCertResp {
    pub const DATA_MAX_SIZE: usize = 1024;
}

// FIPS_GET_VERSION
// No command-specific input args
#[repr(C)]
#[derive(Debug, AsBytes, FromBytes, PartialEq, Eq)]
pub struct FipsVersionResp {
    pub hdr: MailboxRespHeader,
    pub mode: u32,
    pub fips_rev: [u32; 3],
    pub name: [u8; 12],
}

impl FipsVersionResp {
    pub const NAME: [u8; 12] = *b"Caliptra RTM";
    pub const MODE: u32 = 0x46495053;
}