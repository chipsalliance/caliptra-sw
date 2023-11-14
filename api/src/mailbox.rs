// Licensed under the Apache-2.0 license

use caliptra_error::{CaliptraError, CaliptraResult};
use core::mem::size_of;
use zerocopy::{AsBytes, FromBytes, LayoutVerified};

#[derive(PartialEq, Eq)]
pub struct CommandId(pub u32);
impl CommandId {
    pub const FIRMWARE_LOAD: Self = Self(0x46574C44); // "FWLD"
    pub const GET_IDEV_CSR: Self = Self(0x49444556); // "IDEV"
    pub const GET_IDEV_CERT: Self = Self(0x49444543); // IDEC
    pub const GET_IDEV_INFO: Self = Self(0x49444549); // IDEI
    pub const POPULATE_IDEV_CERT: Self = Self(0x49444550); // IDEP
    pub const GET_LDEV_CERT: Self = Self(0x4C444556); // "LDEV"
    pub const ECDSA384_VERIFY: Self = Self(0x53494756); // "SIGV"
    pub const STASH_MEASUREMENT: Self = Self(0x4D454153); // "MEAS"
    pub const INVOKE_DPE: Self = Self(0x44504543); // "DPEC"
    pub const DISABLE_ATTESTATION: Self = Self(0x4453424C); // "DSBL"
    pub const FW_INFO: Self = Self(0x494E464F); // "INFO"

    // TODO: Remove this and merge with GET_LDEV_CERT once that is implemented
    pub const TEST_ONLY_GET_LDEV_CERT: Self = Self(0x4345524c); // "CERL"
    pub const TEST_ONLY_GET_FMC_ALIAS_CERT: Self = Self(0x43455246); // "CERF"
    pub const TEST_ONLY_HMAC384_VERIFY: Self = Self(0x484D4143); // "HMAC"

    /// FIPS module commands.
    /// The status command.
    pub const VERSION: Self = Self(0x4650_5652); // "FPVR"
    /// The self-test command.
    pub const SELF_TEST_START: Self = Self(0x4650_4C54); // "FPST"
    /// The self-test get results.
    pub const SELF_TEST_GET_RESULTS: Self = Self(0x4650_4C67); // "FPGR"
    /// The shutdown command.
    pub const SHUTDOWN: Self = Self(0x4650_5344); // "FPSD"

    // The capabilities command.
    pub const CAPABILITIES: Self = Self(0x4341_5053); // "CAPS"
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

/// A trait implemented by request types. Describes the associated command ID
/// and response type.
pub trait Request: AsBytes + FromBytes {
    const ID: CommandId;
    type Resp: FromBytes;
}

// Contains all the possible mailbox response structs
#[cfg_attr(test, derive(PartialEq, Debug, Eq))]
#[allow(clippy::large_enum_variant)]
pub enum MailboxResp {
    Header(MailboxRespHeader),
    GetIdevCert(GetIdevCertResp),
    GetIdevCsr(GetIdevCsrResp),
    GetIdevInfo(GetIdevInfoResp),
    GetLdevCert(GetLdevCertResp),
    StashMeasurement(StashMeasurementResp),
    InvokeDpeCommand(InvokeDpeResp),
    TestGetFmcAliasCert(TestGetFmcAliasCertResp),
    FipsVersion(FipsVersionResp),
    FwInfo(FwInfoResp),
    Capabilities(CapabilitiesResp),
}

impl MailboxResp {
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            MailboxResp::Header(resp) => resp.as_bytes(),
            MailboxResp::GetIdevCert(resp) => resp.as_bytes(),
            MailboxResp::GetIdevCsr(resp) => resp.as_bytes(),
            MailboxResp::GetIdevInfo(resp) => resp.as_bytes(),
            MailboxResp::GetLdevCert(resp) => resp.as_bytes(),
            MailboxResp::StashMeasurement(resp) => resp.as_bytes(),
            MailboxResp::InvokeDpeCommand(resp) => resp.as_bytes_partial(),
            MailboxResp::TestGetFmcAliasCert(resp) => resp.as_bytes(),
            MailboxResp::FipsVersion(resp) => resp.as_bytes(),
            MailboxResp::FwInfo(resp) => resp.as_bytes(),
            MailboxResp::Capabilities(resp) => resp.as_bytes(),
        }
    }

    pub fn as_bytes_mut(&mut self) -> &mut [u8] {
        match self {
            MailboxResp::Header(resp) => resp.as_bytes_mut(),
            MailboxResp::GetIdevCert(resp) => resp.as_bytes_mut(),
            MailboxResp::GetIdevCsr(resp) => resp.as_bytes_mut(),
            MailboxResp::GetIdevInfo(resp) => resp.as_bytes_mut(),
            MailboxResp::GetLdevCert(resp) => resp.as_bytes_mut(),
            MailboxResp::StashMeasurement(resp) => resp.as_bytes_mut(),
            MailboxResp::InvokeDpeCommand(resp) => resp.as_bytes_partial_mut(),
            MailboxResp::TestGetFmcAliasCert(resp) => resp.as_bytes_mut(),
            MailboxResp::FipsVersion(resp) => resp.as_bytes_mut(),
            MailboxResp::FwInfo(resp) => resp.as_bytes_mut(),
            MailboxResp::Capabilities(resp) => resp.as_bytes_mut(),
        }
    }

    /// Calculate and set the checksum for a response payload
    /// Takes into account the size override for variable-lenth payloads
    pub fn populate_chksum(&mut self) -> CaliptraResult<()> {
        // Calc checksum, use the size override if provided
        let checksum = crate::checksum::calc_checksum(0, &self.as_bytes()[size_of::<i32>()..]);

        // cast as header struct
        let hdr: &mut MailboxRespHeader = LayoutVerified::<&mut [u8], MailboxRespHeader>::new(
            &mut self.as_bytes_mut()[..size_of::<MailboxRespHeader>()],
        )
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

#[cfg_attr(test, derive(PartialEq, Debug, Eq))]
#[allow(clippy::large_enum_variant)]
pub enum MailboxReq {
    EcdsaVerify(EcdsaVerifyReq),
    GetIdevCsr(MailboxReqHeader),
    GetLdevCert(MailboxReqHeader),
    StashMeasurement(StashMeasurementReq),
    InvokeDpeCommand(InvokeDpeReq),
    FipsVersion(MailboxReqHeader),
    FwInfo(MailboxReqHeader),

    #[cfg(feature = "test_only_commands")]
    TestHmacVerify(HmacVerifyReq),
    #[cfg(feature = "test_only_commands")]
    TestGetFmcAliasCert(MailboxReqHeader),
}

impl MailboxReq {
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            MailboxReq::EcdsaVerify(req) => req.as_bytes(),
            MailboxReq::StashMeasurement(req) => req.as_bytes(),
            MailboxReq::InvokeDpeCommand(req) => req.as_bytes(),
            MailboxReq::FipsVersion(req) => req.as_bytes(),
            MailboxReq::FwInfo(req) => req.as_bytes(),
            MailboxReq::GetIdevCsr(req) => req.as_bytes(),
            MailboxReq::GetLdevCert(req) => req.as_bytes(),

            #[cfg(feature = "test_only_commands")]
            MailboxReq::TestGetFmcAliasCert(req) => req.as_bytes(),
            #[cfg(feature = "test_only_commands")]
            MailboxReq::TestHmacVerify(req) => req.as_bytes(),
        }
    }

    pub fn as_bytes_mut(&mut self) -> &mut [u8] {
        match self {
            MailboxReq::EcdsaVerify(req) => req.as_bytes_mut(),
            MailboxReq::GetIdevCsr(req) => req.as_bytes_mut(),
            MailboxReq::GetLdevCert(req) => req.as_bytes_mut(),
            MailboxReq::StashMeasurement(req) => req.as_bytes_mut(),
            MailboxReq::InvokeDpeCommand(req) => req.as_bytes_mut(),
            MailboxReq::FipsVersion(req) => req.as_bytes_mut(),
            MailboxReq::FwInfo(req) => req.as_bytes_mut(),

            #[cfg(feature = "test_only_commands")]
            MailboxReq::TestHmacVerify(req) => req.as_bytes_mut(),
            #[cfg(feature = "test_only_commands")]
            MailboxReq::TestGetFmcAliasCert(req) => req.as_bytes_mut(),
        }
    }

    pub fn cmd_code(&self) -> CommandId {
        match self {
            MailboxReq::EcdsaVerify(_) => CommandId::ECDSA384_VERIFY,
            MailboxReq::GetIdevCsr(_) => CommandId::GET_IDEV_CSR,
            MailboxReq::GetLdevCert(_) => CommandId::GET_LDEV_CERT,
            MailboxReq::StashMeasurement(_) => CommandId::STASH_MEASUREMENT,
            MailboxReq::InvokeDpeCommand(_) => CommandId::INVOKE_DPE,
            MailboxReq::FipsVersion(_) => CommandId::VERSION,
            MailboxReq::FwInfo(_) => CommandId::FW_INFO,

            #[cfg(feature = "test_only_commands")]
            MailboxReq::TestHmacVerify(_) => CommandId::TEST_ONLY_HMAC384_VERIFY,
            #[cfg(feature = "test_only_commands")]
            MailboxReq::TestGetFmcAliasCert(_) => CommandId::TEST_ONLY_GET_FMC_ALIAS_CERT,
        }
    }

    /// Calculate and set the checksum for a request payload
    pub fn populate_chksum(&mut self) -> CaliptraResult<()> {
        // Calc checksum, use the size override if provided
        let checksum = crate::checksum::calc_checksum(
            self.cmd_code().into(),
            &self.as_bytes()[size_of::<i32>()..],
        );

        // cast as header struct
        let hdr: &mut MailboxReqHeader = LayoutVerified::<&mut [u8], MailboxReqHeader>::new(
            &mut self.as_bytes_mut()[..size_of::<MailboxReqHeader>()],
        )
        .ok_or(CaliptraError::RUNTIME_INSUFFICIENT_MEMORY)?
        .into_mut();

        // Set the chksum field
        hdr.chksum = checksum;

        Ok(())
    }
}

// HEADER
#[repr(C)]
#[derive(Default, Debug, AsBytes, FromBytes, PartialEq, Eq)]
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

// GET_IDEV_CERT
#[repr(C)]
#[derive(Debug, AsBytes, FromBytes, PartialEq, Eq)]
pub struct GetIdevCertReq {
    pub hdr: MailboxReqHeader,
    pub tbs_size: u32,
    pub signature_r: [u8; 48],
    pub signature_s: [u8; 48],
    pub tbs: [u8; GetIdevCertReq::DATA_MAX_SIZE], // variable length
}
impl GetIdevCertReq {
    pub const DATA_MAX_SIZE: usize = 916; // Req max size = Resp max size - MAX_ECDSA384_SIG_LEN
}

#[repr(C)]
#[derive(Debug, AsBytes, FromBytes, PartialEq, Eq)]
pub struct GetIdevCertResp {
    pub hdr: MailboxRespHeader,
    pub cert_size: u32,
    pub cert: [u8; GetIdevCertResp::DATA_MAX_SIZE], // variable length
}
impl GetIdevCertResp {
    pub const DATA_MAX_SIZE: usize = 1024;
}

// GET_IDEV_INFO
// No command-specific input args
#[repr(C)]
#[derive(Debug, AsBytes, FromBytes, PartialEq, Eq)]
pub struct GetIdevInfoResp {
    pub hdr: MailboxRespHeader,
    pub idev_pub_x: [u8; 48],
    pub idev_pub_y: [u8; 48],
}

#[repr(C)]
#[derive(Default, Debug, AsBytes, FromBytes, PartialEq, Eq)]
pub struct TestOnlyGetLdevCertReq {
    header: MailboxReqHeader,
}
impl Request for TestOnlyGetLdevCertReq {
    const ID: CommandId = CommandId::TEST_ONLY_GET_LDEV_CERT;
    type Resp = GetLdevCertResp;
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

    pub fn data(&self) -> Option<&[u8]> {
        self.data.get(..self.data_size as usize)
    }
}

// ECDSA384_SIGNATURE_VERIFY
#[repr(C)]
#[derive(Debug, AsBytes, FromBytes, PartialEq, Eq)]
pub struct EcdsaVerifyReq {
    pub hdr: MailboxReqHeader,
    pub pub_key_x: [u8; 48],
    pub pub_key_y: [u8; 48],
    pub signature_r: [u8; 48],
    pub signature_s: [u8; 48],
}
impl Request for EcdsaVerifyReq {
    const ID: CommandId = CommandId::ECDSA384_VERIFY;
    type Resp = MailboxRespHeader;
}
// No command-specific output args

// TEST_ONLY_HMAC384_SIGNATURE_VERIFY
#[repr(C)]
#[derive(Debug, AsBytes, FromBytes, PartialEq, Eq)]
pub struct HmacVerifyReq {
    pub hdr: MailboxReqHeader,
    pub key: [u8; 48],
    pub tag: [u8; 48],
    pub len: u32,
    pub msg: [u8; 256],
}
impl Request for HmacVerifyReq {
    const ID: CommandId = CommandId::TEST_ONLY_HMAC384_VERIFY;
    type Resp = MailboxRespHeader;
}
// No command-specific output args

// STASH_MEASUREMENT
#[repr(C)]
#[derive(Debug, AsBytes, FromBytes, PartialEq, Eq)]
pub struct StashMeasurementReq {
    pub hdr: MailboxReqHeader,
    pub metadata: [u8; 4],
    pub measurement: [u8; 48],
    pub context: [u8; 48],
    pub svn: u32,
}
impl Default for StashMeasurementReq {
    fn default() -> Self {
        Self {
            hdr: Default::default(),
            metadata: Default::default(),
            measurement: [0u8; 48],
            context: [0u8; 48],
            svn: Default::default(),
        }
    }
}
impl Request for StashMeasurementReq {
    const ID: CommandId = CommandId::STASH_MEASUREMENT;
    type Resp = StashMeasurementResp;
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
pub struct InvokeDpeReq {
    pub hdr: MailboxReqHeader,
    pub data_size: u32,
    pub data: [u8; InvokeDpeReq::DATA_MAX_SIZE], // variable length
}

impl InvokeDpeReq {
    pub const DATA_MAX_SIZE: usize = 512;
}

impl Default for InvokeDpeReq {
    fn default() -> Self {
        Self {
            hdr: MailboxReqHeader::default(),
            data_size: 0,
            data: [0u8; InvokeDpeReq::DATA_MAX_SIZE],
        }
    }
}
impl Request for InvokeDpeReq {
    const ID: CommandId = CommandId::INVOKE_DPE;
    type Resp = InvokeDpeResp;
}

#[repr(C)]
#[derive(Debug, AsBytes, FromBytes, PartialEq, Eq)]
pub struct InvokeDpeResp {
    pub hdr: MailboxRespHeader,
    pub data_size: u32,
    pub data: [u8; InvokeDpeResp::DATA_MAX_SIZE], // variable length
}

impl InvokeDpeResp {
    pub const DATA_MAX_SIZE: usize = 2200;

    fn as_bytes_partial(&self) -> &[u8] {
        let unused_byte_count = Self::DATA_MAX_SIZE.saturating_sub(self.data_size as usize);
        &self.as_bytes()[..size_of::<Self>() - unused_byte_count]
    }

    fn as_bytes_partial_mut(&mut self) -> &mut [u8] {
        let unused_byte_count = Self::DATA_MAX_SIZE.saturating_sub(self.data_size as usize);
        &mut self.as_bytes_mut()[..size_of::<Self>() - unused_byte_count]
    }
}

impl Default for InvokeDpeResp {
    fn default() -> Self {
        Self {
            hdr: MailboxRespHeader::default(),
            data_size: 0,
            data: [0u8; InvokeDpeResp::DATA_MAX_SIZE],
        }
    }
}

#[repr(C)]
#[derive(Debug, Default, AsBytes, FromBytes, PartialEq, Eq)]
pub struct TestOnlyGetFmcAliasCertReq {
    header: MailboxReqHeader,
}
impl Request for TestOnlyGetFmcAliasCertReq {
    const ID: CommandId = CommandId::TEST_ONLY_GET_FMC_ALIAS_CERT;
    type Resp = GetLdevCertResp;
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

    pub fn data(&self) -> Option<&[u8]> {
        self.data.get(..self.data_size as usize)
    }
}

// FIPS_SELF_TEST
// No command-specific input args
// No command-specific output args

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

// FW_INFO
// No command-specific input args
#[repr(C)]
#[derive(Debug, AsBytes, FromBytes, PartialEq, Eq)]
pub struct FwInfoResp {
    pub hdr: MailboxRespHeader,
    pub pl0_pauser: u32,
    pub runtime_svn: u32,
    pub min_runtime_svn: u32,
    pub fmc_manifest_svn: u32,
    pub attestation_disabled: u32,
    // TODO: Decide what other information to report for general firmware
    // status.
}

// CAPABILITIES
// No command-specific input args
#[repr(C)]
#[derive(Debug, AsBytes, FromBytes, PartialEq, Eq)]
pub struct CapabilitiesResp {
    pub hdr: MailboxRespHeader,
    pub capabilities: [u8; crate::capabilities::Capabilities::SIZE_IN_BYTES],
}

// POPULATE_IDEV_CERT
// No command-specific output args
#[repr(C)]
#[derive(Debug, AsBytes, FromBytes, PartialEq, Eq)]
pub struct PopulateIdevCertReq {
    pub hdr: MailboxReqHeader,
    pub cert_size: u32,
    pub cert: [u8; PopulateIdevCertReq::MAX_CERT_SIZE], // variable length
}
impl PopulateIdevCertReq {
    pub const MAX_CERT_SIZE: usize = 1024;
}
