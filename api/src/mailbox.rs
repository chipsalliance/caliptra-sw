// Licensed under the Apache-2.0 license

use bitflags::bitflags;
use caliptra_error::{CaliptraError, CaliptraResult};
use core::mem::size_of;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Ref};

use crate::CaliptraApiError;
use caliptra_registers::mbox;
use ureg::MmioMut;

#[derive(PartialEq, Eq)]
pub struct CommandId(pub u32);
impl CommandId {
    pub const FIRMWARE_LOAD: Self = Self(0x46574C44); // "FWLD"
    pub const GET_IDEV_CERT: Self = Self(0x49444543); // "IDEC"
    pub const GET_IDEV_INFO: Self = Self(0x49444549); // "IDEI"
    pub const POPULATE_IDEV_CERT: Self = Self(0x49444550); // "IDEP"
    pub const GET_LDEV_CERT: Self = Self(0x4C444556); // "LDEV"
    pub const GET_FMC_ALIAS_CERT: Self = Self(0x43455246); // "CERF"
    pub const GET_RT_ALIAS_CERT: Self = Self(0x43455252); // "CERR"
    pub const ECDSA384_VERIFY: Self = Self(0x53494756); // "SIGV"
    pub const LMS_VERIFY: Self = Self(0x4C4D5356); // "LMSV"
    pub const STASH_MEASUREMENT: Self = Self(0x4D454153); // "MEAS"
    pub const INVOKE_DPE: Self = Self(0x44504543); // "DPEC"
    pub const DISABLE_ATTESTATION: Self = Self(0x4453424C); // "DSBL"
    pub const FW_INFO: Self = Self(0x494E464F); // "INFO"
    pub const DPE_TAG_TCI: Self = Self(0x54514754); // "TAGT"
    pub const DPE_GET_TAGGED_TCI: Self = Self(0x47544744); // "GTGD"
    pub const INCREMENT_PCR_RESET_COUNTER: Self = Self(0x50435252); // "PCRR"
    pub const QUOTE_PCRS: Self = Self(0x50435251); // "PCRQ"
    pub const EXTEND_PCR: Self = Self(0x50435245); // "PCRE"
    pub const ADD_SUBJECT_ALT_NAME: Self = Self(0x414C544E); // "ALTN"
    pub const CERTIFY_KEY_EXTENDED: Self = Self(0x434B4558); // "CKEX"

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

    // The authorization manifest set command.
    pub const SET_AUTH_MANIFEST: Self = Self(0x4154_4D4E); // "ATMN"

    // The authorize and stash command.
    pub const AUTHORIZE_AND_STASH: Self = Self(0x4154_5348); // "ATSH"

    // The get IDevID CSR command.
    pub const GET_IDEV_CSR: Self = Self(0x4944_4352); // "IDCR"

    // The get FMC Alias CSR command.
    pub const GET_FMC_ALIAS_CSR: Self = Self(0x464D_4352); // "FMCR"

    // The sign with exported ecdsa command.
    pub const SIGN_WITH_EXPORTED_ECDSA: Self = Self(0x5357_4545); // "SWEE"

    // The revoke exported CDI handle command.
    pub const REVOKE_EXPORTED_CDI_HANDLE: Self = Self(0x5256_4348); // "RVCH"
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
pub trait Request: IntoBytes + FromBytes + Immutable + KnownLayout {
    const ID: CommandId;
    type Resp: Response;
}

pub trait Response: IntoBytes + FromBytes
where
    Self: Sized,
{
    /// The minimum size (in bytes) of this response. Transports that receive at
    /// least this much data should pad the missing data with zeroes. If they
    /// receive fewer bytes than MIN_SIZE, they should error.
    const MIN_SIZE: usize = core::mem::size_of::<Self>();

    fn populate_chksum(&mut self) {
        // Note: This will panic if sizeof::<Self>() < 4
        populate_checksum(self.as_mut_bytes());
    }
}

#[repr(C)]
#[derive(Debug, IntoBytes, Default, FromBytes, Immutable, KnownLayout, PartialEq, Eq)]
pub struct MailboxRespHeaderVarSize {
    pub hdr: MailboxRespHeader,
    pub data_len: u32,
}
pub trait ResponseVarSize: IntoBytes + FromBytes + Immutable + KnownLayout {
    fn data(&self) -> CaliptraResult<&[u8]> {
        // Will panic if sizeof<Self>() is smaller than MailboxRespHeaderVarSize
        // or Self doesn't have compatible alignment with
        // MailboxRespHeaderVarSize (should be impossible if MailboxRespHeaderVarSiz is the first field)                                                                 ..
        let (hdr, data) = MailboxRespHeaderVarSize::ref_from_prefix(self.as_bytes())
            .map_err(|_| CaliptraError::RUNTIME_MAILBOX_API_RESPONSE_DATA_LEN_TOO_LARGE)?;
        data.get(..hdr.data_len as usize)
            .ok_or(CaliptraError::RUNTIME_MAILBOX_API_RESPONSE_DATA_LEN_TOO_LARGE)
    }
    fn partial_len(&self) -> CaliptraResult<usize> {
        let (hdr, _) = MailboxRespHeaderVarSize::ref_from_prefix(self.as_bytes())
            .map_err(|_| CaliptraError::RUNTIME_MAILBOX_API_RESPONSE_DATA_LEN_TOO_LARGE)?;
        Ok(size_of::<MailboxRespHeaderVarSize>() + hdr.data_len as usize)
    }
    fn as_bytes_partial(&self) -> CaliptraResult<&[u8]> {
        self.as_bytes()
            .get(..self.partial_len()?)
            .ok_or(CaliptraError::RUNTIME_MAILBOX_API_RESPONSE_DATA_LEN_TOO_LARGE)
    }
    fn as_bytes_partial_mut(&mut self) -> CaliptraResult<&mut [u8]> {
        let partial_len = self.partial_len()?;
        self.as_mut_bytes()
            .get_mut(..partial_len)
            .ok_or(CaliptraError::RUNTIME_MAILBOX_API_RESPONSE_DATA_LEN_TOO_LARGE)
    }
}
impl<T: ResponseVarSize> Response for T {
    const MIN_SIZE: usize = size_of::<MailboxRespHeaderVarSize>();
}

fn populate_checksum(msg: &mut [u8]) {
    let (checksum_bytes, payload_bytes) = msg.split_at_mut(size_of::<u32>());
    let checksum = crate::checksum::calc_checksum(0, payload_bytes);
    checksum_bytes.copy_from_slice(&checksum.to_le_bytes());
}

// Contains all the possible mailbox response structs
#[cfg_attr(test, derive(PartialEq, Debug, Eq))]
#[allow(clippy::large_enum_variant)]
pub enum MailboxResp {
    Header(MailboxRespHeader),
    GetIdevCert(GetIdevCertResp),
    GetIdevInfo(GetIdevInfoResp),
    GetLdevCert(GetLdevCertResp),
    StashMeasurement(StashMeasurementResp),
    InvokeDpeCommand(InvokeDpeResp),
    GetFmcAliasCert(GetFmcAliasCertResp),
    FipsVersion(FipsVersionResp),
    FwInfo(FwInfoResp),
    Capabilities(CapabilitiesResp),
    GetTaggedTci(GetTaggedTciResp),
    GetRtAliasCert(GetRtAliasCertResp),
    QuotePcrs(QuotePcrsResp),
    CertifyKeyExtended(CertifyKeyExtendedResp),
    AuthorizeAndStash(AuthorizeAndStashResp),
    GetIdevCsr(GetIdevCsrResp),
    GetFmcAliasCsr(GetFmcAliasCsrResp),
    SignWithExportedEcdsa(SignWithExportedEcdsaResp),
    RevokeExportedCdiHandle(RevokeExportedCdiHandleResp),
}

impl MailboxResp {
    pub fn as_bytes(&self) -> CaliptraResult<&[u8]> {
        match self {
            MailboxResp::Header(resp) => Ok(resp.as_bytes()),
            MailboxResp::GetIdevCert(resp) => resp.as_bytes_partial(),
            MailboxResp::GetIdevInfo(resp) => Ok(resp.as_bytes()),
            MailboxResp::GetLdevCert(resp) => resp.as_bytes_partial(),
            MailboxResp::StashMeasurement(resp) => Ok(resp.as_bytes()),
            MailboxResp::InvokeDpeCommand(resp) => resp.as_bytes_partial(),
            MailboxResp::FipsVersion(resp) => Ok(resp.as_bytes()),
            MailboxResp::FwInfo(resp) => Ok(resp.as_bytes()),
            MailboxResp::Capabilities(resp) => Ok(resp.as_bytes()),
            MailboxResp::GetTaggedTci(resp) => Ok(resp.as_bytes()),
            MailboxResp::GetFmcAliasCert(resp) => resp.as_bytes_partial(),
            MailboxResp::GetRtAliasCert(resp) => resp.as_bytes_partial(),
            MailboxResp::QuotePcrs(resp) => Ok(resp.as_bytes()),
            MailboxResp::CertifyKeyExtended(resp) => Ok(resp.as_bytes()),
            MailboxResp::AuthorizeAndStash(resp) => Ok(resp.as_bytes()),
            MailboxResp::GetIdevCsr(resp) => Ok(resp.as_bytes()),
            MailboxResp::GetFmcAliasCsr(resp) => Ok(resp.as_bytes()),
            MailboxResp::SignWithExportedEcdsa(resp) => Ok(resp.as_bytes()),
            MailboxResp::RevokeExportedCdiHandle(resp) => Ok(resp.as_bytes()),
        }
    }

    pub fn as_mut_bytes(&mut self) -> CaliptraResult<&mut [u8]> {
        match self {
            MailboxResp::Header(resp) => Ok(resp.as_mut_bytes()),
            MailboxResp::GetIdevCert(resp) => resp.as_bytes_partial_mut(),
            MailboxResp::GetIdevInfo(resp) => Ok(resp.as_mut_bytes()),
            MailboxResp::GetLdevCert(resp) => resp.as_bytes_partial_mut(),
            MailboxResp::StashMeasurement(resp) => Ok(resp.as_mut_bytes()),
            MailboxResp::InvokeDpeCommand(resp) => resp.as_bytes_partial_mut(),
            MailboxResp::FipsVersion(resp) => Ok(resp.as_mut_bytes()),
            MailboxResp::FwInfo(resp) => Ok(resp.as_mut_bytes()),
            MailboxResp::Capabilities(resp) => Ok(resp.as_mut_bytes()),
            MailboxResp::GetTaggedTci(resp) => Ok(resp.as_mut_bytes()),
            MailboxResp::GetFmcAliasCert(resp) => resp.as_bytes_partial_mut(),
            MailboxResp::GetRtAliasCert(resp) => resp.as_bytes_partial_mut(),
            MailboxResp::QuotePcrs(resp) => Ok(resp.as_mut_bytes()),
            MailboxResp::CertifyKeyExtended(resp) => Ok(resp.as_mut_bytes()),
            MailboxResp::AuthorizeAndStash(resp) => Ok(resp.as_mut_bytes()),
            MailboxResp::GetIdevCsr(resp) => Ok(resp.as_mut_bytes()),
            MailboxResp::GetFmcAliasCsr(resp) => Ok(resp.as_mut_bytes()),
            MailboxResp::SignWithExportedEcdsa(resp) => Ok(resp.as_mut_bytes()),
            MailboxResp::RevokeExportedCdiHandle(resp) => Ok(resp.as_mut_bytes()),
        }
    }

    /// Calculate and set the checksum for a response payload
    /// Takes into account the size override for variable-length payloads
    pub fn populate_chksum(&mut self) -> CaliptraResult<()> {
        // Calc checksum, use the size override if provided
        let resp_bytes = self.as_bytes()?;
        if size_of::<u32>() >= resp_bytes.len() {
            return Err(CaliptraError::RUNTIME_MAILBOX_API_RESPONSE_DATA_LEN_TOO_LARGE);
        }
        let checksum = crate::checksum::calc_checksum(0, &resp_bytes[size_of::<u32>()..]);

        let mut_resp_bytes = self.as_mut_bytes()?;
        if size_of::<MailboxRespHeader>() > mut_resp_bytes.len() {
            return Err(CaliptraError::RUNTIME_MAILBOX_API_RESPONSE_DATA_LEN_TOO_LARGE);
        }
        let hdr: &mut MailboxRespHeader = MailboxRespHeader::mut_from_bytes(
            &mut mut_resp_bytes[..size_of::<MailboxRespHeader>()],
        )
        .map_err(|_| CaliptraError::RUNTIME_INSUFFICIENT_MEMORY)?;

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
    LmsVerify(LmsVerifyReq),
    GetLdevCert(GetLdevCertReq),
    StashMeasurement(StashMeasurementReq),
    InvokeDpeCommand(InvokeDpeReq),
    FipsVersion(MailboxReqHeader),
    FwInfo(MailboxReqHeader),
    PopulateIdevCert(PopulateIdevCertReq),
    GetIdevCert(GetIdevCertReq),
    TagTci(TagTciReq),
    GetTaggedTci(GetTaggedTciReq),
    GetFmcAliasCert(GetFmcAliasCertReq),
    GetRtAliasCert(GetRtAliasCertReq),
    IncrementPcrResetCounter(IncrementPcrResetCounterReq),
    QuotePcrs(QuotePcrsReq),
    ExtendPcr(ExtendPcrReq),
    AddSubjectAltName(AddSubjectAltNameReq),
    CertifyKeyExtended(CertifyKeyExtendedReq),
    SetAuthManifest(SetAuthManifestReq),
    AuthorizeAndStash(AuthorizeAndStashReq),
    SignWithExportedEcdsa(SignWithExportedEcdsaReq),
    RevokeExportedCdiHandle(RevokeExportedCdiHandleReq),
}

impl MailboxReq {
    pub fn as_bytes(&self) -> CaliptraResult<&[u8]> {
        match self {
            MailboxReq::EcdsaVerify(req) => Ok(req.as_bytes()),
            MailboxReq::LmsVerify(req) => Ok(req.as_bytes()),
            MailboxReq::StashMeasurement(req) => Ok(req.as_bytes()),
            MailboxReq::InvokeDpeCommand(req) => req.as_bytes_partial(),
            MailboxReq::FipsVersion(req) => Ok(req.as_bytes()),
            MailboxReq::FwInfo(req) => Ok(req.as_bytes()),
            MailboxReq::GetLdevCert(req) => Ok(req.as_bytes()),
            MailboxReq::PopulateIdevCert(req) => req.as_bytes_partial(),
            MailboxReq::GetIdevCert(req) => req.as_bytes_partial(),
            MailboxReq::TagTci(req) => Ok(req.as_bytes()),
            MailboxReq::GetTaggedTci(req) => Ok(req.as_bytes()),
            MailboxReq::GetFmcAliasCert(req) => Ok(req.as_bytes()),
            MailboxReq::GetRtAliasCert(req) => Ok(req.as_bytes()),
            MailboxReq::IncrementPcrResetCounter(req) => Ok(req.as_bytes()),
            MailboxReq::QuotePcrs(req) => Ok(req.as_bytes()),
            MailboxReq::ExtendPcr(req) => Ok(req.as_bytes()),
            MailboxReq::AddSubjectAltName(req) => req.as_bytes_partial(),
            MailboxReq::CertifyKeyExtended(req) => Ok(req.as_bytes()),
            MailboxReq::SetAuthManifest(req) => Ok(req.as_bytes()),
            MailboxReq::AuthorizeAndStash(req) => Ok(req.as_bytes()),
            MailboxReq::SignWithExportedEcdsa(req) => Ok(req.as_bytes()),
            MailboxReq::RevokeExportedCdiHandle(req) => Ok(req.as_bytes()),
        }
    }

    pub fn as_mut_bytes(&mut self) -> CaliptraResult<&mut [u8]> {
        match self {
            MailboxReq::EcdsaVerify(req) => Ok(req.as_mut_bytes()),
            MailboxReq::LmsVerify(req) => Ok(req.as_mut_bytes()),
            MailboxReq::GetLdevCert(req) => Ok(req.as_mut_bytes()),
            MailboxReq::StashMeasurement(req) => Ok(req.as_mut_bytes()),
            MailboxReq::InvokeDpeCommand(req) => req.as_bytes_partial_mut(),
            MailboxReq::FipsVersion(req) => Ok(req.as_mut_bytes()),
            MailboxReq::FwInfo(req) => Ok(req.as_mut_bytes()),
            MailboxReq::PopulateIdevCert(req) => req.as_bytes_partial_mut(),
            MailboxReq::GetIdevCert(req) => req.as_bytes_partial_mut(),
            MailboxReq::TagTci(req) => Ok(req.as_mut_bytes()),
            MailboxReq::GetTaggedTci(req) => Ok(req.as_mut_bytes()),
            MailboxReq::GetFmcAliasCert(req) => Ok(req.as_mut_bytes()),
            MailboxReq::GetRtAliasCert(req) => Ok(req.as_mut_bytes()),
            MailboxReq::IncrementPcrResetCounter(req) => Ok(req.as_mut_bytes()),
            MailboxReq::QuotePcrs(req) => Ok(req.as_mut_bytes()),
            MailboxReq::ExtendPcr(req) => Ok(req.as_mut_bytes()),
            MailboxReq::AddSubjectAltName(req) => req.as_bytes_partial_mut(),
            MailboxReq::CertifyKeyExtended(req) => Ok(req.as_mut_bytes()),
            MailboxReq::SetAuthManifest(req) => Ok(req.as_mut_bytes()),
            MailboxReq::AuthorizeAndStash(req) => Ok(req.as_mut_bytes()),
            MailboxReq::SignWithExportedEcdsa(req) => Ok(req.as_mut_bytes()),
            MailboxReq::RevokeExportedCdiHandle(req) => Ok(req.as_mut_bytes()),
        }
    }

    pub fn cmd_code(&self) -> CommandId {
        match self {
            MailboxReq::EcdsaVerify(_) => CommandId::ECDSA384_VERIFY,
            MailboxReq::LmsVerify(_) => CommandId::LMS_VERIFY,
            MailboxReq::GetLdevCert(_) => CommandId::GET_LDEV_CERT,
            MailboxReq::StashMeasurement(_) => CommandId::STASH_MEASUREMENT,
            MailboxReq::InvokeDpeCommand(_) => CommandId::INVOKE_DPE,
            MailboxReq::FipsVersion(_) => CommandId::VERSION,
            MailboxReq::FwInfo(_) => CommandId::FW_INFO,
            MailboxReq::PopulateIdevCert(_) => CommandId::POPULATE_IDEV_CERT,
            MailboxReq::GetIdevCert(_) => CommandId::GET_IDEV_CERT,
            MailboxReq::TagTci(_) => CommandId::DPE_TAG_TCI,
            MailboxReq::GetTaggedTci(_) => CommandId::DPE_GET_TAGGED_TCI,
            MailboxReq::GetFmcAliasCert(_) => CommandId::GET_FMC_ALIAS_CERT,
            MailboxReq::GetRtAliasCert(_) => CommandId::GET_RT_ALIAS_CERT,
            MailboxReq::IncrementPcrResetCounter(_) => CommandId::INCREMENT_PCR_RESET_COUNTER,
            MailboxReq::QuotePcrs(_) => CommandId::QUOTE_PCRS,
            MailboxReq::ExtendPcr(_) => CommandId::EXTEND_PCR,
            MailboxReq::AddSubjectAltName(_) => CommandId::ADD_SUBJECT_ALT_NAME,
            MailboxReq::CertifyKeyExtended(_) => CommandId::CERTIFY_KEY_EXTENDED,
            MailboxReq::SetAuthManifest(_) => CommandId::SET_AUTH_MANIFEST,
            MailboxReq::AuthorizeAndStash(_) => CommandId::AUTHORIZE_AND_STASH,
            MailboxReq::SignWithExportedEcdsa(_) => CommandId::SIGN_WITH_EXPORTED_ECDSA,
            MailboxReq::RevokeExportedCdiHandle(_) => CommandId::REVOKE_EXPORTED_CDI_HANDLE,
        }
    }

    /// Calculate and set the checksum for a request payload
    pub fn populate_chksum(&mut self) -> CaliptraResult<()> {
        // Calc checksum, use the size override if provided
        let checksum = crate::checksum::calc_checksum(
            self.cmd_code().into(),
            &self.as_bytes()?[size_of::<i32>()..],
        );

        let hdr: &mut MailboxReqHeader = MailboxReqHeader::mut_from_bytes(
            &mut self.as_mut_bytes()?[..size_of::<MailboxReqHeader>()],
        )
        .map_err(|_| CaliptraError::RUNTIME_INSUFFICIENT_MEMORY)?;

        // Set the chksum field
        hdr.chksum = checksum;

        Ok(())
    }
}

// HEADER
#[repr(C)]
#[derive(Default, Debug, IntoBytes, FromBytes, Immutable, KnownLayout, PartialEq, Eq)]
pub struct MailboxReqHeader {
    pub chksum: u32,
}

#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct MailboxRespHeader {
    pub chksum: u32,
    pub fips_status: u32,
}
impl Response for MailboxRespHeader {}

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

// GET_IDEV_CERT
#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, Immutable, KnownLayout, PartialEq, Eq)]
pub struct GetIdevCertReq {
    pub hdr: MailboxReqHeader,
    pub tbs_size: u32,
    pub signature_r: [u8; 48],
    pub signature_s: [u8; 48],
    pub tbs: [u8; GetIdevCertReq::DATA_MAX_SIZE], // variable length
}
impl GetIdevCertReq {
    pub const DATA_MAX_SIZE: usize = 916; // Req max size = Resp max size - MAX_ECDSA384_SIG_LEN

    pub fn as_bytes_partial(&self) -> CaliptraResult<&[u8]> {
        if self.tbs_size as usize > Self::DATA_MAX_SIZE {
            return Err(CaliptraError::RUNTIME_MAILBOX_API_REQUEST_DATA_LEN_TOO_LARGE);
        }
        let unused_byte_count = Self::DATA_MAX_SIZE - self.tbs_size as usize;
        Ok(&self.as_bytes()[..size_of::<Self>() - unused_byte_count])
    }

    pub fn as_bytes_partial_mut(&mut self) -> CaliptraResult<&mut [u8]> {
        if self.tbs_size as usize > Self::DATA_MAX_SIZE {
            return Err(CaliptraError::RUNTIME_MAILBOX_API_REQUEST_DATA_LEN_TOO_LARGE);
        }
        let unused_byte_count = Self::DATA_MAX_SIZE - self.tbs_size as usize;
        Ok(&mut self.as_mut_bytes()[..size_of::<Self>() - unused_byte_count])
    }
}
impl Default for GetIdevCertReq {
    fn default() -> Self {
        Self {
            hdr: MailboxReqHeader::default(),
            tbs_size: 0,
            signature_r: [0u8; 48],
            signature_s: [0u8; 48],
            tbs: [0u8; GetIdevCertReq::DATA_MAX_SIZE],
        }
    }
}

#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, Immutable, KnownLayout, PartialEq, Eq)]
pub struct GetIdevCertResp {
    pub hdr: MailboxRespHeader,
    pub cert_size: u32,
    pub cert: [u8; GetIdevCertResp::DATA_MAX_SIZE], // variable length
}
impl GetIdevCertResp {
    pub const DATA_MAX_SIZE: usize = 1024;
}
impl ResponseVarSize for GetIdevCertResp {}

impl Default for GetIdevCertResp {
    fn default() -> Self {
        Self {
            hdr: MailboxRespHeader::default(),
            cert_size: 0,
            cert: [0u8; GetIdevCertResp::DATA_MAX_SIZE],
        }
    }
}

// GET_IDEV_INFO
// No command-specific input args
#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, Immutable, KnownLayout, PartialEq, Eq)]
pub struct GetIdevInfoResp {
    pub hdr: MailboxRespHeader,
    pub idev_pub_x: [u8; 48],
    pub idev_pub_y: [u8; 48],
}

// GET_LDEV_CERT
#[repr(C)]
#[derive(Default, Debug, IntoBytes, FromBytes, Immutable, KnownLayout, PartialEq, Eq)]
pub struct GetLdevCertReq {
    pub header: MailboxReqHeader,
}

impl Request for GetLdevCertReq {
    const ID: CommandId = CommandId::GET_LDEV_CERT;
    type Resp = GetLdevCertResp;
}

#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, Immutable, KnownLayout, PartialEq, Eq)]
pub struct GetLdevCertResp {
    pub hdr: MailboxRespHeader,
    pub data_size: u32,
    pub data: [u8; GetLdevCertResp::DATA_MAX_SIZE], // variable length
}
impl GetLdevCertResp {
    pub const DATA_MAX_SIZE: usize = 1024;
}
impl ResponseVarSize for GetLdevCertResp {}

impl Default for GetLdevCertResp {
    fn default() -> Self {
        Self {
            hdr: MailboxRespHeader::default(),
            data_size: 0,
            data: [0u8; GetLdevCertResp::DATA_MAX_SIZE],
        }
    }
}

// GET_RT_ALIAS_CERT
#[repr(C)]
#[derive(Default, Debug, IntoBytes, FromBytes, Immutable, KnownLayout, PartialEq, Eq)]
pub struct GetRtAliasCertReq {
    pub header: MailboxReqHeader,
}
impl Request for GetRtAliasCertReq {
    const ID: CommandId = CommandId::GET_RT_ALIAS_CERT;
    type Resp = GetRtAliasCertResp;
}

#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, Immutable, KnownLayout, PartialEq, Eq)]
pub struct GetRtAliasCertResp {
    pub hdr: MailboxRespHeader,
    pub data_size: u32,
    pub data: [u8; GetRtAliasCertResp::DATA_MAX_SIZE], // variable length
}
impl GetRtAliasCertResp {
    pub const DATA_MAX_SIZE: usize = 1024;

    pub fn data(&self) -> Option<&[u8]> {
        self.data.get(..self.data_size as usize)
    }
}
impl ResponseVarSize for GetRtAliasCertResp {}

impl Default for GetRtAliasCertResp {
    fn default() -> Self {
        Self {
            hdr: MailboxRespHeader::default(),
            data_size: 0,
            data: [0u8; GetRtAliasCertResp::DATA_MAX_SIZE],
        }
    }
}

// ECDSA384_SIGNATURE_VERIFY
#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, Immutable, KnownLayout, PartialEq, Eq)]
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

// LMS_SIGNATURE_VERIFY
#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, Immutable, KnownLayout, PartialEq, Eq)]
pub struct LmsVerifyReq {
    pub hdr: MailboxReqHeader,
    pub pub_key_tree_type: u32,
    pub pub_key_ots_type: u32,
    pub pub_key_id: [u8; 16],
    pub pub_key_digest: [u8; 24],
    pub signature_q: u32,
    pub signature_ots: [u8; 1252],
    pub signature_tree_type: u32,
    pub signature_tree_path: [u8; 360],
}
impl Request for LmsVerifyReq {
    const ID: CommandId = CommandId::LMS_VERIFY;
    type Resp = MailboxRespHeader;
}
// No command-specific output args

// STASH_MEASUREMENT
#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, Immutable, KnownLayout, PartialEq, Eq)]
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
#[derive(Debug, Default, IntoBytes, FromBytes, Immutable, KnownLayout, PartialEq, Eq)]
pub struct StashMeasurementResp {
    pub hdr: MailboxRespHeader,
    pub dpe_result: u32,
}
impl Response for StashMeasurementResp {}

// DISABLE_ATTESTATION
// No command-specific input args
// No command-specific output args

// CERTIFY_KEY_EXTENDED
#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, Immutable, KnownLayout, PartialEq, Eq)]
pub struct CertifyKeyExtendedReq {
    pub hdr: MailboxReqHeader,
    pub flags: CertifyKeyExtendedFlags,
    pub certify_key_req: [u8; CertifyKeyExtendedReq::CERTIFY_KEY_REQ_SIZE],
}
impl CertifyKeyExtendedReq {
    pub const CERTIFY_KEY_REQ_SIZE: usize = 72;
}
impl Request for CertifyKeyExtendedReq {
    const ID: CommandId = CommandId::CERTIFY_KEY_EXTENDED;
    type Resp = CertifyKeyExtendedResp;
}

#[repr(C)]
#[derive(Debug, PartialEq, Eq, FromBytes, Immutable, KnownLayout, IntoBytes)]
pub struct CertifyKeyExtendedFlags(pub u32);

bitflags! {
    impl CertifyKeyExtendedFlags: u32 {
        const DMTF_OTHER_NAME = 1u32 << 31;
    }
}

#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, Immutable, KnownLayout, PartialEq, Eq)]
pub struct CertifyKeyExtendedResp {
    pub hdr: MailboxRespHeader,
    pub certify_key_resp: [u8; CertifyKeyExtendedResp::CERTIFY_KEY_RESP_SIZE],
}
impl CertifyKeyExtendedResp {
    pub const CERTIFY_KEY_RESP_SIZE: usize = 6272;
}
impl Response for CertifyKeyExtendedResp {}

// INVOKE_DPE_COMMAND
#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, Immutable, KnownLayout, PartialEq, Eq)]
pub struct InvokeDpeReq {
    pub hdr: MailboxReqHeader,
    pub data_size: u32,
    pub data: [u8; InvokeDpeReq::DATA_MAX_SIZE], // variable length
}

impl InvokeDpeReq {
    pub const DATA_MAX_SIZE: usize = 512;

    pub fn as_bytes_partial(&self) -> CaliptraResult<&[u8]> {
        if self.data_size as usize > Self::DATA_MAX_SIZE {
            return Err(CaliptraError::RUNTIME_MAILBOX_API_REQUEST_DATA_LEN_TOO_LARGE);
        }
        let unused_byte_count = Self::DATA_MAX_SIZE - self.data_size as usize;
        Ok(&self.as_bytes()[..size_of::<Self>() - unused_byte_count])
    }

    pub fn as_bytes_partial_mut(&mut self) -> CaliptraResult<&mut [u8]> {
        if self.data_size as usize > Self::DATA_MAX_SIZE {
            return Err(CaliptraError::RUNTIME_MAILBOX_API_REQUEST_DATA_LEN_TOO_LARGE);
        }
        let unused_byte_count = Self::DATA_MAX_SIZE - self.data_size as usize;
        Ok(&mut self.as_mut_bytes()[..size_of::<Self>() - unused_byte_count])
    }
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

// EXTEND_PCR
#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, Immutable, KnownLayout, PartialEq, Eq)]
pub struct ExtendPcrReq {
    pub hdr: MailboxReqHeader,
    pub pcr_idx: u32,
    pub data: [u8; 48],
}

impl Request for ExtendPcrReq {
    const ID: CommandId = CommandId::EXTEND_PCR;
    type Resp = MailboxRespHeader;
}

// No command-specific output args

#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, Immutable, KnownLayout, PartialEq, Eq)]
pub struct InvokeDpeResp {
    pub hdr: MailboxRespHeader,
    pub data_size: u32,
    pub data: [u8; InvokeDpeResp::DATA_MAX_SIZE], // variable length
}
impl InvokeDpeResp {
    pub const DATA_MAX_SIZE: usize = 6556;
}
impl ResponseVarSize for InvokeDpeResp {}

impl Default for InvokeDpeResp {
    fn default() -> Self {
        Self {
            hdr: MailboxRespHeader::default(),
            data_size: 0,
            data: [0u8; InvokeDpeResp::DATA_MAX_SIZE],
        }
    }
}

// GET_FMC_ALIAS_CERT
#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, Immutable, KnownLayout, PartialEq, Eq)]
pub struct GetFmcAliasCertReq {
    pub header: MailboxReqHeader,
}
impl Request for GetFmcAliasCertReq {
    const ID: CommandId = CommandId::GET_FMC_ALIAS_CERT;
    type Resp = GetFmcAliasCertResp;
}

#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, Immutable, KnownLayout, PartialEq, Eq)]
pub struct GetFmcAliasCertResp {
    pub hdr: MailboxRespHeader,
    pub data_size: u32,
    pub data: [u8; GetFmcAliasCertResp::DATA_MAX_SIZE], // variable length
}
impl GetFmcAliasCertResp {
    pub const DATA_MAX_SIZE: usize = 1024;
}
impl ResponseVarSize for GetFmcAliasCertResp {}

impl Default for GetFmcAliasCertResp {
    fn default() -> Self {
        Self {
            hdr: MailboxRespHeader::default(),
            data_size: 0,
            data: [0u8; GetFmcAliasCertResp::DATA_MAX_SIZE],
        }
    }
}

// FIPS_SELF_TEST
// No command-specific input args
// No command-specific output args

// FIPS_GET_VERSION
// No command-specific input args
#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, Immutable, KnownLayout, PartialEq, Eq)]
pub struct FipsVersionResp {
    pub hdr: MailboxRespHeader,
    pub mode: u32,
    pub fips_rev: [u32; 3],
    pub name: [u8; 12],
}
impl Response for FipsVersionResp {}

// FW_INFO
// No command-specific input args
#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, Immutable, KnownLayout, PartialEq, Eq)]
pub struct FwInfoResp {
    pub hdr: MailboxRespHeader,
    pub pl0_pauser: u32,
    pub runtime_svn: u32,
    pub min_runtime_svn: u32,
    pub fmc_manifest_svn: u32,
    pub attestation_disabled: u32,
    pub rom_revision: [u8; 20],
    pub fmc_revision: [u8; 20],
    pub runtime_revision: [u8; 20],
    pub rom_sha256_digest: [u32; 8],
    pub fmc_sha384_digest: [u32; 12],
    pub runtime_sha384_digest: [u32; 12],
    pub owner_pub_key_hash: [u32; 12],
    pub authman_sha384_digest: [u32; 12],
}

// CAPABILITIES
// No command-specific input args
#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, Immutable, KnownLayout, PartialEq, Eq)]
pub struct CapabilitiesResp {
    pub hdr: MailboxRespHeader,
    pub capabilities: [u8; crate::capabilities::Capabilities::SIZE_IN_BYTES],
}
impl Response for CapabilitiesResp {}

// ADD_SUBJECT_ALT_NAME
// No command-specific output args
#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, Immutable, KnownLayout, PartialEq, Eq)]
pub struct AddSubjectAltNameReq {
    pub hdr: MailboxReqHeader,
    pub dmtf_device_info_size: u32,
    pub dmtf_device_info: [u8; AddSubjectAltNameReq::MAX_DEVICE_INFO_LEN], // variable length
}
impl AddSubjectAltNameReq {
    pub const MAX_DEVICE_INFO_LEN: usize = 128;

    pub fn as_bytes_partial(&self) -> CaliptraResult<&[u8]> {
        if self.dmtf_device_info_size as usize > Self::MAX_DEVICE_INFO_LEN {
            return Err(CaliptraError::RUNTIME_MAILBOX_API_REQUEST_DATA_LEN_TOO_LARGE);
        }
        let unused_byte_count = Self::MAX_DEVICE_INFO_LEN - self.dmtf_device_info_size as usize;
        Ok(&self.as_bytes()[..size_of::<Self>() - unused_byte_count])
    }

    pub fn as_bytes_partial_mut(&mut self) -> CaliptraResult<&mut [u8]> {
        if self.dmtf_device_info_size as usize > Self::MAX_DEVICE_INFO_LEN {
            return Err(CaliptraError::RUNTIME_MAILBOX_API_REQUEST_DATA_LEN_TOO_LARGE);
        }
        let unused_byte_count = Self::MAX_DEVICE_INFO_LEN - self.dmtf_device_info_size as usize;
        Ok(&mut self.as_mut_bytes()[..size_of::<Self>() - unused_byte_count])
    }
}
impl Default for AddSubjectAltNameReq {
    fn default() -> Self {
        Self {
            hdr: MailboxReqHeader::default(),
            dmtf_device_info_size: 0,
            dmtf_device_info: [0u8; AddSubjectAltNameReq::MAX_DEVICE_INFO_LEN],
        }
    }
}

// POPULATE_IDEV_CERT
// No command-specific output args
#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, Immutable, KnownLayout, PartialEq, Eq)]
pub struct PopulateIdevCertReq {
    pub hdr: MailboxReqHeader,
    pub cert_size: u32,
    pub cert: [u8; PopulateIdevCertReq::MAX_CERT_SIZE], // variable length
}
impl PopulateIdevCertReq {
    pub const MAX_CERT_SIZE: usize = 1024;

    pub fn as_bytes_partial(&self) -> CaliptraResult<&[u8]> {
        if self.cert_size as usize > Self::MAX_CERT_SIZE {
            return Err(CaliptraError::RUNTIME_MAILBOX_API_REQUEST_DATA_LEN_TOO_LARGE);
        }
        let unused_byte_count = Self::MAX_CERT_SIZE - self.cert_size as usize;
        Ok(&self.as_bytes()[..size_of::<Self>() - unused_byte_count])
    }

    pub fn as_bytes_partial_mut(&mut self) -> CaliptraResult<&mut [u8]> {
        if self.cert_size as usize > Self::MAX_CERT_SIZE {
            return Err(CaliptraError::RUNTIME_MAILBOX_API_REQUEST_DATA_LEN_TOO_LARGE);
        }
        let unused_byte_count = Self::MAX_CERT_SIZE - self.cert_size as usize;
        Ok(&mut self.as_mut_bytes()[..size_of::<Self>() - unused_byte_count])
    }
}
impl Default for PopulateIdevCertReq {
    fn default() -> Self {
        Self {
            hdr: MailboxReqHeader::default(),
            cert_size: 0,
            cert: [0u8; PopulateIdevCertReq::MAX_CERT_SIZE],
        }
    }
}

// DPE_TAG_TCI
// No command-specific output args
#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, Immutable, KnownLayout, PartialEq, Eq)]
pub struct TagTciReq {
    pub hdr: MailboxReqHeader,
    pub handle: [u8; 16],
    pub tag: u32,
}

// DPE_GET_TAGGED_TCI
#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, Immutable, KnownLayout, PartialEq, Eq)]
pub struct GetTaggedTciReq {
    pub hdr: MailboxReqHeader,
    pub tag: u32,
}
#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, Immutable, KnownLayout, PartialEq, Eq)]
pub struct GetTaggedTciResp {
    pub hdr: MailboxRespHeader,
    pub tci_cumulative: [u8; 48],
    pub tci_current: [u8; 48],
}

// INCREMENT_PCR_RESET_COUNTER request
// No command specific output
#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, Immutable, KnownLayout, PartialEq, Eq)]
pub struct IncrementPcrResetCounterReq {
    pub hdr: MailboxReqHeader,
    pub index: u32,
}

impl Request for IncrementPcrResetCounterReq {
    const ID: CommandId = CommandId::INCREMENT_PCR_RESET_COUNTER;
    type Resp = MailboxRespHeader;
}

/// QUOTE_PCRS input arguments
#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, Immutable, KnownLayout, PartialEq, Eq)]
pub struct QuotePcrsReq {
    pub hdr: MailboxReqHeader,
    pub nonce: [u8; 32],
}

pub type PcrValue = [u8; 48];

/// QUOTE_PCRS output
#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, Immutable, KnownLayout, PartialEq, Eq)]
pub struct QuotePcrsResp {
    pub hdr: MailboxRespHeader,
    /// The PCR values
    pub pcrs: [PcrValue; 32],
    pub nonce: [u8; 32],
    pub digest: [u8; 48],
    pub reset_ctrs: [u32; 32],
    pub signature_r: [u8; 48],
    pub signature_s: [u8; 48],
}

impl Response for QuotePcrsResp {}

impl Request for QuotePcrsReq {
    const ID: CommandId = CommandId::QUOTE_PCRS;
    type Resp = QuotePcrsResp;
}

// SET_AUTH_MANIFEST
#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, Immutable, KnownLayout, PartialEq, Eq)]
pub struct SetAuthManifestReq {
    pub hdr: MailboxReqHeader,
    pub manifest_size: u32,
    pub manifest: [u8; SetAuthManifestReq::MAX_MAN_SIZE],
}
impl SetAuthManifestReq {
    pub const MAX_MAN_SIZE: usize = 14 * 1024;

    pub fn as_bytes_partial(&self) -> CaliptraResult<&[u8]> {
        if self.manifest_size as usize > Self::MAX_MAN_SIZE {
            return Err(CaliptraError::RUNTIME_MAILBOX_API_REQUEST_DATA_LEN_TOO_LARGE);
        }
        let unused_byte_count = Self::MAX_MAN_SIZE - self.manifest_size as usize;
        Ok(&self.as_bytes()[..size_of::<Self>() - unused_byte_count])
    }

    pub fn as_bytes_partial_mut(&mut self) -> CaliptraResult<&mut [u8]> {
        if self.manifest_size as usize > Self::MAX_MAN_SIZE {
            return Err(CaliptraError::RUNTIME_MAILBOX_API_REQUEST_DATA_LEN_TOO_LARGE);
        }
        let unused_byte_count = Self::MAX_MAN_SIZE - self.manifest_size as usize;
        Ok(&mut self.as_mut_bytes()[..size_of::<Self>() - unused_byte_count])
    }
}
impl Default for SetAuthManifestReq {
    fn default() -> Self {
        Self {
            hdr: MailboxReqHeader::default(),
            manifest_size: 0,
            manifest: [0u8; SetAuthManifestReq::MAX_MAN_SIZE],
        }
    }
}

// GET_IDEVID_CSR
#[repr(C)]
#[derive(Default, Debug, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct GetIdevCsrReq {
    pub hdr: MailboxReqHeader,
}

impl Request for GetIdevCsrReq {
    const ID: CommandId = CommandId::GET_IDEV_CSR;
    type Resp = GetIdevCsrResp;
}

#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct GetIdevCsrResp {
    pub hdr: MailboxRespHeader,
    pub data_size: u32,
    pub data: [u8; Self::DATA_MAX_SIZE],
}
impl GetIdevCsrResp {
    pub const DATA_MAX_SIZE: usize = 512;
}
impl ResponseVarSize for GetIdevCsrResp {}

impl Default for GetIdevCsrResp {
    fn default() -> Self {
        Self {
            hdr: MailboxRespHeader::default(),
            data_size: 0,
            data: [0u8; Self::DATA_MAX_SIZE],
        }
    }
}

// GET_FMC_ALIAS_CSR
#[repr(C)]
#[derive(Default, Debug, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct GetFmcAliasCsrReq {
    pub hdr: MailboxReqHeader,
}

impl Request for GetFmcAliasCsrReq {
    const ID: CommandId = CommandId::GET_FMC_ALIAS_CSR;
    type Resp = GetFmcAliasCsrResp;
}

#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct GetFmcAliasCsrResp {
    pub hdr: MailboxRespHeader,
    pub data_size: u32,
    pub data: [u8; Self::DATA_MAX_SIZE],
}

impl Default for GetFmcAliasCsrResp {
    fn default() -> Self {
        Self {
            hdr: MailboxRespHeader::default(),
            data_size: 0,
            data: [0u8; Self::DATA_MAX_SIZE],
        }
    }
}

impl GetFmcAliasCsrResp {
    pub const DATA_MAX_SIZE: usize = 512;
}
impl ResponseVarSize for GetFmcAliasCsrResp {}

// SIGN_WITH_EXPORTED_ECDSA
#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct SignWithExportedEcdsaReq {
    pub hdr: MailboxReqHeader,
    pub exported_cdi_handle: [u8; Self::EXPORTED_CDI_MAX_SIZE],
    pub tbs: [u8; Self::MAX_DIGEST_SIZE],
}

impl Default for SignWithExportedEcdsaReq {
    fn default() -> Self {
        Self {
            hdr: MailboxReqHeader::default(),
            exported_cdi_handle: [0u8; Self::EXPORTED_CDI_MAX_SIZE],
            tbs: [0u8; Self::MAX_DIGEST_SIZE],
        }
    }
}

impl SignWithExportedEcdsaReq {
    pub const EXPORTED_CDI_MAX_SIZE: usize = 32;
    pub const MAX_DIGEST_SIZE: usize = 48;
}

impl Request for SignWithExportedEcdsaReq {
    const ID: CommandId = CommandId::SIGN_WITH_EXPORTED_ECDSA;
    type Resp = SignWithExportedEcdsaResp;
}

#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct SignWithExportedEcdsaResp {
    pub hdr: MailboxRespHeader,
    pub derived_pubkey_x: [u8; Self::X_SIZE],
    pub derived_pubkey_y: [u8; Self::Y_SIZE],
    pub signature_r: [u8; Self::R_SIZE],
    pub signature_s: [u8; Self::S_SIZE],
}

impl SignWithExportedEcdsaResp {
    pub const X_SIZE: usize = 48;
    pub const Y_SIZE: usize = 48;
    pub const R_SIZE: usize = 48;
    pub const S_SIZE: usize = 48;
}

impl ResponseVarSize for SignWithExportedEcdsaResp {}

impl Default for SignWithExportedEcdsaResp {
    fn default() -> Self {
        Self {
            hdr: MailboxRespHeader::default(),
            signature_r: [0u8; Self::R_SIZE],
            signature_s: [0u8; Self::S_SIZE],
            derived_pubkey_x: [0u8; Self::X_SIZE],
            derived_pubkey_y: [0u8; Self::Y_SIZE],
        }
    }
}

// REVOKE_EXPORTED_CDI_HANDLE
#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct RevokeExportedCdiHandleReq {
    pub hdr: MailboxReqHeader,
    pub exported_cdi_handle: [u8; Self::EXPORTED_CDI_MAX_SIZE],
}

impl Default for RevokeExportedCdiHandleReq {
    fn default() -> Self {
        Self {
            hdr: MailboxReqHeader::default(),
            exported_cdi_handle: [0u8; Self::EXPORTED_CDI_MAX_SIZE],
        }
    }
}

impl RevokeExportedCdiHandleReq {
    pub const EXPORTED_CDI_MAX_SIZE: usize = 32;
}

impl Request for RevokeExportedCdiHandleReq {
    const ID: CommandId = CommandId::REVOKE_EXPORTED_CDI_HANDLE;
    type Resp = RevokeExportedCdiHandleResp;
}
impl Response for RevokeExportedCdiHandleResp {}

#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct RevokeExportedCdiHandleResp {
    pub hdr: MailboxRespHeader,
}

#[repr(u32)]
#[derive(Debug, PartialEq, Eq)]
pub enum ImageHashSource {
    Invalid = 0,
    InRequest,
    ShaAcc,
}

impl From<u32> for ImageHashSource {
    fn from(val: u32) -> Self {
        match val {
            1_u32 => ImageHashSource::InRequest,
            2_u32 => ImageHashSource::ShaAcc,
            _ => ImageHashSource::Invalid,
        }
    }
}

bitflags::bitflags! {
    pub struct AuthAndStashFlags : u32 {
        const SKIP_STASH = 0x1;
    }
}

impl From<u32> for AuthAndStashFlags {
    /// Converts to this type from the input type.
    fn from(value: u32) -> Self {
        AuthAndStashFlags::from_bits_truncate(value)
    }
}

impl AuthAndStashFlags {
    pub fn set_skip_stash(&mut self, skip_stash: bool) {
        self.set(AuthAndStashFlags::SKIP_STASH, skip_stash);
    }
}

// AUTHORIZE_AND_STASH
#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, Immutable, KnownLayout, PartialEq, Eq)]
pub struct AuthorizeAndStashReq {
    pub hdr: MailboxReqHeader,
    pub fw_id: [u8; 4],
    pub measurement: [u8; 48], // Image digest.
    pub context: [u8; 48],
    pub svn: u32,
    pub flags: u32,
    pub source: u32,
}
impl Default for AuthorizeAndStashReq {
    fn default() -> Self {
        Self {
            hdr: Default::default(),
            fw_id: Default::default(),
            measurement: [0u8; 48],
            context: [0u8; 48],
            svn: Default::default(),
            flags: AuthAndStashFlags::SKIP_STASH.bits(),
            source: ImageHashSource::InRequest as u32,
        }
    }
}
impl Request for AuthorizeAndStashReq {
    const ID: CommandId = CommandId::AUTHORIZE_AND_STASH;
    type Resp = StashMeasurementResp;
}

#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, Immutable, KnownLayout, PartialEq, Eq)]
pub struct AuthorizeAndStashResp {
    pub hdr: MailboxRespHeader,
    pub auth_req_result: u32,
}
impl Response for AuthorizeAndStashResp {}

/// Retrieves dlen bytes  from the mailbox.
pub fn mbox_read_response(
    mbox: mbox::RegisterBlock<impl MmioMut>,
    buf: &mut [u8],
) -> Result<&[u8], CaliptraApiError> {
    let dlen_bytes = mbox.dlen().read() as usize;

    // Buffer must be big enough to store dlen bytes.
    let buf = buf
        .get_mut(..dlen_bytes)
        .ok_or(CaliptraApiError::ReadBuffTooSmall)?;

    mbox_read_fifo(mbox, buf)?;

    Ok(buf)
}

pub fn mbox_read_fifo(
    mbox: mbox::RegisterBlock<impl MmioMut>,
    buf: &mut [u8],
) -> core::result::Result<(), CaliptraApiError> {
    use zerocopy::Unalign;

    fn dequeue_words(mbox: &mbox::RegisterBlock<impl MmioMut>, buf: &mut [Unalign<u32>]) {
        for word in buf.iter_mut() {
            *word = Unalign::new(mbox.dataout().read());
        }
    }

    let dlen_bytes = mbox.dlen().read() as usize;

    let buf = buf
        .get_mut(..dlen_bytes)
        .ok_or(CaliptraApiError::UnableToReadMailbox)?;

    let len_words = buf.len() / size_of::<u32>();
    let (mut buf_words, suffix) = Ref::from_prefix_with_elems(buf, len_words)
        .map_err(|_| CaliptraApiError::ReadBuffTooSmall)?;

    dequeue_words(&mbox, &mut buf_words);
    if !suffix.is_empty() {
        let last_word = mbox.dataout().read();
        let suffix_len = suffix.len();
        suffix
            .as_mut_bytes()
            .copy_from_slice(&last_word.as_bytes()[..suffix_len]);
    }

    Ok(())
}

pub fn mbox_write_fifo(
    mbox: &mbox::RegisterBlock<impl MmioMut>,
    buf: &[u8],
) -> core::result::Result<(), CaliptraApiError> {
    const MAILBOX_SIZE: u32 = 128 * 1024;

    let Ok(input_len) = u32::try_from(buf.len()) else {
        return Err(CaliptraApiError::BufferTooLargeForMailbox);
    };
    if input_len > MAILBOX_SIZE {
        return Err(CaliptraApiError::BufferTooLargeForMailbox);
    }
    mbox.dlen().write(|_| input_len);

    let mut remaining = buf;
    while remaining.len() >= 4 {
        // Panic is impossible because the subslice is always 4 bytes
        let word = u32::from_le_bytes(remaining[..4].try_into().unwrap());
        mbox.datain().write(|_| word);
        remaining = &remaining[4..];
    }
    if !remaining.is_empty() {
        let mut word_bytes = [0u8; 4];
        word_bytes[..remaining.len()].copy_from_slice(remaining);
        let word = u32::from_le_bytes(word_bytes);
        mbox.datain().write(|_| word);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_populate_checksum_resp_header() {
        let mut hdr = MailboxRespHeader {
            fips_status: 0x4242,
            ..Default::default()
        };
        hdr.populate_chksum();
        assert_eq!(
            hdr,
            MailboxRespHeader {
                chksum: 0u32.wrapping_sub(0x84),
                fips_status: 0x4242,
            }
        )
    }
    #[test]
    fn test_populate_checksum_capabilities() {
        let mut msg = CapabilitiesResp {
            hdr: Default::default(),
            capabilities: [
                0x42, 0x23, 0x43, 0x81, 0x45, 0x6c, 0x55, 0x75, 0x3d, 0x81, 0xd4, 0xcc, 0x3c, 0x28,
                0x29, 0xc9,
            ],
        };
        msg.populate_chksum();
        assert_eq!(
            msg,
            CapabilitiesResp {
                hdr: MailboxRespHeader {
                    chksum: 0xfffff9a8,
                    fips_status: 0
                },
                capabilities: [
                    0x42, 0x23, 0x43, 0x81, 0x45, 0x6c, 0x55, 0x75, 0x3d, 0x81, 0xd4, 0xcc, 0x3c,
                    0x28, 0x29, 0xc9
                ],
            }
        );
    }
}
