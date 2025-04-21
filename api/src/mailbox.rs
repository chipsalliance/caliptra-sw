// Licensed under the Apache-2.0 license

use bitflags::bitflags;
use caliptra_error::{CaliptraError, CaliptraResult};
use caliptra_image_types::{
    MLDSA87_PUB_KEY_BYTE_SIZE, MLDSA87_SIGNATURE_BYTE_SIZE, SHA512_DIGEST_BYTE_SIZE,
};
use core::mem::size_of;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Ref};

use crate::CaliptraApiError;
use caliptra_registers::mbox;
use ureg::MmioMut;

/// Maximum input data size for cryptographic mailbox commands.
pub const MAX_CMB_DATA_SIZE: usize = 4096;
/// Context size for CMB SHA commands.
pub const CMB_SHA_CONTEXT_SIZE: usize = 200;
/// Maximum response data size
pub const MAX_RESP_DATA_SIZE: usize = 9216; // 9K

#[derive(PartialEq, Eq)]
pub struct CommandId(pub u32);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlgorithmType {
    Ecc384,
    Mldsa87,
}

impl CommandId {
    pub const FIRMWARE_LOAD: Self = Self(0x46574C44); // "FWLD"
    pub const GET_IDEV_ECC384_CERT: Self = Self(0x49444543); // "IDEC"
    pub const GET_IDEV_ECC384_INFO: Self = Self(0x49444549); // "IDEI"
    pub const POPULATE_IDEV_CERT: Self = Self(0x49444550); // "IDEP"
    pub const GET_LDEV_ECC384_CERT: Self = Self(0x4C444556); // "LDEV"
    pub const GET_FMC_ALIAS_ECC384_CERT: Self = Self(0x43455246); // "CERF"
    pub const GET_RT_ALIAS_ECC384_CERT: Self = Self(0x43455252); // "CERR"

    // MLDSA87 versions
    pub const GET_IDEV_MLDSA87_CERT: Self = Self(0x49444D43); // "IDMC"
    pub const POPULATE_IDEV_MLDSA87_CERT: Self = Self(0x49444D50); // "IDMP"
    pub const GET_LDEV_MLDSA87_CERT: Self = Self(0x4C444D43); // "LDMC"
    pub const GET_FMC_ALIAS_MLDSA87_CERT: Self = Self(0x434D4346); // "CMCF"
    pub const GET_RT_ALIAS_MLDSA87_CERT: Self = Self(0x434D4352); // "CMCR"
    pub const GET_IDEV_MLDSA87_INFO: Self = Self(0x49444D49); // "IDMI"
    pub const ECDSA384_VERIFY: Self = Self(0x45435632); // "ECV2"
    pub const LMS_VERIFY: Self = Self(0x4C4D5632); // "LMV2"
    pub const MLDSA87_VERIFY: Self = Self(0x4d4c5632); // "MLV2"
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

    // The download firmware from recovery interface command.
    pub const RI_DOWNLOAD_FIRMWARE: Self = Self(0x5249_4644); // "RIFD"

    // The get IDevID ECC CSR command.
    pub const GET_IDEV_ECC384_CSR: Self = Self(0x4944_4352); // "IDCR"

    // The get IDevID MLDSA CSR command.
    pub const GET_IDEV_MLDSA87_CSR: Self = Self(0x4944_4d52); // "IDMR"

    // The get FMC Alias ECC CSR command.
    pub const GET_FMC_ALIAS_ECC384_CSR: Self = Self(0x464D_4352); // "FMCR"

    // The get FMC Alias MLDSA CSR command.
    pub const GET_FMC_ALIAS_MLDSA87_CSR: Self = Self(0x464d_4452); // "FMDR"

    // The sign with exported ecdsa command.
    pub const SIGN_WITH_EXPORTED_ECDSA: Self = Self(0x5357_4545); // "SWEE"

    // The sign with exported mldsa command.
    pub const SIGN_WITH_EXPORTED_MLDSA: Self = Self(0x5357_4D4C); // "SWML"

    // Debug unlock commands
    pub const MANUF_DEBUG_UNLOCK_REQ_TOKEN: Self = Self(0x4d445554); // "MDUT"
    pub const PRODUCTION_AUTH_DEBUG_UNLOCK_REQ: Self = Self(0x50445552); // "PDUR"
    pub const PRODUCTION_AUTH_DEBUG_UNLOCK_TOKEN: Self = Self(0x50445554); // "PDUT"

    // Cryptographic mailbox commands
    pub const CM_IMPORT: Self = Self(0x434D_494D); // "CMIM"
    pub const CM_STATUS: Self = Self(0x434D_5354); // "CMST"
    pub const CM_SHA_INIT: Self = Self(0x434D_5349); // "CMSI"
    pub const CM_SHA_UPDATE: Self = Self(0x434D_5355); // "CMSU"
    pub const CM_SHA_FINAL: Self = Self(0x434D_5346); // "CMSF"
    pub const CM_RANDOM_GENERATE: Self = Self(0x434D_5247); // "CMRG"
    pub const CM_RANDOM_STIR: Self = Self(0x434D_5253); // "CMRS"
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
    GetIdevMldsa87Info(GetIdevMldsa87InfoResp),
    GetLdevCert(GetLdevCertResp),
    StashMeasurement(StashMeasurementResp),
    InvokeDpeCommand(InvokeDpeResp),
    GetFmcAliasEcc384Cert(GetFmcAliasEcc384CertResp),
    GetFmcAliasMlDsa87Cert(GetFmcAliasMlDsa87CertResp),
    FipsVersion(FipsVersionResp),
    FwInfo(FwInfoResp),
    Capabilities(CapabilitiesResp),
    GetTaggedTci(GetTaggedTciResp),
    GetRtAliasCert(GetRtAliasCertResp),
    QuotePcrs(QuotePcrsResp),
    CertifyKeyExtended(CertifyKeyExtendedResp),
    AuthorizeAndStash(AuthorizeAndStashResp),
    GetIdevCsr(GetIdevCsrResp),
    GetIdevMldsaCsr(GetIdevCsrResp),
    GetFmcAliasCsr(GetFmcAliasCsrResp),
    SignWithExportedEcdsa(SignWithExportedEcdsaResp),
    CmImport(CmImportResp),
    CmStatus(CmStatusResp),
    CmShaInit(CmShaInitResp),
    CmShaFinal(CmShaFinalResp),
    CmRandomGenerate(CmRandomGenerateResp),
}

impl MailboxResp {
    pub fn as_bytes(&self) -> CaliptraResult<&[u8]> {
        match self {
            MailboxResp::Header(resp) => Ok(resp.as_bytes()),
            MailboxResp::GetIdevCert(resp) => resp.as_bytes_partial(),
            MailboxResp::GetIdevInfo(resp) => Ok(resp.as_bytes()),
            MailboxResp::GetIdevMldsa87Info(resp) => Ok(resp.as_bytes()),
            MailboxResp::GetLdevCert(resp) => resp.as_bytes_partial(),
            MailboxResp::StashMeasurement(resp) => Ok(resp.as_bytes()),
            MailboxResp::InvokeDpeCommand(resp) => resp.as_bytes_partial(),
            MailboxResp::FipsVersion(resp) => Ok(resp.as_bytes()),
            MailboxResp::FwInfo(resp) => Ok(resp.as_bytes()),
            MailboxResp::Capabilities(resp) => Ok(resp.as_bytes()),
            MailboxResp::GetTaggedTci(resp) => Ok(resp.as_bytes()),
            MailboxResp::GetFmcAliasEcc384Cert(resp) => resp.as_bytes_partial(),
            MailboxResp::GetFmcAliasMlDsa87Cert(resp) => resp.as_bytes_partial(),
            MailboxResp::GetRtAliasCert(resp) => resp.as_bytes_partial(),
            MailboxResp::QuotePcrs(resp) => Ok(resp.as_bytes()),
            MailboxResp::CertifyKeyExtended(resp) => Ok(resp.as_bytes()),
            MailboxResp::AuthorizeAndStash(resp) => Ok(resp.as_bytes()),
            MailboxResp::GetIdevCsr(resp) => resp.as_bytes_partial(),
            MailboxResp::GetIdevMldsaCsr(resp) => Ok(resp.as_bytes()),
            MailboxResp::GetFmcAliasCsr(resp) => resp.as_bytes_partial(),
            MailboxResp::SignWithExportedEcdsa(resp) => Ok(resp.as_bytes()),
            MailboxResp::CmImport(resp) => Ok(resp.as_bytes()),
            MailboxResp::CmStatus(resp) => Ok(resp.as_bytes()),
            MailboxResp::CmShaInit(resp) => Ok(resp.as_bytes()),
            MailboxResp::CmShaFinal(resp) => resp.as_bytes_partial(),
            MailboxResp::CmRandomGenerate(resp) => resp.as_bytes_partial(),
        }
    }

    pub fn as_mut_bytes(&mut self) -> CaliptraResult<&mut [u8]> {
        match self {
            MailboxResp::Header(resp) => Ok(resp.as_mut_bytes()),
            MailboxResp::GetIdevCert(resp) => resp.as_bytes_partial_mut(),
            MailboxResp::GetIdevInfo(resp) => Ok(resp.as_mut_bytes()),
            MailboxResp::GetIdevMldsa87Info(resp) => Ok(resp.as_mut_bytes()),
            MailboxResp::GetLdevCert(resp) => resp.as_bytes_partial_mut(),
            MailboxResp::StashMeasurement(resp) => Ok(resp.as_mut_bytes()),
            MailboxResp::InvokeDpeCommand(resp) => resp.as_bytes_partial_mut(),
            MailboxResp::FipsVersion(resp) => Ok(resp.as_mut_bytes()),
            MailboxResp::FwInfo(resp) => Ok(resp.as_mut_bytes()),
            MailboxResp::Capabilities(resp) => Ok(resp.as_mut_bytes()),
            MailboxResp::GetTaggedTci(resp) => Ok(resp.as_mut_bytes()),
            MailboxResp::GetFmcAliasEcc384Cert(resp) => resp.as_bytes_partial_mut(),
            MailboxResp::GetFmcAliasMlDsa87Cert(resp) => resp.as_bytes_partial_mut(),
            MailboxResp::GetRtAliasCert(resp) => resp.as_bytes_partial_mut(),
            MailboxResp::QuotePcrs(resp) => Ok(resp.as_mut_bytes()),
            MailboxResp::CertifyKeyExtended(resp) => Ok(resp.as_mut_bytes()),
            MailboxResp::AuthorizeAndStash(resp) => Ok(resp.as_mut_bytes()),
            MailboxResp::GetIdevCsr(resp) => resp.as_bytes_partial_mut(),
            MailboxResp::GetIdevMldsaCsr(resp) => Ok(resp.as_mut_bytes()),
            MailboxResp::GetFmcAliasCsr(resp) => resp.as_bytes_partial_mut(),
            MailboxResp::SignWithExportedEcdsa(resp) => Ok(resp.as_mut_bytes()),
            MailboxResp::CmImport(resp) => Ok(resp.as_mut_bytes()),
            MailboxResp::CmStatus(resp) => Ok(resp.as_mut_bytes()),
            MailboxResp::CmShaInit(resp) => Ok(resp.as_mut_bytes()),
            MailboxResp::CmShaFinal(resp) => resp.as_bytes_partial_mut(),
            MailboxResp::CmRandomGenerate(resp) => resp.as_bytes_partial_mut(),
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
    GetLdevEcc384Cert(GetLdevEcc384CertReq),
    GetLdevMldsa87Cert(GetLdevMldsa87CertReq),
    StashMeasurement(StashMeasurementReq),
    InvokeDpeCommand(InvokeDpeReq),
    FipsVersion(MailboxReqHeader),
    FwInfo(MailboxReqHeader),
    PopulateIdevEcc384Cert(PopulateIdevEcc384CertReq),
    GetIdevEcc384Cert(GetIdevEcc384CertReq),
    GetIdevMldsa87Cert(GetIdevMldsa87CertReq),
    TagTci(TagTciReq),
    GetTaggedTci(GetTaggedTciReq),
    GetFmcAliasEcc384Cert(GetFmcAliasEcc384CertReq),
    GetRtAliasEcc384Cert(GetRtAliasEcc384CertReq),
    GetRtAliasMldsa87Cert(GetRtAliasMldsa87CertReq),
    IncrementPcrResetCounter(IncrementPcrResetCounterReq),
    QuotePcrs(QuotePcrsReq),
    ExtendPcr(ExtendPcrReq),
    AddSubjectAltName(AddSubjectAltNameReq),
    CertifyKeyExtended(CertifyKeyExtendedReq),
    SetAuthManifest(SetAuthManifestReq),
    AuthorizeAndStash(AuthorizeAndStashReq),
    SignWithExportedEcdsa(SignWithExportedEcdsaReq),
    CmImport(CmImportReq),
    CmShaInit(CmShaInitReq),
    CmShaUpdate(CmShaUpdateReq),
    CmShaFinal(CmShaFinalReq),
    CmRandomGenerate(CmRandomGenerateReq),
    CmRandomStir(CmRandomStirReq),
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
            MailboxReq::GetLdevEcc384Cert(req) => Ok(req.as_bytes()),
            MailboxReq::GetLdevMldsa87Cert(req) => Ok(req.as_bytes()),
            MailboxReq::PopulateIdevEcc384Cert(req) => req.as_bytes_partial(),
            MailboxReq::GetIdevEcc384Cert(req) => req.as_bytes_partial(),
            MailboxReq::GetIdevMldsa87Cert(req) => req.as_bytes_partial(),
            MailboxReq::TagTci(req) => Ok(req.as_bytes()),
            MailboxReq::GetTaggedTci(req) => Ok(req.as_bytes()),
            MailboxReq::GetFmcAliasEcc384Cert(req) => Ok(req.as_bytes()),
            MailboxReq::GetRtAliasEcc384Cert(req) => Ok(req.as_bytes()),
            MailboxReq::GetRtAliasMldsa87Cert(req) => Ok(req.as_bytes()),
            MailboxReq::IncrementPcrResetCounter(req) => Ok(req.as_bytes()),
            MailboxReq::QuotePcrs(req) => Ok(req.as_bytes()),
            MailboxReq::ExtendPcr(req) => Ok(req.as_bytes()),
            MailboxReq::AddSubjectAltName(req) => req.as_bytes_partial(),
            MailboxReq::CertifyKeyExtended(req) => Ok(req.as_bytes()),
            MailboxReq::SetAuthManifest(req) => Ok(req.as_bytes()),
            MailboxReq::AuthorizeAndStash(req) => Ok(req.as_bytes()),
            MailboxReq::SignWithExportedEcdsa(req) => Ok(req.as_bytes()),
            MailboxReq::CmImport(req) => req.as_bytes_partial(),
            MailboxReq::CmShaInit(req) => req.as_bytes_partial(),
            MailboxReq::CmShaUpdate(req) => req.as_bytes_partial(),
            MailboxReq::CmShaFinal(req) => req.as_bytes_partial(),
            MailboxReq::CmRandomGenerate(req) => Ok(req.as_bytes()),
            MailboxReq::CmRandomStir(req) => req.as_bytes_partial(),
        }
    }

    pub fn as_mut_bytes(&mut self) -> CaliptraResult<&mut [u8]> {
        match self {
            MailboxReq::EcdsaVerify(req) => Ok(req.as_mut_bytes()),
            MailboxReq::LmsVerify(req) => Ok(req.as_mut_bytes()),
            MailboxReq::GetLdevEcc384Cert(req) => Ok(req.as_mut_bytes()),
            MailboxReq::GetLdevMldsa87Cert(req) => Ok(req.as_mut_bytes()),
            MailboxReq::StashMeasurement(req) => Ok(req.as_mut_bytes()),
            MailboxReq::InvokeDpeCommand(req) => req.as_bytes_partial_mut(),
            MailboxReq::FipsVersion(req) => Ok(req.as_mut_bytes()),
            MailboxReq::FwInfo(req) => Ok(req.as_mut_bytes()),
            MailboxReq::PopulateIdevEcc384Cert(req) => req.as_bytes_partial_mut(),
            MailboxReq::GetIdevEcc384Cert(req) => req.as_bytes_partial_mut(),
            MailboxReq::GetIdevMldsa87Cert(req) => req.as_bytes_partial_mut(),
            MailboxReq::TagTci(req) => Ok(req.as_mut_bytes()),
            MailboxReq::GetTaggedTci(req) => Ok(req.as_mut_bytes()),
            MailboxReq::GetFmcAliasEcc384Cert(req) => Ok(req.as_mut_bytes()),
            MailboxReq::GetRtAliasEcc384Cert(req) => Ok(req.as_mut_bytes()),
            MailboxReq::GetRtAliasMldsa87Cert(req) => Ok(req.as_mut_bytes()),
            MailboxReq::IncrementPcrResetCounter(req) => Ok(req.as_mut_bytes()),
            MailboxReq::QuotePcrs(req) => Ok(req.as_mut_bytes()),
            MailboxReq::ExtendPcr(req) => Ok(req.as_mut_bytes()),
            MailboxReq::AddSubjectAltName(req) => req.as_bytes_partial_mut(),
            MailboxReq::CertifyKeyExtended(req) => Ok(req.as_mut_bytes()),
            MailboxReq::SetAuthManifest(req) => Ok(req.as_mut_bytes()),
            MailboxReq::AuthorizeAndStash(req) => Ok(req.as_mut_bytes()),
            MailboxReq::SignWithExportedEcdsa(req) => Ok(req.as_mut_bytes()),
            MailboxReq::CmImport(req) => Ok(req.as_mut_bytes()),
            MailboxReq::CmShaInit(req) => req.as_bytes_partial_mut(),
            MailboxReq::CmShaUpdate(req) => req.as_bytes_partial_mut(),
            MailboxReq::CmShaFinal(req) => req.as_bytes_partial_mut(),
            MailboxReq::CmRandomGenerate(req) => Ok(req.as_mut_bytes()),
            MailboxReq::CmRandomStir(req) => req.as_bytes_partial_mut(),
        }
    }

    pub fn cmd_code(&self) -> CommandId {
        match self {
            MailboxReq::EcdsaVerify(_) => CommandId::ECDSA384_VERIFY,
            MailboxReq::LmsVerify(_) => CommandId::LMS_VERIFY,
            MailboxReq::GetLdevEcc384Cert(_) => CommandId::GET_LDEV_ECC384_CERT,
            MailboxReq::GetLdevMldsa87Cert(_) => CommandId::GET_LDEV_MLDSA87_CERT,
            MailboxReq::StashMeasurement(_) => CommandId::STASH_MEASUREMENT,
            MailboxReq::InvokeDpeCommand(_) => CommandId::INVOKE_DPE,
            MailboxReq::FipsVersion(_) => CommandId::VERSION,
            MailboxReq::FwInfo(_) => CommandId::FW_INFO,
            MailboxReq::PopulateIdevEcc384Cert(_) => CommandId::POPULATE_IDEV_CERT,
            MailboxReq::GetIdevEcc384Cert(_) => CommandId::GET_IDEV_ECC384_CERT,
            MailboxReq::GetIdevMldsa87Cert(_) => CommandId::GET_IDEV_MLDSA87_CERT,
            MailboxReq::TagTci(_) => CommandId::DPE_TAG_TCI,
            MailboxReq::GetTaggedTci(_) => CommandId::DPE_GET_TAGGED_TCI,
            MailboxReq::GetFmcAliasEcc384Cert(_) => CommandId::GET_FMC_ALIAS_ECC384_CERT,
            MailboxReq::GetRtAliasEcc384Cert(_) => CommandId::GET_RT_ALIAS_ECC384_CERT,
            MailboxReq::GetRtAliasMldsa87Cert(_) => CommandId::GET_RT_ALIAS_MLDSA87_CERT,
            MailboxReq::IncrementPcrResetCounter(_) => CommandId::INCREMENT_PCR_RESET_COUNTER,
            MailboxReq::QuotePcrs(_) => CommandId::QUOTE_PCRS,
            MailboxReq::ExtendPcr(_) => CommandId::EXTEND_PCR,
            MailboxReq::AddSubjectAltName(_) => CommandId::ADD_SUBJECT_ALT_NAME,
            MailboxReq::CertifyKeyExtended(_) => CommandId::CERTIFY_KEY_EXTENDED,
            MailboxReq::SetAuthManifest(_) => CommandId::SET_AUTH_MANIFEST,
            MailboxReq::AuthorizeAndStash(_) => CommandId::AUTHORIZE_AND_STASH,
            MailboxReq::SignWithExportedEcdsa(_) => CommandId::SIGN_WITH_EXPORTED_ECDSA,
            MailboxReq::CmImport(_) => CommandId::CM_IMPORT,
            MailboxReq::CmShaInit(_) => CommandId::CM_SHA_INIT,
            MailboxReq::CmShaUpdate(_) => CommandId::CM_SHA_UPDATE,
            MailboxReq::CmShaFinal(_) => CommandId::CM_SHA_FINAL,
            MailboxReq::CmRandomGenerate(_) => CommandId::CM_RANDOM_GENERATE,
            MailboxReq::CmRandomStir(_) => CommandId::CM_RANDOM_STIR,
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

// Generic variable-sized data response type
#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, Immutable, KnownLayout, PartialEq, Eq)]
pub struct VarSizeDataResp {
    pub hdr: MailboxRespHeader,
    pub data_size: u32,
    pub data: [u8; VarSizeDataResp::DATA_MAX_SIZE], // variable length
}

impl VarSizeDataResp {
    pub const DATA_MAX_SIZE: usize = MAX_RESP_DATA_SIZE;

    pub fn data(&self) -> Option<&[u8]> {
        self.data.get(..self.data_size as usize)
    }
}

impl ResponseVarSize for VarSizeDataResp {}

impl Default for VarSizeDataResp {
    fn default() -> Self {
        Self {
            hdr: MailboxRespHeader::default(),
            data_size: 0,
            data: [0u8; Self::DATA_MAX_SIZE],
        }
    }
}

// GET_IDEV_ECC384_CERT
#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, Immutable, KnownLayout, PartialEq, Eq)]
pub struct GetIdevEcc384CertReq {
    pub hdr: MailboxReqHeader,
    pub tbs_size: u32,
    pub signature_r: [u8; 48],
    pub signature_s: [u8; 48],
    pub tbs: [u8; GetIdevEcc384CertReq::DATA_MAX_SIZE], // variable length
}
impl GetIdevEcc384CertReq {
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
impl Default for GetIdevEcc384CertReq {
    fn default() -> Self {
        Self {
            hdr: MailboxReqHeader::default(),
            tbs_size: 0,
            signature_r: [0u8; 48],
            signature_s: [0u8; 48],
            tbs: [0u8; GetIdevEcc384CertReq::DATA_MAX_SIZE],
        }
    }
}

// GET_IDEV_MLDSA87_CERT
#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, Immutable, KnownLayout, PartialEq, Eq)]
pub struct GetIdevMldsa87CertReq {
    pub hdr: MailboxReqHeader,
    pub tbs_size: u32,
    pub signature: [u8; 4628],
    pub tbs: [u8; GetIdevMldsa87CertReq::DATA_MAX_SIZE], // variable length
}
impl GetIdevMldsa87CertReq {
    pub const DATA_MAX_SIZE: usize = 916; // Req max size = Resp max size - MAX_MLDSA87_SIG_LEN

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
impl Default for GetIdevMldsa87CertReq {
    fn default() -> Self {
        Self {
            hdr: MailboxReqHeader::default(),
            tbs_size: 0,
            signature: [0u8; 4628],
            tbs: [0u8; GetIdevMldsa87CertReq::DATA_MAX_SIZE],
        }
    }
}

// Use the generic VarSizeDataResp for certificate responses
pub type GetIdevCertResp = VarSizeDataResp;

// GET_IDEV_ECC384_INFO
// No command-specific input args
#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, Immutable, KnownLayout, PartialEq, Eq)]
pub struct GetIdevInfoResp {
    pub hdr: MailboxRespHeader,
    pub idev_pub_x: [u8; 48],
    pub idev_pub_y: [u8; 48],
}

// GET_IDEV_MLDSA87_INFO
// No command-specific input args
#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, Immutable, KnownLayout, PartialEq, Eq)]
pub struct GetIdevMldsa87InfoResp {
    pub hdr: MailboxRespHeader,
    pub idev_pub_key: [u8; MLDSA87_PUB_KEY_BYTE_SIZE],
}

// GET_LDEV_CERT
#[repr(C)]
#[derive(Default, Debug, IntoBytes, FromBytes, Immutable, KnownLayout, PartialEq, Eq)]
pub struct GetLdevEcc384CertReq {
    pub header: MailboxReqHeader,
}

impl Request for GetLdevEcc384CertReq {
    const ID: CommandId = CommandId::GET_LDEV_ECC384_CERT;
    type Resp = GetLdevCertResp;
}

// GET_LDEV_MLDSA87_CERT
#[repr(C)]
#[derive(Default, Debug, IntoBytes, FromBytes, Immutable, KnownLayout, PartialEq, Eq)]
pub struct GetLdevMldsa87CertReq {
    pub header: MailboxReqHeader,
}

impl Request for GetLdevMldsa87CertReq {
    const ID: CommandId = CommandId::GET_LDEV_MLDSA87_CERT;
    type Resp = GetLdevCertResp;
}
pub type GetLdevCertResp = VarSizeDataResp;

// GET_RT_ALIAS_CERT
#[repr(C)]
#[derive(Default, Debug, IntoBytes, FromBytes, Immutable, KnownLayout, PartialEq, Eq)]
pub struct GetRtAliasEcc384CertReq {
    pub header: MailboxReqHeader,
}
impl Request for GetRtAliasEcc384CertReq {
    const ID: CommandId = CommandId::GET_RT_ALIAS_ECC384_CERT;
    type Resp = GetRtAliasCertResp;
}

pub type GetRtAliasCertResp = VarSizeDataResp;

// GET_RT_ALIAS_MLDSA87_CERT
#[repr(C)]
#[derive(Default, Debug, IntoBytes, FromBytes, Immutable, KnownLayout, PartialEq, Eq)]
pub struct GetRtAliasMldsa87CertReq {
    pub header: MailboxReqHeader,
}
impl Request for GetRtAliasMldsa87CertReq {
    const ID: CommandId = CommandId::GET_RT_ALIAS_MLDSA87_CERT;
    type Resp = GetRtAliasMldsaCertResp;
}

pub type GetRtAliasMldsaCertResp = VarSizeDataResp;

// ECDSA384_SIGNATURE_VERIFY
#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, Immutable, KnownLayout, PartialEq, Eq)]
pub struct EcdsaVerifyReq {
    pub hdr: MailboxReqHeader,
    pub pub_key_x: [u8; 48],
    pub pub_key_y: [u8; 48],
    pub signature_r: [u8; 48],
    pub signature_s: [u8; 48],
    pub hash: [u8; 48],
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
    pub hash: [u8; 48],
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
pub struct GetFmcAliasEcc384CertReq {
    pub header: MailboxReqHeader,
}
impl Request for GetFmcAliasEcc384CertReq {
    const ID: CommandId = CommandId::GET_FMC_ALIAS_ECC384_CERT;
    type Resp = GetFmcAliasEcc384CertResp;
}

pub type GetFmcAliasEcc384CertResp = VarSizeDataResp;

#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, Immutable, KnownLayout, PartialEq, Eq)]
pub struct GetFmcAliasMlDsa87CertReq {
    pub header: MailboxReqHeader,
}
impl Request for GetFmcAliasMlDsa87CertReq {
    const ID: CommandId = CommandId::GET_FMC_ALIAS_MLDSA87_CERT;
    type Resp = GetFmcAliasMlDsa87CertResp;
}

pub type GetFmcAliasMlDsa87CertResp = VarSizeDataResp;

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
    pub fw_svn: u32,
    pub min_fw_svn: u32,
    pub cold_boot_fw_svn: u32,
    pub attestation_disabled: u32,
    pub rom_revision: [u8; 20],
    pub fmc_revision: [u8; 20],
    pub runtime_revision: [u8; 20],
    pub rom_sha256_digest: [u32; 8],
    pub fmc_sha384_digest: [u32; 12],
    pub runtime_sha384_digest: [u32; 12],
    pub owner_pub_key_hash: [u32; 12],
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
pub struct PopulateIdevEcc384CertReq {
    pub hdr: MailboxReqHeader,
    pub cert_size: u32,
    pub cert: [u8; PopulateIdevEcc384CertReq::MAX_CERT_SIZE], // variable length
}
impl PopulateIdevEcc384CertReq {
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
impl Default for PopulateIdevEcc384CertReq {
    fn default() -> Self {
        Self {
            hdr: MailboxReqHeader::default(),
            cert_size: 0,
            cert: [0u8; PopulateIdevEcc384CertReq::MAX_CERT_SIZE],
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

#[repr(C)]
#[derive(Debug, PartialEq, Eq, FromBytes, Immutable, KnownLayout, IntoBytes)]
pub struct QuotePcrsFlags(u32);

bitflags! {
    impl QuotePcrsFlags: u32 {
        const ECC_SIGNATURE = 0b0000_0001;
        const MLDSA_SIGNATURE = 0b0000_0010;
    }
}

/// QUOTE_PCRS input arguments
#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, Immutable, KnownLayout, PartialEq, Eq)]
pub struct QuotePcrsReq {
    pub hdr: MailboxReqHeader,
    pub nonce: [u8; 32],
    pub flags: QuotePcrsFlags,
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
    pub digest: [u8; 64],
    pub reset_ctrs: [u32; 32],
    pub ecc_signature_r: [u8; 48],
    pub ecc_signature_s: [u8; 48],
    pub mldsa_signature: [u8; MLDSA87_SIGNATURE_BYTE_SIZE],
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
    const ID: CommandId = CommandId::GET_IDEV_ECC384_CSR;
    type Resp = GetIdevCsrResp;
}

pub type GetIdevCsrResp = VarSizeDataResp;

// GET_IDEVID_MLDSA_CSR
#[repr(C)]
#[derive(Default, Debug, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct GetIdevMldsaCsrReq {
    pub hdr: MailboxReqHeader,
}

impl Request for GetIdevMldsaCsrReq {
    const ID: CommandId = CommandId::GET_IDEV_MLDSA87_CSR;
    type Resp = GetIdevMldsaCsrResp;
}

pub type GetIdevMldsaCsrResp = VarSizeDataResp;

// GET_FMC_ALIAS_CSR
#[repr(C)]
#[derive(Default, Debug, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct GetFmcAliasCsrReq {
    pub hdr: MailboxReqHeader,
}

impl Request for GetFmcAliasCsrReq {
    const ID: CommandId = CommandId::GET_FMC_ALIAS_ECC384_CSR;
    type Resp = GetFmcAliasCsrResp;
}

pub type GetFmcAliasCsrResp = VarSizeDataResp;

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

// SIGN_WITH_EXPORTED_MLDSA
#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct SignWithExportedMldsaReq {
    pub hdr: MailboxReqHeader,
    pub exported_cdi_handle: [u8; Self::EXPORTED_CDI_MAX_SIZE],
    pub tbs: [u8; Self::MAX_DIGEST_SIZE],
}

impl Default for SignWithExportedMldsaReq {
    fn default() -> Self {
        Self {
            hdr: MailboxReqHeader::default(),
            exported_cdi_handle: [0u8; Self::EXPORTED_CDI_MAX_SIZE],
            tbs: [0u8; Self::MAX_DIGEST_SIZE],
        }
    }
}

impl SignWithExportedMldsaReq {
    pub const EXPORTED_CDI_MAX_SIZE: usize = 32;
    pub const MAX_DIGEST_SIZE: usize = 64;
}

impl Request for SignWithExportedMldsaReq {
    const ID: CommandId = CommandId::SIGN_WITH_EXPORTED_MLDSA;
    type Resp = SignWithExportedMldsaResp;
}

#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct SignWithExportedMldsaResp {
    pub hdr: MailboxRespHeader,
    pub derived_pubkey: [u8; Self::PUBKEY_SIZE],
    pub signature: [u8; Self::SIG_SIZE],
}

impl SignWithExportedMldsaResp {
    pub const SIG_SIZE: usize = 4628;
    pub const PUBKEY_SIZE: usize = 2592;
}

impl ResponseVarSize for SignWithExportedMldsaResp {}

impl Default for SignWithExportedMldsaResp {
    fn default() -> Self {
        Self {
            hdr: MailboxRespHeader::default(),
            signature: [0u8; Self::SIG_SIZE],
            derived_pubkey: [0u8; Self::PUBKEY_SIZE],
        }
    }
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

impl From<ImageHashSource> for u32 {
    fn from(val: ImageHashSource) -> Self {
        match val {
            ImageHashSource::InRequest => 1,
            ImageHashSource::ShaAcc => 2,
            _ => 0,
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

// MANUF_DEBUG_UNLOCK_REQ_TOKEN
#[repr(C)]
#[derive(Debug, FromBytes, Immutable, IntoBytes, KnownLayout, PartialEq, Eq, Default)]
pub struct ManufDebugUnlockTokenReq {
    pub hdr: MailboxReqHeader,
    pub token: [u8; 32],
}
impl Request for ManufDebugUnlockTokenReq {
    const ID: CommandId = CommandId::MANUF_DEBUG_UNLOCK_REQ_TOKEN;
    type Resp = MailboxRespHeader;
}

// PRODUCTION_AUTH_DEBUG_UNLOCK_REQ
#[repr(C)]
#[derive(Debug, FromBytes, Immutable, IntoBytes, KnownLayout, PartialEq, Eq, Default)]
pub struct ProductionAuthDebugUnlockReq {
    pub hdr: MailboxReqHeader,
    pub length: u32,       // Length (in DWORDs)
    pub unlock_level: u8,  // Debug unlock Level 1-8
    pub reserved: [u8; 3], // Reserved (3 bytes)
}

impl Request for ProductionAuthDebugUnlockReq {
    const ID: CommandId = CommandId::PRODUCTION_AUTH_DEBUG_UNLOCK_REQ;
    type Resp = ProductionAuthDebugUnlockChallenge;
}

// PRODUCTION_AUTH_DEBUG_UNLOCK_CHALLENGE
#[repr(C)]
#[derive(Debug, FromBytes, Immutable, IntoBytes, KnownLayout, PartialEq, Eq)]
pub struct ProductionAuthDebugUnlockChallenge {
    pub hdr: MailboxRespHeader,
    pub length: u32,                        // Length (in DWORDs)
    pub unique_device_identifier: [u8; 32], // Device identifier of the Caliptra Device
    pub challenge: [u8; 48],                // Random number
}
impl Default for ProductionAuthDebugUnlockChallenge {
    fn default() -> Self {
        Self {
            hdr: Default::default(),
            length: 0,
            unique_device_identifier: Default::default(),
            challenge: [0; 48],
        }
    }
}
impl Response for ProductionAuthDebugUnlockChallenge {}

// PRODUCTION_AUTH_DEBUG_UNLOCK_TOKEN
#[repr(C)]
#[derive(Debug, FromBytes, Immutable, IntoBytes, KnownLayout, PartialEq, Eq)]
pub struct ProductionAuthDebugUnlockToken {
    pub hdr: MailboxReqHeader,
    pub length: u32,                        // Length (in DWORDs)
    pub unique_device_identifier: [u8; 32], // Device identifier of the Caliptra Device
    pub unlock_level: u8,                   // Debug unlock Level (1-8)
    pub reserved: [u8; 3],                  // Reserved
    pub challenge: [u8; 48],                // Random number
    pub ecc_public_key: [u32; 24], // ECC public key (in hardware format i.e. little endian)
    pub mldsa_public_key: [u32; 648], // MLDSA public key (in hardware format i.e. little endian)
    // ECC P-384 signature of the Message hashed using SHA2-384 (in hardware format i.e. little endian)
    // R-Coordinate: Random Point (48 bytes) S-Coordinate: Proof (48 bytes)
    pub ecc_signature: [u32; 24],
    // MLDSA signature of the Message hashed using SHA2-512. (4627 bytes + 1 Reserved byte) (in hardware format i.e. little endian)
    pub mldsa_signature: [u32; 1157],
}
impl Default for ProductionAuthDebugUnlockToken {
    fn default() -> Self {
        Self {
            hdr: Default::default(),
            reserved: Default::default(),
            length: Default::default(),
            unique_device_identifier: Default::default(),
            unlock_level: Default::default(),
            challenge: [0; 48],
            ecc_public_key: [0; 24],
            mldsa_public_key: [0; 648],
            ecc_signature: [0; 24],
            mldsa_signature: [0; 1157],
        }
    }
}
impl Request for ProductionAuthDebugUnlockToken {
    const ID: CommandId = CommandId::PRODUCTION_AUTH_DEBUG_UNLOCK_TOKEN; // TODO
    type Resp = MailboxRespHeader; // TODO Check
}

pub const CMK_MAX_KEY_SIZE_BITS: usize = 512;
pub const CMK_SIZE_BYTES: usize = 128;
/// CMK is an opaque (encrypted) wrapper around a key.
#[derive(Clone, Debug, FromBytes, Immutable, IntoBytes, KnownLayout, PartialEq, Eq)]
pub struct Cmk(pub [u8; CMK_SIZE_BYTES]);

impl Default for Cmk {
    fn default() -> Self {
        Self([0u8; CMK_SIZE_BYTES])
    }
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CmKeyUsage {
    Reserved = 0,
    Hmac = 1,
    HKDF = 2,
    AES = 3,
}

impl From<u32> for CmKeyUsage {
    fn from(val: u32) -> Self {
        match val {
            1_u32 => CmKeyUsage::Hmac,
            2_u32 => CmKeyUsage::HKDF,
            3_u32 => CmKeyUsage::AES,
            _ => CmKeyUsage::Reserved,
        }
    }
}

impl From<CmKeyUsage> for u32 {
    fn from(value: CmKeyUsage) -> Self {
        match value {
            CmKeyUsage::Hmac => 1,
            CmKeyUsage::HKDF => 2,
            CmKeyUsage::AES => 3,
            _ => 0,
        }
    }
}

// CM_IMPORT
#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct CmImportReq {
    pub hdr: MailboxReqHeader,
    pub key_usage: u32,
    pub input_size: u32,
    pub input: [u8; Self::MAX_KEY_SIZE],
}

impl Default for CmImportReq {
    fn default() -> Self {
        Self {
            hdr: MailboxReqHeader::default(),
            key_usage: 0,
            input_size: 0,
            input: [0u8; Self::MAX_KEY_SIZE],
        }
    }
}

impl CmImportReq {
    pub const MAX_KEY_SIZE: usize = CMK_MAX_KEY_SIZE_BITS / 8;

    pub fn as_bytes_partial(&self) -> CaliptraResult<&[u8]> {
        if self.input_size as usize > Self::MAX_KEY_SIZE {
            return Err(CaliptraError::RUNTIME_MAILBOX_API_REQUEST_DATA_LEN_TOO_LARGE);
        }
        let unused_byte_count = Self::MAX_KEY_SIZE - self.input_size as usize;
        Ok(&self.as_bytes()[..size_of::<Self>() - unused_byte_count])
    }

    pub fn as_bytes_partial_mut(&mut self) -> CaliptraResult<&mut [u8]> {
        if self.input_size as usize > Self::MAX_KEY_SIZE {
            return Err(CaliptraError::RUNTIME_MAILBOX_API_REQUEST_DATA_LEN_TOO_LARGE);
        }
        let unused_byte_count = Self::MAX_KEY_SIZE - self.input_size as usize;
        Ok(&mut self.as_mut_bytes()[..size_of::<Self>() - unused_byte_count])
    }
}

impl Request for CmImportReq {
    const ID: CommandId = CommandId::CM_IMPORT;
    type Resp = CmImportResp;
}

#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct CmImportResp {
    pub hdr: MailboxRespHeader,
    pub cmk: Cmk,
}

impl Response for CmImportResp {}

/// CM_STATUS response
#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct CmStatusResp {
    pub hdr: MailboxRespHeader,
    pub used_usage_storage: u32,
    pub total_usage_storage: u32,
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CmHashAlgorithm {
    Reserved = 0,
    Sha384 = 1,
    Sha512 = 2,
}

impl From<u32> for CmHashAlgorithm {
    fn from(val: u32) -> Self {
        match val {
            1_u32 => CmHashAlgorithm::Sha384,
            2_u32 => CmHashAlgorithm::Sha512,
            _ => CmHashAlgorithm::Reserved,
        }
    }
}

impl From<CmHashAlgorithm> for u32 {
    fn from(value: CmHashAlgorithm) -> Self {
        match value {
            CmHashAlgorithm::Sha384 => 1,
            CmHashAlgorithm::Sha512 => 2,
            _ => 0,
        }
    }
}

// CM_SHA_INIT
#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct CmShaInitReq {
    pub hdr: MailboxReqHeader,
    pub hash_algorithm: u32,
    pub input_size: u32,
    pub input: [u8; MAX_CMB_DATA_SIZE],
}

impl Default for CmShaInitReq {
    fn default() -> Self {
        Self {
            hdr: MailboxReqHeader::default(),
            hash_algorithm: 0,
            input_size: 0,
            input: [0u8; MAX_CMB_DATA_SIZE],
        }
    }
}

impl CmShaInitReq {
    pub fn as_bytes_partial(&self) -> CaliptraResult<&[u8]> {
        if self.input_size as usize > MAX_CMB_DATA_SIZE {
            return Err(CaliptraError::RUNTIME_MAILBOX_API_REQUEST_DATA_LEN_TOO_LARGE);
        }
        let unused_byte_count = MAX_CMB_DATA_SIZE - self.input_size as usize;
        Ok(&self.as_bytes()[..size_of::<Self>() - unused_byte_count])
    }

    pub fn as_bytes_partial_mut(&mut self) -> CaliptraResult<&mut [u8]> {
        if self.input_size as usize > MAX_CMB_DATA_SIZE {
            return Err(CaliptraError::RUNTIME_MAILBOX_API_REQUEST_DATA_LEN_TOO_LARGE);
        }
        let unused_byte_count = MAX_CMB_DATA_SIZE - self.input_size as usize;
        Ok(&mut self.as_mut_bytes()[..size_of::<Self>() - unused_byte_count])
    }
}

impl Request for CmShaInitReq {
    const ID: CommandId = CommandId::CM_SHA_INIT;
    type Resp = CmShaInitResp;
}

#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct CmShaInitResp {
    pub hdr: MailboxRespHeader,
    pub context: [u8; CMB_SHA_CONTEXT_SIZE],
}

impl Default for CmShaInitResp {
    fn default() -> Self {
        Self {
            hdr: MailboxRespHeader::default(),
            context: [0u8; CMB_SHA_CONTEXT_SIZE],
        }
    }
}

impl Response for CmShaInitResp {}

// CM_SHA_UPDATE
#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct CmShaUpdateReq {
    pub hdr: MailboxReqHeader,
    pub context: [u8; CMB_SHA_CONTEXT_SIZE],
    pub input_size: u32,
    pub input: [u8; MAX_CMB_DATA_SIZE],
}

impl Default for CmShaUpdateReq {
    fn default() -> Self {
        Self {
            hdr: MailboxReqHeader::default(),
            context: [0u8; CMB_SHA_CONTEXT_SIZE],
            input_size: 0,
            input: [0u8; MAX_CMB_DATA_SIZE],
        }
    }
}

impl CmShaUpdateReq {
    pub fn as_bytes_partial(&self) -> CaliptraResult<&[u8]> {
        if self.input_size as usize > MAX_CMB_DATA_SIZE {
            return Err(CaliptraError::RUNTIME_MAILBOX_API_REQUEST_DATA_LEN_TOO_LARGE);
        }
        let unused_byte_count = MAX_CMB_DATA_SIZE - self.input_size as usize;
        Ok(&self.as_bytes()[..size_of::<Self>() - unused_byte_count])
    }

    pub fn as_bytes_partial_mut(&mut self) -> CaliptraResult<&mut [u8]> {
        if self.input_size as usize > MAX_CMB_DATA_SIZE {
            return Err(CaliptraError::RUNTIME_MAILBOX_API_REQUEST_DATA_LEN_TOO_LARGE);
        }
        let unused_byte_count = MAX_CMB_DATA_SIZE - self.input_size as usize;
        Ok(&mut self.as_mut_bytes()[..size_of::<Self>() - unused_byte_count])
    }
}

impl Request for CmShaUpdateReq {
    const ID: CommandId = CommandId::CM_SHA_UPDATE;
    type Resp = CmShaInitResp; // We can reuse the same response struct for update and init.
}

// CM_SHA_FINAL
#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct CmShaFinalReq {
    pub hdr: MailboxReqHeader,
    pub context: [u8; CMB_SHA_CONTEXT_SIZE],
    pub input_size: u32,
    pub input: [u8; MAX_CMB_DATA_SIZE],
}

impl Default for CmShaFinalReq {
    fn default() -> Self {
        Self {
            hdr: MailboxReqHeader::default(),
            context: [0u8; CMB_SHA_CONTEXT_SIZE],
            input_size: 0,
            input: [0u8; MAX_CMB_DATA_SIZE],
        }
    }
}

impl CmShaFinalReq {
    pub fn as_bytes_partial(&self) -> CaliptraResult<&[u8]> {
        if self.input_size as usize > MAX_CMB_DATA_SIZE {
            return Err(CaliptraError::RUNTIME_MAILBOX_API_REQUEST_DATA_LEN_TOO_LARGE);
        }
        let unused_byte_count = MAX_CMB_DATA_SIZE - self.input_size as usize;
        Ok(&self.as_bytes()[..size_of::<Self>() - unused_byte_count])
    }

    pub fn as_bytes_partial_mut(&mut self) -> CaliptraResult<&mut [u8]> {
        if self.input_size as usize > MAX_CMB_DATA_SIZE {
            return Err(CaliptraError::RUNTIME_MAILBOX_API_REQUEST_DATA_LEN_TOO_LARGE);
        }
        let unused_byte_count = MAX_CMB_DATA_SIZE - self.input_size as usize;
        Ok(&mut self.as_mut_bytes()[..size_of::<Self>() - unused_byte_count])
    }
}

impl Request for CmShaFinalReq {
    const ID: CommandId = CommandId::CM_SHA_FINAL;
    type Resp = CmShaFinalResp; // We can reuse the same response struct for update and init.
}

#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct CmShaFinalResp {
    pub hdr: MailboxRespHeaderVarSize,
    pub hash: [u8; SHA512_DIGEST_BYTE_SIZE],
}

impl Default for CmShaFinalResp {
    fn default() -> Self {
        Self {
            hdr: MailboxRespHeaderVarSize::default(),
            hash: [0u8; SHA512_DIGEST_BYTE_SIZE],
        }
    }
}

impl ResponseVarSize for CmShaFinalResp {}

#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, Immutable, KnownLayout, PartialEq, Eq)]
pub struct CmRandomGenerateReq {
    pub hdr: MailboxReqHeader,
    pub size: u32,
}

impl Request for CmRandomGenerateReq {
    const ID: CommandId = CommandId::CM_RANDOM_GENERATE;
    type Resp = CmRandomGenerateResp;
}

#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct CmRandomGenerateResp {
    pub hdr: MailboxRespHeaderVarSize,
    pub data: [u8; MAX_CMB_DATA_SIZE],
}

impl Default for CmRandomGenerateResp {
    fn default() -> Self {
        Self {
            hdr: MailboxRespHeaderVarSize::default(),
            data: [0u8; MAX_CMB_DATA_SIZE],
        }
    }
}

impl ResponseVarSize for CmRandomGenerateResp {}

// CM_RANDOM_STIR
#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct CmRandomStirReq {
    pub hdr: MailboxReqHeader,
    pub input_size: u32,
    pub input: [u8; MAX_CMB_DATA_SIZE],
}

impl Default for CmRandomStirReq {
    fn default() -> Self {
        Self {
            hdr: MailboxReqHeader::default(),
            input_size: 0,
            input: [0u8; MAX_CMB_DATA_SIZE],
        }
    }
}

impl CmRandomStirReq {
    pub fn as_bytes_partial(&self) -> CaliptraResult<&[u8]> {
        if self.input_size as usize > MAX_CMB_DATA_SIZE {
            return Err(CaliptraError::RUNTIME_MAILBOX_API_REQUEST_DATA_LEN_TOO_LARGE);
        }
        let unused_byte_count = MAX_CMB_DATA_SIZE - self.input_size as usize;
        Ok(&self.as_bytes()[..size_of::<Self>() - unused_byte_count])
    }

    pub fn as_bytes_partial_mut(&mut self) -> CaliptraResult<&mut [u8]> {
        if self.input_size as usize > MAX_CMB_DATA_SIZE {
            return Err(CaliptraError::RUNTIME_MAILBOX_API_REQUEST_DATA_LEN_TOO_LARGE);
        }
        let unused_byte_count = MAX_CMB_DATA_SIZE - self.input_size as usize;
        Ok(&mut self.as_mut_bytes()[..size_of::<Self>() - unused_byte_count])
    }
}

impl Request for CmRandomStirReq {
    const ID: CommandId = CommandId::CM_RANDOM_STIR;
    type Resp = MailboxRespHeader;
}

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
    const MAILBOX_SIZE: u32 = 256 * 1024;

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
