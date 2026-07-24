// Licensed under the Apache-2.0 license

#![allow(clippy::upper_case_acronyms)]

use bitflags::bitflags;
use caliptra_error::{CaliptraError, CaliptraResult};
#[cfg(feature = "mldsa_attestation")]
use caliptra_mldsa::{MLDSA87_MU_BYTES, MLDSA87_PRIVATE_SEED_BYTES};
use caliptra_mldsa::{MLDSA87_PUBLIC_KEY_BYTES, MLDSA87_SIGNATURE_BYTES};
#[cfg(feature = "mldsa_attestation")]
use core::mem::size_of;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

use crate::CaliptraApiError;
use caliptra_registers::mbox;
use ureg::MmioMut;

/// PQ IDevID seed size in bytes for SET_PQ_SEED.
#[cfg(feature = "mldsa_attestation")]
pub const SET_PQ_SEED_SEED_SIZE: usize = MLDSA87_PRIVATE_SEED_BYTES;

#[derive(PartialEq, Eq)]
pub struct CommandId(pub u32);
/// Sentinel id for a command whose `CommandId` is compiled out under the current
/// feature set. `u32::MAX` is not a valid FourCC command id, so it never matches
/// a real request; the reserved opcode slot keeps every later index fixed.
/// Also rejected explicitly by [`CommandId::to_opcode`], so it is referenced in
/// every feature configuration.
const NO_CMD: u32 = u32::MAX;

/// Defines the dispatchable mailbox commands from a single list, keeping the
/// `CommandId` constants, the dense [`op`] opcodes, the `OPCODE_CMDS` lookup
/// table, and [`CommandId::to_opcode`] in lockstep so they cannot drift.
///
/// Each entry `NAME = id` becomes `CommandId::NAME` and opcode `op::NAME` (its
/// index in the list). A `#[cfg(..)]` entry reserves its opcode slot with
/// [`struct@NO_CMD`] when compiled out, so indices stay fixed across feature
/// configurations. `FIRMWARE_LOAD` is intentionally excluded: it is handled
/// before opcode dispatch, so it has no opcode.
macro_rules! mailbox_commands {
    ( $( $(#[cfg($cfg:meta)])? $name:ident = $id:literal ),* $(,)? ) => {
        impl CommandId {
            $( $(#[cfg($cfg)])? pub const $name: Self = Self($id); )*

            /// Resolve this command id to its dense opcode (its index in the
            /// `OPCODE_CMDS` table), or `None` if it is not a dispatchable
            /// command.
            pub fn to_opcode(&self) -> Option<u8> {
                // NO_CMD reserves the opcode slots of feature-gated-out commands.
                // Guard it so a request literally carrying that value resolves to
                // `None` (not a spurious hit on a reserved slot) in every config.
                if self.0 == NO_CMD {
                    return None;
                }
                OPCODE_CMDS
                    .iter()
                    .position(|&id| id == self.0)
                    .map(|i| i as u8)
            }
        }

        /// Compile-time numbering source for [`op`]; carries no runtime cost
        /// (only used in `const` casts, never materialized).
        #[allow(dead_code, non_camel_case_types)]
        #[repr(u8)]
        enum Opcode { $($name),* }

        /// Dense `u8` opcode for each dispatchable command, equal to the
        /// command's index in `OPCODE_CMDS`. Matching on these compiles to a
        /// jump table rather than a ladder of 32-bit `CommandId` compares.
        pub mod op {
            #![allow(dead_code)]
            use super::Opcode;
            $( pub const $name: u8 = Opcode::$name as u8; )*
        }

        /// Wire command ids indexed by opcode. Slots for commands compiled out
        /// under the current feature set hold [`struct@NO_CMD`] to keep every
        /// index fixed.
        const OPCODE_CMDS: &[u32] = &[
            $(
                $(#[cfg($cfg)])? $id,
                $( #[cfg(not($cfg))] NO_CMD, )?
            )*
        ];
    };
}

impl CommandId {
    pub const FIRMWARE_LOAD: Self = Self(0x46574C44); // "FWLD"
}

// Note: These are inadvertently recognized as acronyms due to being within a macro statement.  As
// such disable the lint.
mailbox_commands! {
    GET_IDEV_CERT = 0x49444543, // "IDEC"
    #[cfg(feature = "mldsa_attestation")]
    GET_PQ_CERT = 0x47505143, // "GPQC"
    GET_IDEV_INFO = 0x49444549, // "IDEI"
    POPULATE_IDEV_CERT = 0x49444550, // "IDEP"
    #[cfg(feature = "mldsa_attestation")]
    POPULATE_PQ_CERT = 0x50505143, // "PPQC"
    GET_LDEV_CERT = 0x4C444556, // "LDEV"
    GET_FMC_ALIAS_CERT = 0x43455246, // "CERF"
    GET_RT_ALIAS_CERT = 0x43455252, // "CERR"
    ECDSA384_VERIFY = 0x53494756, // "SIGV"
    LMS_VERIFY = 0x4C4D5356, // "LMSV"
    MLDSA87_SIGNATURE_VERIFY = 0x4D445356, // "MDSV"
    STASH_MEASUREMENT = 0x4D454153, // "MEAS"
    INVOKE_DPE = 0x44504543, // "DPEC"
    DISABLE_ATTESTATION = 0x4453424C, // "DSBL"
    #[cfg(feature = "mldsa_attestation")]
    SET_PQ_SEED = 0x5051_5344, // "PQSD"
    FW_INFO = 0x494E464F, // "INFO"
    DPE_TAG_TCI = 0x54514754, // "TAGT"
    DPE_GET_TAGGED_TCI = 0x47544744, // "GTGD"
    INCREMENT_PCR_RESET_COUNTER = 0x50435252, // "PCRR"
    QUOTE_PCRS = 0x50435251, // "PCRQ"
    EXTEND_PCR = 0x50435245, // "PCRE"
    ADD_SUBJECT_ALT_NAME = 0x414C544E, // "ALTN"
    CERTIFY_KEY_EXTENDED = 0x434B4558, // "CKEX"
    #[cfg(feature = "mldsa_attestation")]
    INVOKE_DPE_MLDSA87 = 0x4D4C4450, // "MLDP"
    #[cfg(feature = "mldsa_attestation")]
    GET_PQ_CSR = 0x50514353, // "PQCS"
    #[cfg(feature = "mldsa_attestation")]
    GET_PQ_INFO = 0x5051_494E, // "PQIN"
    #[cfg(feature = "mldsa_attestation")]
    CERTIFY_KEY_EXTENDED_MLDSA87 = 0x434B454D, // "CKEM"
    // FIPS module commands.
    VERSION = 0x4650_5652, // "FPVR" (status)
    SELF_TEST_START = 0x4650_4C54, // "FPST"
    SELF_TEST_GET_RESULTS = 0x4650_4C67, // "FPGR"
    SHUTDOWN = 0x4650_5344, // "FPSD"
    CAPABILITIES = 0x4341_5053, // "CAPS"
    SET_AUTH_MANIFEST = 0x4154_4D4E, // "ATMN"
    AUTHORIZE_AND_STASH = 0x4154_5348, // "ATSH"
    GET_IDEV_CSR = 0x4944_4352, // "IDCR"
    GET_FMC_ALIAS_CSR = 0x464D_4352, // "FMCR"
    SIGN_WITH_EXPORTED_ECDSA = 0x5357_4545, // "SWEE"
    REVOKE_EXPORTED_CDI_HANDLE = 0x5256_4348, // "RVCH"
    #[cfg(feature = "mldsa_attestation")]
    SIGN_WITH_EXPORTED_MLDSA = 0x5357_4D4C, // "SWML"
    GET_PCR_LOG = 0x504C_4F47, // "PLOG"
    REALLOCATE_DPE_CONTEXT_LIMITS = 0x5243_5458, // "RCTX"
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

pub fn populate_checksum(msg: &mut [u8]) {
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
    #[cfg(feature = "mldsa_attestation")]
    InvokeDpeMldsa87Command(InvokeDpeMldsa87Resp),
    #[cfg(feature = "mldsa_attestation")]
    GetPqCsr(GetPqCsrResp),
    #[cfg(feature = "mldsa_attestation")]
    GetPqInfo(GetPqInfoResp),
    #[cfg(feature = "mldsa_attestation")]
    CertifyKeyExtendedMldsa87(CertifyKeyExtendedMldsa87Resp),
    AuthorizeAndStash(AuthorizeAndStashResp),
    GetIdevCsr(GetIdevCsrResp),
    GetFmcAliasCsr(GetFmcAliasCsrResp),
    SignWithExportedEcdsa(SignWithExportedEcdsaResp),
    RevokeExportedCdiHandle(RevokeExportedCdiHandleResp),
    #[cfg(feature = "mldsa_attestation")]
    SignWithExportedMldsa(SignWithExportedMldsaResp),
    ReallocateDpeContextLimits(ReallocateDpeContextLimitsResp),
    GetPcrLog(GetPcrLogResp),
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
            #[cfg(feature = "mldsa_attestation")]
            MailboxResp::InvokeDpeMldsa87Command(resp) => resp.as_bytes_partial(),
            #[cfg(feature = "mldsa_attestation")]
            MailboxResp::GetPqCsr(resp) => Ok(resp.as_bytes()),
            #[cfg(feature = "mldsa_attestation")]
            MailboxResp::GetPqInfo(resp) => Ok(resp.as_bytes()),
            #[cfg(feature = "mldsa_attestation")]
            MailboxResp::CertifyKeyExtendedMldsa87(resp) => Ok(resp.as_bytes()),
            MailboxResp::AuthorizeAndStash(resp) => Ok(resp.as_bytes()),
            MailboxResp::GetIdevCsr(resp) => Ok(resp.as_bytes()),
            MailboxResp::GetFmcAliasCsr(resp) => Ok(resp.as_bytes()),
            MailboxResp::SignWithExportedEcdsa(resp) => Ok(resp.as_bytes()),
            MailboxResp::RevokeExportedCdiHandle(resp) => Ok(resp.as_bytes()),
            #[cfg(feature = "mldsa_attestation")]
            MailboxResp::SignWithExportedMldsa(resp) => Ok(resp.as_bytes()),
            MailboxResp::ReallocateDpeContextLimits(resp) => Ok(resp.as_bytes()),
            MailboxResp::GetPcrLog(resp) => Ok(resp.as_bytes()),
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
            #[cfg(feature = "mldsa_attestation")]
            MailboxResp::InvokeDpeMldsa87Command(resp) => resp.as_bytes_partial_mut(),
            #[cfg(feature = "mldsa_attestation")]
            MailboxResp::GetPqCsr(resp) => Ok(resp.as_mut_bytes()),
            #[cfg(feature = "mldsa_attestation")]
            MailboxResp::GetPqInfo(resp) => Ok(resp.as_mut_bytes()),
            #[cfg(feature = "mldsa_attestation")]
            MailboxResp::CertifyKeyExtendedMldsa87(resp) => Ok(resp.as_mut_bytes()),
            MailboxResp::AuthorizeAndStash(resp) => Ok(resp.as_mut_bytes()),
            MailboxResp::GetIdevCsr(resp) => Ok(resp.as_mut_bytes()),
            MailboxResp::GetFmcAliasCsr(resp) => Ok(resp.as_mut_bytes()),
            MailboxResp::SignWithExportedEcdsa(resp) => Ok(resp.as_mut_bytes()),
            MailboxResp::RevokeExportedCdiHandle(resp) => Ok(resp.as_mut_bytes()),
            #[cfg(feature = "mldsa_attestation")]
            MailboxResp::SignWithExportedMldsa(resp) => Ok(resp.as_mut_bytes()),
            MailboxResp::ReallocateDpeContextLimits(resp) => Ok(resp.as_mut_bytes()),
            MailboxResp::GetPcrLog(resp) => Ok(resp.as_mut_bytes()),
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
    Mldsa87Verify(Mldsa87VerifyReq),
    GetLdevCert(GetLdevCertReq),
    StashMeasurement(StashMeasurementReq),
    InvokeDpeCommand(InvokeDpeReq),
    FipsVersion(MailboxReqHeader),
    FwInfo(MailboxReqHeader),
    PopulateIdevCert(PopulateIdevCertReq),
    #[cfg(feature = "mldsa_attestation")]
    PopulatePqCert(PopulatePqCertReq),
    GetIdevCert(GetIdevCertReq),
    #[cfg(feature = "mldsa_attestation")]
    GetPqCert(GetPqCertReq),
    TagTci(TagTciReq),
    GetTaggedTci(GetTaggedTciReq),
    GetFmcAliasCert(GetFmcAliasCertReq),
    GetRtAliasCert(GetRtAliasCertReq),
    IncrementPcrResetCounter(IncrementPcrResetCounterReq),
    QuotePcrs(QuotePcrsReq),
    #[cfg(feature = "mldsa_attestation")]
    SetPqSeed(SetPqSeedReq),
    #[cfg(feature = "mldsa_attestation")]
    InvokeDpeMldsa87Command(InvokeDpeMldsa87Req),
    #[cfg(feature = "mldsa_attestation")]
    CertifyKeyExtendedMldsa87(CertifyKeyExtendedMldsa87Req),
    ExtendPcr(ExtendPcrReq),
    AddSubjectAltName(AddSubjectAltNameReq),
    CertifyKeyExtended(CertifyKeyExtendedReq),
    SetAuthManifest(SetAuthManifestReq),
    AuthorizeAndStash(AuthorizeAndStashReq),
    SignWithExportedEcdsa(SignWithExportedEcdsaReq),
    RevokeExportedCdiHandle(RevokeExportedCdiHandleReq),
    #[cfg(feature = "mldsa_attestation")]
    SignWithExportedMldsa(SignWithExportedMldsaReq),
    ReallocateDpeContextLimits(ReallocateDpeContextLimitsReq),
    GetPcrLog(MailboxReqHeader),
}

impl MailboxReq {
    pub fn as_bytes(&self) -> CaliptraResult<&[u8]> {
        match self {
            MailboxReq::EcdsaVerify(req) => Ok(req.as_bytes()),
            MailboxReq::LmsVerify(req) => Ok(req.as_bytes()),
            MailboxReq::Mldsa87Verify(req) => Ok(req.as_bytes()),
            MailboxReq::StashMeasurement(req) => Ok(req.as_bytes()),
            MailboxReq::InvokeDpeCommand(req) => req.as_bytes_partial(),
            MailboxReq::FipsVersion(req) => Ok(req.as_bytes()),
            MailboxReq::FwInfo(req) => Ok(req.as_bytes()),
            MailboxReq::GetLdevCert(req) => Ok(req.as_bytes()),
            MailboxReq::PopulateIdevCert(req) => req.as_bytes_partial(),
            #[cfg(feature = "mldsa_attestation")]
            MailboxReq::PopulatePqCert(req) => req.as_bytes_partial(),
            MailboxReq::GetIdevCert(req) => req.as_bytes_partial(),
            #[cfg(feature = "mldsa_attestation")]
            MailboxReq::GetPqCert(req) => req.as_bytes_partial(),
            MailboxReq::TagTci(req) => Ok(req.as_bytes()),
            MailboxReq::GetTaggedTci(req) => Ok(req.as_bytes()),
            MailboxReq::GetFmcAliasCert(req) => Ok(req.as_bytes()),
            MailboxReq::GetRtAliasCert(req) => Ok(req.as_bytes()),
            MailboxReq::IncrementPcrResetCounter(req) => Ok(req.as_bytes()),
            MailboxReq::QuotePcrs(req) => Ok(req.as_bytes()),
            #[cfg(feature = "mldsa_attestation")]
            MailboxReq::SetPqSeed(req) => Ok(req.as_bytes()),
            #[cfg(feature = "mldsa_attestation")]
            MailboxReq::InvokeDpeMldsa87Command(req) => req.as_bytes_partial(),
            #[cfg(feature = "mldsa_attestation")]
            MailboxReq::CertifyKeyExtendedMldsa87(req) => Ok(req.as_bytes()),
            MailboxReq::ExtendPcr(req) => Ok(req.as_bytes()),
            MailboxReq::AddSubjectAltName(req) => req.as_bytes_partial(),
            MailboxReq::CertifyKeyExtended(req) => Ok(req.as_bytes()),
            MailboxReq::SetAuthManifest(req) => Ok(req.as_bytes()),
            MailboxReq::AuthorizeAndStash(req) => Ok(req.as_bytes()),
            MailboxReq::SignWithExportedEcdsa(req) => Ok(req.as_bytes()),
            MailboxReq::RevokeExportedCdiHandle(req) => Ok(req.as_bytes()),
            #[cfg(feature = "mldsa_attestation")]
            MailboxReq::SignWithExportedMldsa(req) => req.as_bytes_partial(),
            MailboxReq::ReallocateDpeContextLimits(req) => Ok(req.as_bytes()),
            MailboxReq::GetPcrLog(req) => Ok(req.as_bytes()),
        }
    }

    pub fn as_mut_bytes(&mut self) -> CaliptraResult<&mut [u8]> {
        match self {
            MailboxReq::EcdsaVerify(req) => Ok(req.as_mut_bytes()),
            MailboxReq::LmsVerify(req) => Ok(req.as_mut_bytes()),
            MailboxReq::Mldsa87Verify(req) => Ok(req.as_mut_bytes()),
            MailboxReq::GetLdevCert(req) => Ok(req.as_mut_bytes()),
            MailboxReq::StashMeasurement(req) => Ok(req.as_mut_bytes()),
            MailboxReq::InvokeDpeCommand(req) => req.as_bytes_partial_mut(),
            MailboxReq::FipsVersion(req) => Ok(req.as_mut_bytes()),
            MailboxReq::FwInfo(req) => Ok(req.as_mut_bytes()),
            MailboxReq::PopulateIdevCert(req) => req.as_bytes_partial_mut(),
            #[cfg(feature = "mldsa_attestation")]
            MailboxReq::PopulatePqCert(req) => req.as_bytes_partial_mut(),
            MailboxReq::GetIdevCert(req) => req.as_bytes_partial_mut(),
            #[cfg(feature = "mldsa_attestation")]
            MailboxReq::GetPqCert(req) => req.as_bytes_partial_mut(),
            MailboxReq::TagTci(req) => Ok(req.as_mut_bytes()),
            MailboxReq::GetTaggedTci(req) => Ok(req.as_mut_bytes()),
            MailboxReq::GetFmcAliasCert(req) => Ok(req.as_mut_bytes()),
            MailboxReq::GetRtAliasCert(req) => Ok(req.as_mut_bytes()),
            MailboxReq::IncrementPcrResetCounter(req) => Ok(req.as_mut_bytes()),
            MailboxReq::QuotePcrs(req) => Ok(req.as_mut_bytes()),
            #[cfg(feature = "mldsa_attestation")]
            MailboxReq::SetPqSeed(req) => Ok(req.as_mut_bytes()),
            #[cfg(feature = "mldsa_attestation")]
            MailboxReq::InvokeDpeMldsa87Command(req) => req.as_bytes_partial_mut(),
            #[cfg(feature = "mldsa_attestation")]
            MailboxReq::CertifyKeyExtendedMldsa87(req) => Ok(req.as_mut_bytes()),
            MailboxReq::ExtendPcr(req) => Ok(req.as_mut_bytes()),
            MailboxReq::AddSubjectAltName(req) => req.as_bytes_partial_mut(),
            MailboxReq::CertifyKeyExtended(req) => Ok(req.as_mut_bytes()),
            MailboxReq::SetAuthManifest(req) => Ok(req.as_mut_bytes()),
            MailboxReq::AuthorizeAndStash(req) => Ok(req.as_mut_bytes()),
            MailboxReq::SignWithExportedEcdsa(req) => Ok(req.as_mut_bytes()),
            MailboxReq::RevokeExportedCdiHandle(req) => Ok(req.as_mut_bytes()),
            #[cfg(feature = "mldsa_attestation")]
            MailboxReq::SignWithExportedMldsa(req) => req.as_bytes_partial_mut(),
            MailboxReq::ReallocateDpeContextLimits(req) => Ok(req.as_mut_bytes()),
            MailboxReq::GetPcrLog(req) => Ok(req.as_mut_bytes()),
        }
    }

    pub fn cmd_code(&self) -> CommandId {
        match self {
            MailboxReq::EcdsaVerify(_) => CommandId::ECDSA384_VERIFY,
            MailboxReq::LmsVerify(_) => CommandId::LMS_VERIFY,
            MailboxReq::Mldsa87Verify(_) => CommandId::MLDSA87_SIGNATURE_VERIFY,
            MailboxReq::GetLdevCert(_) => CommandId::GET_LDEV_CERT,
            MailboxReq::StashMeasurement(_) => CommandId::STASH_MEASUREMENT,
            MailboxReq::InvokeDpeCommand(_) => CommandId::INVOKE_DPE,
            MailboxReq::FipsVersion(_) => CommandId::VERSION,
            MailboxReq::FwInfo(_) => CommandId::FW_INFO,
            MailboxReq::PopulateIdevCert(_) => CommandId::POPULATE_IDEV_CERT,
            #[cfg(feature = "mldsa_attestation")]
            MailboxReq::PopulatePqCert(_) => CommandId::POPULATE_PQ_CERT,
            MailboxReq::GetIdevCert(_) => CommandId::GET_IDEV_CERT,
            #[cfg(feature = "mldsa_attestation")]
            MailboxReq::GetPqCert(_) => CommandId::GET_PQ_CERT,
            MailboxReq::TagTci(_) => CommandId::DPE_TAG_TCI,
            MailboxReq::GetTaggedTci(_) => CommandId::DPE_GET_TAGGED_TCI,
            MailboxReq::GetFmcAliasCert(_) => CommandId::GET_FMC_ALIAS_CERT,
            MailboxReq::GetRtAliasCert(_) => CommandId::GET_RT_ALIAS_CERT,
            MailboxReq::IncrementPcrResetCounter(_) => CommandId::INCREMENT_PCR_RESET_COUNTER,
            MailboxReq::QuotePcrs(_) => CommandId::QUOTE_PCRS,
            #[cfg(feature = "mldsa_attestation")]
            MailboxReq::SetPqSeed(_) => CommandId::SET_PQ_SEED,
            #[cfg(feature = "mldsa_attestation")]
            MailboxReq::InvokeDpeMldsa87Command(_) => CommandId::INVOKE_DPE_MLDSA87,
            #[cfg(feature = "mldsa_attestation")]
            MailboxReq::CertifyKeyExtendedMldsa87(_) => CommandId::CERTIFY_KEY_EXTENDED_MLDSA87,
            MailboxReq::ExtendPcr(_) => CommandId::EXTEND_PCR,
            MailboxReq::AddSubjectAltName(_) => CommandId::ADD_SUBJECT_ALT_NAME,
            MailboxReq::CertifyKeyExtended(_) => CommandId::CERTIFY_KEY_EXTENDED,
            MailboxReq::SetAuthManifest(_) => CommandId::SET_AUTH_MANIFEST,
            MailboxReq::AuthorizeAndStash(_) => CommandId::AUTHORIZE_AND_STASH,
            MailboxReq::SignWithExportedEcdsa(_) => CommandId::SIGN_WITH_EXPORTED_ECDSA,
            MailboxReq::RevokeExportedCdiHandle(_) => CommandId::REVOKE_EXPORTED_CDI_HANDLE,
            #[cfg(feature = "mldsa_attestation")]
            MailboxReq::SignWithExportedMldsa(_) => CommandId::SIGN_WITH_EXPORTED_MLDSA,
            MailboxReq::ReallocateDpeContextLimits(_) => CommandId::REALLOCATE_DPE_CONTEXT_LIMITS,
            MailboxReq::GetPcrLog(_) => CommandId::GET_PCR_LOG,
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

// GET_PQ_CERT
#[cfg(feature = "mldsa_attestation")]
#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, Immutable, KnownLayout, PartialEq, Eq)]
pub struct GetPqCertReq {
    pub hdr: MailboxReqHeader,
    pub tbs_size: u32,
    pub signature: [u8; MLDSA87_SIGNATURE_BYTES],
    pub tbs: [u8; GetPqCertReq::DATA_MAX_SIZE], // variable length
}
#[cfg(feature = "mldsa_attestation")]
impl GetPqCertReq {
    // GetPqCertResp::DATA_MAX_SIZE - MAX_MLDSA87_SIG_DER_LEN + 2-byte padding for alignment
    pub const DATA_MAX_SIZE: usize = 3553;

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
#[cfg(feature = "mldsa_attestation")]
impl Default for GetPqCertReq {
    fn default() -> Self {
        Self {
            hdr: MailboxReqHeader::default(),
            tbs_size: 0,
            signature: [0u8; MLDSA87_SIGNATURE_BYTES],
            tbs: [0u8; GetPqCertReq::DATA_MAX_SIZE],
        }
    }
}

#[cfg(feature = "mldsa_attestation")]
#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, Immutable, KnownLayout, PartialEq, Eq)]
pub struct GetPqCertResp {
    pub hdr: MailboxRespHeader,
    pub cert_size: u32,
    pub cert: [u8; GetPqCertResp::DATA_MAX_SIZE], // variable length
}
#[cfg(feature = "mldsa_attestation")]
impl GetPqCertResp {
    pub const DATA_MAX_SIZE: usize = 8192;
}
#[cfg(feature = "mldsa_attestation")]
impl ResponseVarSize for GetPqCertResp {}

#[cfg(feature = "mldsa_attestation")]
impl Default for GetPqCertResp {
    fn default() -> Self {
        Self {
            hdr: MailboxRespHeader::default(),
            cert_size: 0,
            cert: [0u8; GetPqCertResp::DATA_MAX_SIZE],
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

// MLDSA87_SIGNATURE_VERIFY
//
// The message digest to verify against is taken from Caliptra's SHA
// accelerator (matching ECDSA384_VERIFY and LMS_VERIFY). Callers must
// stream the message through the SHA accelerator before issuing this
// command. Carrying the raw message in-band would put hashing outside
// the FIPS module boundary and is therefore disallowed.
#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, Immutable, KnownLayout, PartialEq, Eq)]
pub struct Mldsa87VerifyReq {
    pub hdr: MailboxReqHeader,
    pub pub_key: [u8; MLDSA87_PUBLIC_KEY_BYTES],
    pub signature: [u8; MLDSA87_SIGNATURE_BYTES],
    pub _pad: u8,
}
impl Request for Mldsa87VerifyReq {
    const ID: CommandId = CommandId::MLDSA87_SIGNATURE_VERIFY;
    type Resp = MailboxRespHeader;
}
impl Default for Mldsa87VerifyReq {
    fn default() -> Self {
        Self {
            hdr: MailboxReqHeader::default(),
            pub_key: [0u8; MLDSA87_PUBLIC_KEY_BYTES],
            signature: [0u8; MLDSA87_SIGNATURE_BYTES],
            _pad: 0,
        }
    }
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
    pub size: u32,
    pub certify_key_resp: [u8; CertifyKeyExtendedResp::CERTIFY_KEY_RESP_SIZE],
}
impl CertifyKeyExtendedResp {
    pub const CERTIFY_KEY_RESP_SIZE: usize = 25152;
}
impl Response for CertifyKeyExtendedResp {}

impl Default for CertifyKeyExtendedResp {
    fn default() -> Self {
        Self {
            hdr: MailboxRespHeader::default(),
            size: 0,
            certify_key_resp: [0u8; CertifyKeyExtendedResp::CERTIFY_KEY_RESP_SIZE],
        }
    }
}

impl CertifyKeyExtendedResp {
    pub fn as_bytes_partial(&self) -> CaliptraResult<&[u8]> {
        if self.size as usize > Self::CERTIFY_KEY_RESP_SIZE {
            return Err(CaliptraError::RUNTIME_MAILBOX_API_REQUEST_DATA_LEN_TOO_LARGE);
        }
        let unused_byte_count = Self::CERTIFY_KEY_RESP_SIZE - self.size as usize;
        Ok(&self.as_bytes()[..size_of::<Self>() - unused_byte_count])
    }
}

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
    pub const DATA_MAX_SIZE: usize = 25152;
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

// POPULATE_PQ_CERT
// No command-specific output args
#[cfg(feature = "mldsa_attestation")]
#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, Immutable, KnownLayout, PartialEq, Eq)]
pub struct PopulatePqCertReq {
    pub hdr: MailboxReqHeader,
    pub cert_size: u32,
    pub cert: [u8; PopulatePqCertReq::MAX_CERT_SIZE], // variable length
}
#[cfg(feature = "mldsa_attestation")]
impl PopulatePqCertReq {
    pub const MAX_CERT_SIZE: usize = 8192;

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
#[cfg(feature = "mldsa_attestation")]
impl Default for PopulatePqCertReq {
    fn default() -> Self {
        Self {
            hdr: MailboxReqHeader::default(),
            cert_size: 0,
            cert: [0u8; PopulatePqCertReq::MAX_CERT_SIZE],
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

// SET_PQ_SEED
#[cfg(feature = "mldsa_attestation")]
#[repr(C)]
#[derive(Default, Debug, IntoBytes, FromBytes, Immutable, KnownLayout, PartialEq, Eq)]
pub struct SetPqSeedReq {
    pub hdr: MailboxReqHeader,
    pub seed: [u8; SET_PQ_SEED_SEED_SIZE],
}

#[cfg(feature = "mldsa_attestation")]
const _: () =
    assert!(size_of::<SetPqSeedReq>() == size_of::<MailboxReqHeader>() + SET_PQ_SEED_SEED_SIZE);

#[cfg(feature = "mldsa_attestation")]
impl Request for SetPqSeedReq {
    const ID: CommandId = CommandId::SET_PQ_SEED;
    type Resp = MailboxRespHeader;
}

// INVOKE_DPE_MLDSA87
#[cfg(feature = "mldsa_attestation")]
#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, Immutable, KnownLayout, PartialEq, Eq)]
pub struct InvokeDpeMldsa87Req {
    pub hdr: MailboxReqHeader,
    pub data_size: u32,
    pub data: [u8; InvokeDpeMldsa87Req::DATA_MAX_SIZE], // variable length
}

#[cfg(feature = "mldsa_attestation")]
impl InvokeDpeMldsa87Req {
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
#[cfg(feature = "mldsa_attestation")]
impl Default for InvokeDpeMldsa87Req {
    fn default() -> Self {
        Self {
            hdr: MailboxReqHeader::default(),
            data_size: 0,
            data: [0u8; InvokeDpeMldsa87Req::DATA_MAX_SIZE],
        }
    }
}
#[cfg(feature = "mldsa_attestation")]
impl Request for InvokeDpeMldsa87Req {
    const ID: CommandId = CommandId::INVOKE_DPE_MLDSA87;
    type Resp = InvokeDpeMldsa87Resp;
}

#[cfg(feature = "mldsa_attestation")]
#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, Immutable, KnownLayout, PartialEq, Eq)]
pub struct InvokeDpeMldsa87Resp {
    pub hdr: MailboxRespHeader,
    pub data_size: u32,
    pub data: [u8; InvokeDpeMldsa87Resp::DATA_MAX_SIZE], // variable length
}
#[cfg(feature = "mldsa_attestation")]
impl InvokeDpeMldsa87Resp {
    pub const DATA_MAX_SIZE: usize = 25168;
}
#[cfg(feature = "mldsa_attestation")]
impl ResponseVarSize for InvokeDpeMldsa87Resp {}

#[cfg(feature = "mldsa_attestation")]
impl Default for InvokeDpeMldsa87Resp {
    fn default() -> Self {
        Self {
            hdr: MailboxRespHeader::default(),
            data_size: 0,
            data: [0u8; InvokeDpeMldsa87Resp::DATA_MAX_SIZE],
        }
    }
}

// GET_PQ_CSR
#[cfg(feature = "mldsa_attestation")]
#[repr(C)]
#[derive(Default, Debug, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct GetPqCsrReq {
    pub hdr: MailboxReqHeader,
}

#[cfg(feature = "mldsa_attestation")]
impl Request for GetPqCsrReq {
    const ID: CommandId = CommandId::GET_PQ_CSR;
    type Resp = GetPqCsrResp;
}

#[cfg(feature = "mldsa_attestation")]
#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct GetPqCsrResp {
    pub hdr: MailboxRespHeader,
    pub data_size: u32,
    pub data: [u8; Self::DATA_MAX_SIZE],
}
#[cfg(feature = "mldsa_attestation")]
impl GetPqCsrResp {
    pub const DATA_MAX_SIZE: usize = 12800;
}
#[cfg(feature = "mldsa_attestation")]
impl ResponseVarSize for GetPqCsrResp {}

#[cfg(feature = "mldsa_attestation")]
impl Default for GetPqCsrResp {
    fn default() -> Self {
        Self {
            hdr: MailboxRespHeader::default(),
            data_size: 0,
            data: [0u8; Self::DATA_MAX_SIZE],
        }
    }
}

// GET_PQ_INFO
// No command-specific input args
#[cfg(feature = "mldsa_attestation")]
#[repr(C)]
#[derive(Default, Debug, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct GetPqInfoReq {
    pub hdr: MailboxReqHeader,
}

#[cfg(feature = "mldsa_attestation")]
impl Request for GetPqInfoReq {
    const ID: CommandId = CommandId::GET_PQ_INFO;
    type Resp = GetPqInfoResp;
}

#[cfg(feature = "mldsa_attestation")]
#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct GetPqInfoResp {
    pub hdr: MailboxRespHeader,
    pub pq_pub_key: [u8; MLDSA87_PUBLIC_KEY_BYTES],
}
#[cfg(feature = "mldsa_attestation")]
impl Response for GetPqInfoResp {}

#[cfg(feature = "mldsa_attestation")]
impl Default for GetPqInfoResp {
    fn default() -> Self {
        Self {
            hdr: MailboxRespHeader::default(),
            pq_pub_key: [0u8; MLDSA87_PUBLIC_KEY_BYTES],
        }
    }
}

// CERTIFY_KEY_EXTENDED_MLDSA87
#[cfg(feature = "mldsa_attestation")]
#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, Immutable, KnownLayout, PartialEq, Eq)]
pub struct CertifyKeyExtendedMldsa87Req {
    pub hdr: MailboxReqHeader,
    pub flags: CertifyKeyExtendedFlags,
    pub certify_key_req: [u8; CertifyKeyExtendedMldsa87Req::CERTIFY_KEY_REQ_SIZE],
}
#[cfg(feature = "mldsa_attestation")]
impl CertifyKeyExtendedMldsa87Req {
    pub const CERTIFY_KEY_REQ_SIZE: usize = 72;
}
#[cfg(feature = "mldsa_attestation")]
impl Request for CertifyKeyExtendedMldsa87Req {
    const ID: CommandId = CommandId::CERTIFY_KEY_EXTENDED_MLDSA87;
    type Resp = CertifyKeyExtendedMldsa87Resp;
}

#[cfg(feature = "mldsa_attestation")]
#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, Immutable, KnownLayout, PartialEq, Eq)]
pub struct CertifyKeyExtendedMldsa87Resp {
    pub hdr: MailboxRespHeader,
    pub size: u32,
    pub certify_key_resp: [u8; CertifyKeyExtendedMldsa87Resp::CERTIFY_KEY_RESP_SIZE],
}
#[cfg(feature = "mldsa_attestation")]
impl CertifyKeyExtendedMldsa87Resp {
    pub const CERTIFY_KEY_RESP_SIZE: usize = 25152;
}
#[cfg(feature = "mldsa_attestation")]
impl Response for CertifyKeyExtendedMldsa87Resp {}

#[cfg(feature = "mldsa_attestation")]
impl Default for CertifyKeyExtendedMldsa87Resp {
    fn default() -> Self {
        Self {
            hdr: MailboxRespHeader::default(),
            size: 0,
            certify_key_resp: [0u8; CertifyKeyExtendedMldsa87Resp::CERTIFY_KEY_RESP_SIZE],
        }
    }
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
    pub const DATA_MAX_SIZE: usize = 768;
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

// SIGN_WITH_EXPORTED_MLDSA
//
// Signs with an ML-DSA-87 key pair derived from a previously exported CDI
// handle. Two signing modes are selected by `sign_mode`:
//   * `SIGN_MODE_DATA`        - `message[..message_size]` is the raw message to
//                               sign; the device computes mu internally.
//   * `SIGN_MODE_EXTERNAL_MU` - `message[..MU_SIZE]` is a caller-supplied
//                               external mu (`message_size` must equal MU_SIZE).
#[cfg(feature = "mldsa_attestation")]
#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct SignWithExportedMldsaReq {
    pub hdr: MailboxReqHeader,
    pub exported_cdi_handle: [u8; Self::EXPORTED_CDI_MAX_SIZE],
    pub sign_mode: u32,
    pub message_size: u32,
    pub message: [u8; Self::MAX_DATA_SIZE],
}

#[cfg(feature = "mldsa_attestation")]
impl Default for SignWithExportedMldsaReq {
    fn default() -> Self {
        Self {
            hdr: MailboxReqHeader::default(),
            exported_cdi_handle: [0u8; Self::EXPORTED_CDI_MAX_SIZE],
            sign_mode: Self::SIGN_MODE_DATA,
            message_size: 0,
            message: [0u8; Self::MAX_DATA_SIZE],
        }
    }
}

#[cfg(feature = "mldsa_attestation")]
impl SignWithExportedMldsaReq {
    pub const EXPORTED_CDI_MAX_SIZE: usize = 32;
    pub const MAX_DATA_SIZE: usize = 1024;
    /// Size of an external mu, occupying the first bytes of `message`.
    pub const MU_SIZE: usize = MLDSA87_MU_BYTES;

    /// `message[..message_size]` is the raw message to sign.
    pub const SIGN_MODE_DATA: u32 = 0;
    /// `message[..MU_SIZE]` is a caller-supplied external mu.
    pub const SIGN_MODE_EXTERNAL_MU: u32 = 1;

    /// Serialize only the populated prefix of the request (trailing unused
    /// `message` bytes are trimmed based on `message_size`).
    pub fn as_bytes_partial(&self) -> CaliptraResult<&[u8]> {
        if self.message_size as usize > Self::MAX_DATA_SIZE {
            return Err(CaliptraError::RUNTIME_MAILBOX_API_REQUEST_DATA_LEN_TOO_LARGE);
        }
        let unused_byte_count = Self::MAX_DATA_SIZE - self.message_size as usize;
        Ok(&self.as_bytes()[..size_of::<Self>() - unused_byte_count])
    }

    pub fn as_bytes_partial_mut(&mut self) -> CaliptraResult<&mut [u8]> {
        if self.message_size as usize > Self::MAX_DATA_SIZE {
            return Err(CaliptraError::RUNTIME_MAILBOX_API_REQUEST_DATA_LEN_TOO_LARGE);
        }
        let unused_byte_count = Self::MAX_DATA_SIZE - self.message_size as usize;
        Ok(&mut self.as_mut_bytes()[..size_of::<Self>() - unused_byte_count])
    }
}

#[cfg(feature = "mldsa_attestation")]
impl Request for SignWithExportedMldsaReq {
    const ID: CommandId = CommandId::SIGN_WITH_EXPORTED_MLDSA;
    type Resp = SignWithExportedMldsaResp;
}

#[cfg(feature = "mldsa_attestation")]
#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct SignWithExportedMldsaResp {
    pub hdr: MailboxRespHeader,
    pub derived_pubkey: [u8; Self::PUBKEY_SIZE],
    pub signature: [u8; Self::SIG_SIZE],
    // Pads the struct to a 4-byte multiple so `IntoBytes`/`FromBytes` can be
    // derived (SIG_SIZE is odd). Always zero.
    pub reserved: [u8; 1],
}

#[cfg(feature = "mldsa_attestation")]
impl SignWithExportedMldsaResp {
    pub const PUBKEY_SIZE: usize = MLDSA87_PUBLIC_KEY_BYTES;
    pub const SIG_SIZE: usize = MLDSA87_SIGNATURE_BYTES;
}

#[cfg(feature = "mldsa_attestation")]
impl ResponseVarSize for SignWithExportedMldsaResp {}

#[cfg(feature = "mldsa_attestation")]
impl Default for SignWithExportedMldsaResp {
    fn default() -> Self {
        Self {
            hdr: MailboxRespHeader::default(),
            derived_pubkey: [0u8; Self::PUBKEY_SIZE],
            signature: [0u8; Self::SIG_SIZE],
            reserved: [0u8; 1],
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

// REALLOCATE_DPE_CONTEXT_LIMITS
#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, Immutable, KnownLayout, PartialEq, Eq)]
pub struct ReallocateDpeContextLimitsReq {
    pub hdr: MailboxReqHeader,
    pub pl0_context_limit: u32,
}
impl Request for ReallocateDpeContextLimitsReq {
    const ID: CommandId = CommandId::REALLOCATE_DPE_CONTEXT_LIMITS;
    type Resp = ReallocateDpeContextLimitsResp;
}

#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, Immutable, KnownLayout, PartialEq, Eq)]
pub struct ReallocateDpeContextLimitsResp {
    pub hdr: MailboxRespHeader,
    pub new_pl0_context_limit: u32,
    pub new_pl1_context_limit: u32,
}
impl Response for ReallocateDpeContextLimitsResp {}

// GET_PCR_LOG
#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, Immutable, KnownLayout, PartialEq, Eq)]
pub struct GetPcrLogResp {
    pub hdr: MailboxRespHeader,
    pub data_size: u32,
    pub data: [u8; GetPcrLogResp::DATA_MAX_SIZE], // variable length
}
impl GetPcrLogResp {
    pub const DATA_MAX_SIZE: usize = 952; // max 17 pcr log entries

    pub fn data(&self) -> Option<&[u8]> {
        self.data.get(..self.data_size as usize)
    }
}
impl ResponseVarSize for GetPcrLogResp {}

impl Default for GetPcrLogResp {
    fn default() -> Self {
        Self {
            hdr: MailboxRespHeader::default(),
            data_size: 0,
            data: [0u8; Self::DATA_MAX_SIZE],
        }
    }
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
    let dlen_bytes = mbox.dlen().read() as usize;

    let buf = buf
        .get_mut(..dlen_bytes)
        .ok_or(CaliptraApiError::UnableToReadMailbox)?;

    let mut remaining = &mut buf[..];
    while remaining.len() >= 4 {
        let (chunk, rest) = remaining.split_at_mut(4);
        let word = mbox.dataout().read().to_le_bytes();
        chunk[0] = word[0];
        chunk[1] = word[1];
        chunk[2] = word[2];
        chunk[3] = word[3];
        remaining = rest;
    }
    if !remaining.is_empty() {
        let last_word = mbox.dataout().read().to_le_bytes();
        remaining.copy_from_slice(&last_word[..remaining.len()]);
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

    #[test]
    fn test_opcode_round_trips_index() {
        // Each active slot round-trips: its opcode equals its position in
        // OPCODE_CMDS, and to_opcode() recovers that position. NO_CMD slots
        // (feature-gated commands compiled out) are reserved and skipped.
        for (i, &id) in OPCODE_CMDS.iter().enumerate() {
            if id == NO_CMD {
                continue;
            }
            assert_eq!(
                CommandId(id).to_opcode(),
                Some(i as u8),
                "command id {id:#010x} at index {i} did not round-trip"
            );
        }
    }

    #[test]
    fn test_opcode_ids_unique() {
        // No two active commands share a wire id.
        for (i, op_a) in OPCODE_CMDS.iter().enumerate() {
            if OPCODE_CMDS[i] == NO_CMD {
                continue;
            }
            for op_b in OPCODE_CMDS.iter().skip(i + 1) {
                assert_ne!(op_a, op_b);
            }
        }
    }

    #[test]
    fn test_opcode_named_constants_align() {
        // The op::* constants index OPCODE_CMDS to the matching command id
        // (spot-check first, a FIPS command, and last), and to_opcode() agrees.
        assert_eq!(
            OPCODE_CMDS[op::GET_IDEV_CERT as usize],
            CommandId::GET_IDEV_CERT.0
        );
        assert_eq!(OPCODE_CMDS[op::VERSION as usize], CommandId::VERSION.0);
        assert_eq!(
            OPCODE_CMDS[op::REALLOCATE_DPE_CONTEXT_LIMITS as usize],
            CommandId::REALLOCATE_DPE_CONTEXT_LIMITS.0
        );
        assert_eq!(
            CommandId::GET_IDEV_CERT.to_opcode(),
            Some(op::GET_IDEV_CERT)
        );
    }

    #[test]
    fn test_unknown_and_firmware_load_have_no_opcode() {
        // Unknown ids and FIRMWARE_LOAD (handled before opcode dispatch) are not
        // in the table.
        assert_eq!(CommandId(0xDEAD_BEEF).to_opcode(), None);
        assert_eq!(CommandId::FIRMWARE_LOAD.to_opcode(), None);
        // The NO_CMD sentinel value must never resolve to an opcode, even in
        // feature-reduced builds where it fills reserved slots in OPCODE_CMDS.
        assert_eq!(CommandId(NO_CMD).to_opcode(), None);
    }
}
