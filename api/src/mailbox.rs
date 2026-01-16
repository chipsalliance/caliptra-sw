// Licensed under the Apache-2.0 license

use crate::CaliptraApiError;
use bitflags::bitflags;
use caliptra_error::{CaliptraError, CaliptraResult};
use caliptra_image_types::{
    ECC384_SCALAR_BYTE_SIZE, MLDSA87_PUB_KEY_BYTE_SIZE, MLDSA87_SIGNATURE_BYTE_SIZE,
    SHA512_DIGEST_BYTE_SIZE,
};
use caliptra_registers::mbox;
use core::mem::size_of;
use ureg::MmioMut;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Ref};

/// Maximum input data size for cryptographic mailbox commands.
pub const MAX_CMB_DATA_SIZE: usize = 4096;
/// Maximum output size for AES GCM encrypt or decrypt operations.
pub const MAX_CMB_AES_GCM_OUTPUT_SIZE: usize = MAX_CMB_DATA_SIZE + 16;
/// Maximum mailbox size when subsystem staging area is available.
pub const SUBSYSTEM_MAILBOX_SIZE_LIMIT: usize = 16 * 1024; // 16K
/// Context size for CMB SHA commands.
pub const CMB_SHA_CONTEXT_SIZE: usize = 200;
/// Maximum response data size
pub const MAX_RESP_DATA_SIZE: usize = 9216; // 9K
/// Unencrypted context size for the CMB AES generic commands.
pub const _CMB_AES_CONTEXT_SIZE: usize = 128;
/// Encrypted context size for the CMB AES generic commands.
pub const CMB_AES_ENCRYPTED_CONTEXT_SIZE: usize = 156; // = unencrypted size + 12 bytes IV + 16 bytes tag
const _: () = assert!(_CMB_AES_CONTEXT_SIZE + 12 + 16 == CMB_AES_ENCRYPTED_CONTEXT_SIZE);
/// Encrypted context size for the CMB AES GCM commands.
pub const CMB_AES_GCM_ENCRYPTED_CONTEXT_SIZE: usize = 128;
// ECDH context (unencrypted) size
pub const CMB_ECDH_CONTEXT_SIZE: usize = 48;
/// Context size for CMB ECDH commands.
pub const CMB_ECDH_ENCRYPTED_CONTEXT_SIZE: usize = 76; // = unencrypted size + 12 bytes IV + 16 bytes tag
const _: () = assert!(CMB_ECDH_CONTEXT_SIZE + 12 + 16 == CMB_ECDH_ENCRYPTED_CONTEXT_SIZE);
/// CMB ECDH exchange data maximum size is the size of two coordinates + 1 byte, rounded up.
pub const CMB_ECDH_EXCHANGE_DATA_MAX_SIZE: usize = 96; // = 48 * 2;
const _: () = assert!(CMB_ECDH_CONTEXT_SIZE * 2 == CMB_ECDH_EXCHANGE_DATA_MAX_SIZE);
pub const CMB_HMAC_MAX_SIZE: usize = 64; // SHA512 digest size

/// The max number of HPKE handles that OCP LOCK can manage.
pub const OCP_LOCK_MAX_HPKE_HANDLES: usize = 3;
// The largest pub key is the hybrid pub key
pub const OCP_LOCK_MAX_HPKE_PUBKEY_LEN: usize = 1665;
// TODO(clundin): Double check this number
// https://github.com/chipsalliance/caliptra-sw/issues/3115
pub const OCP_LOCK_MAX_ENDORSEMENT_CERT_SIZE: usize = 8192;

/// The metadata length of an OCP LOCK WRAPPED KEY
pub const OCP_LOCK_WRAPPED_KEY_MAX_METADATA_LEN: usize = 32;

#[derive(PartialEq, Eq)]
pub struct CommandId(pub u32);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlgorithmType {
    Ecc384,
    Mldsa87,
}

impl CommandId {
    pub const ACTIVATE_FIRMWARE: Self = Self(0x41435446); // "ACTF"
    pub const FIRMWARE_LOAD: Self = Self(0x46574C44); // "FWLD"
    pub const FIRMWARE_VERIFY: Self = Self(0x46575652); // "FWVR"
    pub const GET_IDEV_ECC384_CERT: Self = Self(0x49444543); // "IDEC"
    pub const GET_IDEV_ECC384_INFO: Self = Self(0x49444549); // "IDEI"
    pub const POPULATE_IDEV_ECC384_CERT: Self = Self(0x49444550); // "IDEP"
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
    pub const ECDSA384_SIGNATURE_VERIFY: Self = Self(0x45435632); // "ECV2"
    pub const LMS_SIGNATURE_VERIFY: Self = Self(0x4C4D5632); // "LMV2"
    pub const MLDSA87_SIGNATURE_VERIFY: Self = Self(0x4d4c5632); // "MLV2"
    pub const STASH_MEASUREMENT: Self = Self(0x4D454153); // "MEAS"
    pub const INVOKE_DPE: Self = Self(0x44504543); // "DPEC"
    pub const DISABLE_ATTESTATION: Self = Self(0x4453424C); // "DSBL"
    pub const FW_INFO: Self = Self(0x494E464F); // "INFO"
    pub const DPE_TAG_TCI: Self = Self(0x54514754); // "TAGT"
    pub const DPE_GET_TAGGED_TCI: Self = Self(0x47544744); // "GTGD"
    pub const INCREMENT_PCR_RESET_COUNTER: Self = Self(0x50435252); // "PCRR"
    pub const QUOTE_PCRS_ECC384: Self = Self(0x50435251); // "PCRQ"
    pub const QUOTE_PCRS_MLDSA87: Self = Self(0x5043524D); // "PCRM"
    pub const EXTEND_PCR: Self = Self(0x50435245); // "PCRE"
    pub const ADD_SUBJECT_ALT_NAME: Self = Self(0x414C544E); // "ALTN"
    pub const CERTIFY_KEY_EXTENDED: Self = Self(0x434B4558); // "CKEX"
    pub const ZEROIZE_UDS_FE: Self = Self(0x5A455546); // "ZEUF"

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

    // Verify the authorization manifest command.
    pub const VERIFY_AUTH_MANIFEST: Self = Self(0x4154_564D); // "ATVM"

    // The authorize and stash command.
    pub const AUTHORIZE_AND_STASH: Self = Self(0x4154_5348); // "ATSH"

    // The download firmware from recovery interface command.
    pub const RI_DOWNLOAD_FIRMWARE: Self = Self(0x5249_4644); // "RIFD"

    // The download encrypted firmware from recovery interface command.
    pub const RI_DOWNLOAD_ENCRYPTED_FIRMWARE: Self = Self(0x5249_4645); // "RIFE"

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

    // The revoke exported CDI handle command.
    pub const REVOKE_EXPORTED_CDI_HANDLE: Self = Self(0x5256_4348); // "RVCH"

    // The sign with exported mldsa command.
    pub const SIGN_WITH_EXPORTED_MLDSA: Self = Self(0x5357_4D4C); // "SWML"

    // The FE programming command.
    pub const FE_PROG: Self = Self(0x4645_5052); // "FEPR"

    // Get PCR log command.
    pub const GET_PCR_LOG: Self = Self(0x504C_4F47); // "PLOG"

    // External mailbox command
    pub const EXTERNAL_MAILBOX_CMD: Self = Self(0x4558_544D); // "EXTM"

    // Debug unlock commands
    pub const MANUF_DEBUG_UNLOCK_REQ_TOKEN: Self = Self(0x4d445554); // "MDUT"
    pub const PRODUCTION_AUTH_DEBUG_UNLOCK_REQ: Self = Self(0x50445552); // "PDUR"
    pub const PRODUCTION_AUTH_DEBUG_UNLOCK_TOKEN: Self = Self(0x50445554); // "PDUT"

    // Image metadata commands
    pub const GET_IMAGE_INFO: Self = Self(0x494D_4530); // "IME0"

    // Device Ownership Transfer command
    pub const INSTALL_OWNER_PK_HASH: Self = Self(0x4F574E50); // "OWNP"

    // Cryptographic mailbox commands
    pub const CM_IMPORT: Self = Self(0x434D_494D); // "CMIM"
    pub const CM_DELETE: Self = Self(0x434D_444C); // "CMDL"
    pub const CM_CLEAR: Self = Self(0x434D_434C); // "CMCL"
    pub const CM_STATUS: Self = Self(0x434D_5354); // "CMST"
    pub const CM_SHA_INIT: Self = Self(0x434D_5349); // "CMSI"
    pub const CM_SHA_UPDATE: Self = Self(0x434D_5355); // "CMSU"
    pub const CM_SHA_FINAL: Self = Self(0x434D_5346); // "CMSF"
    pub const CM_RANDOM_GENERATE: Self = Self(0x434D_5247); // "CMRG"
    pub const CM_RANDOM_STIR: Self = Self(0x434D_5253); // "CMRS"
    pub const CM_AES_ENCRYPT_INIT: Self = Self(0x434D_4149); // "CMAI"
    pub const CM_AES_ENCRYPT_UPDATE: Self = Self(0x434D_4155); // "CMAU"
    pub const CM_AES_DECRYPT_INIT: Self = Self(0x434D_414A); // "CMAJ"
    pub const CM_AES_DECRYPT_UPDATE: Self = Self(0x434D_4156); // "CMAV"
    pub const CM_AES_GCM_ENCRYPT_INIT: Self = Self(0x434D_4749); // "CMGI"
    pub const CM_AES_GCM_SPDM_ENCRYPT_INIT: Self = Self(0x434D_5345); // "CMSE"
    pub const CM_AES_GCM_ENCRYPT_UPDATE: Self = Self(0x434D_4755); // "CMGU"
    pub const CM_AES_GCM_ENCRYPT_FINAL: Self = Self(0x434D_4746); // "CMGF"
    pub const CM_AES_GCM_DECRYPT_INIT: Self = Self(0x434D_4449); // "CMDI"
    pub const CM_AES_GCM_SPDM_DECRYPT_INIT: Self = Self(0x434D_5344); // "CMSD"
    pub const CM_AES_GCM_DECRYPT_UPDATE: Self = Self(0x434D_4455); // "CMDU"
    pub const CM_AES_GCM_DECRYPT_FINAL: Self = Self(0x434D_4446); // "CMDF"
    pub const CM_ECDH_GENERATE: Self = Self(0x434D_4547); // "CMEG"
    pub const CM_ECDH_FINISH: Self = Self(0x434D_4546); // "CMEF"
    pub const CM_HMAC: Self = Self(0x434D_484D); // "CMHM"
    pub const CM_HMAC_KDF_COUNTER: Self = Self(0x434D_4B43); // "CMKC"
    pub const CM_HKDF_EXTRACT: Self = Self(0x434D_4B54); // "CMKT"
    pub const CM_HKDF_EXPAND: Self = Self(0x434D_4B50); // "CMKP"
    pub const CM_MLDSA_PUBLIC_KEY: Self = Self(0x434D_4D50); // "CMMP"
    pub const CM_MLDSA_SIGN: Self = Self(0x434D_4D53); // "CMMS"
    pub const CM_MLDSA_VERIFY: Self = Self(0x434D_4D56); // "CMMV"
    pub const CM_ECDSA_PUBLIC_KEY: Self = Self(0x434D_4550); // "CMEP"
    pub const CM_ECDSA_SIGN: Self = Self(0x434D_4553); // "CMES"
    pub const CM_ECDSA_VERIFY: Self = Self(0x434D_4556); // "CMEV"
    pub const CM_DERIVE_STABLE_KEY: Self = Self(0x494D_4453); // "CMDS"
    pub const CM_AES_GCM_DECRYPT_DMA: Self = Self(0x434D_4444); // "CMDD"

    // OCP LOCK Commands
    pub const OCP_LOCK_REPORT_HEK_METADATA: Self = Self(0x5248_4D54); // "RHMT"
    pub const OCP_LOCK_GET_ALGORITHMS: Self = Self(0x4741_4C47); // "GALG"
    pub const OCP_LOCK_INITIALIZE_MEK_SECRET: Self = Self(0x494D_4B53); // "IMKS"
    pub const OCP_LOCK_DERIVE_MEK: Self = Self(0x444D_454B); // "DMEK"
    pub const OCP_LOCK_ENUMERATE_HPKE_HANDLES: Self = Self(0x4548_444C); // "EHDL"
    pub const OCP_LOCK_ROTATE_HPKE_KEY: Self = Self(0x5248_504B); // "RHPK"
    pub const OCP_LOCK_GENERATE_MEK: Self = Self(0x474D_454B); // "GMEK"
    pub const OCP_LOCK_ENDORSE_HPKE_PUB_KEY: Self = Self(0x4548_504B); // "EHPK"

    pub const REALLOCATE_DPE_CONTEXT_LIMITS: Self = Self(0x5243_5458); // "RCTX"
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
    GetIdevEcc384Info(GetIdevEcc384InfoResp),
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
    QuotePcrsEcc384(QuotePcrsEcc384Resp),
    QuotePcrsMldsa87(QuotePcrsMldsa87Resp),
    CertifyKeyExtended(CertifyKeyExtendedResp),
    AuthorizeAndStash(AuthorizeAndStashResp),
    GetIdevEccCsr(GetIdevCsrResp),
    GetIdevMldsaCsr(GetIdevCsrResp),
    GetFmcAliasCsr(GetFmcAliasCsrResp),
    SignWithExportedEcdsa(SignWithExportedEcdsaResp),
    RevokeExportedCdiHandle(RevokeExportedCdiHandleResp),
    GetImageInfo(GetImageInfoResp),
    CmImport(CmImportResp),
    CmStatus(CmStatusResp),
    CmShaInit(CmShaInitResp),
    CmShaFinal(CmShaFinalResp),
    CmRandomGenerate(CmRandomGenerateResp),
    CmAesEncryptInit(CmAesEncryptInitResp),
    CmAesEncryptUpdate(CmAesResp),
    CmAesDecryptInit(CmAesResp),
    CmAesDecryptUpdate(CmAesResp),
    CmAesGcmEncryptInit(CmAesGcmEncryptInitResp),
    CmAesGcmSpdmEncryptInit(CmAesGcmSpdmEncryptInitResp),
    CmAesGcmEncryptUpdate(CmAesGcmEncryptUpdateResp),
    CmAesGcmEncryptFinal(CmAesGcmEncryptFinalResp),
    CmAesGcmDecryptInit(CmAesGcmDecryptInitResp),
    CmAesGcmSpdmDecryptInit(CmAesGcmSpdmDecryptInitResp),
    CmAesGcmDecryptUpdate(CmAesGcmDecryptUpdateResp),
    CmAesGcmDecryptFinal(CmAesGcmDecryptFinalResp),
    CmEcdhGenerate(CmEcdhGenerateResp),
    CmEcdhFinish(CmEcdhFinishResp),
    CmHmac(CmHmacResp),
    CmHmacKdfCounter(CmHmacKdfCounterResp),
    CmHkdfExtract(CmHkdfExtractResp),
    CmHkdfExpand(CmHkdfExpandResp),
    CmMldsaPublicKey(CmMldsaPublicKeyResp),
    CmMldsaSign(CmMldsaSignResp),
    CmEcdsaPublicKey(CmEcdsaPublicKeyResp),
    CmEcdsaSign(CmEcdsaSignResp),
    CmDeriveStableKey(CmDeriveStableKeyResp),
    CmAesGcmDecryptDma(CmAesGcmDecryptDmaResp),
    ProductionAuthDebugUnlockChallenge(ProductionAuthDebugUnlockChallenge),
    GetPcrLog(GetPcrLogResp),
    ReallocateDpeContextLimits(ReallocateDpeContextLimitsResp),
    OcpLockReportHekMetadata(OcpLockReportHekMetadataResp),
    OcpLockGetAlgorithms(OcpLockGetAlgorithmsResp),
    OcpLockEnumerateHpkeHandles(OcpLockEnumerateHpkeHandlesResp),
    OcpLockRotateHpkeKey(OcpLockRotateHpkeKeyResp),
    OcpLockEndorseHpkePubKey(OcpLockEndorseHpkePubKeyResp),
    OcpLockInitializeMekSecret(OcpLockInitializeMekSecretResp),
    OcpLockDeriveMek(OcpLockDeriveMekResp),
}

pub const MAX_RESP_SIZE: usize = size_of::<MailboxResp>();

impl MailboxResp {
    pub fn as_bytes(&self) -> CaliptraResult<&[u8]> {
        match self {
            MailboxResp::Header(resp) => Ok(resp.as_bytes()),
            MailboxResp::GetIdevCert(resp) => resp.as_bytes_partial(),
            MailboxResp::GetIdevEcc384Info(resp) => Ok(resp.as_bytes()),
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
            MailboxResp::QuotePcrsEcc384(resp) => Ok(resp.as_bytes()),
            MailboxResp::QuotePcrsMldsa87(resp) => Ok(resp.as_bytes()),
            MailboxResp::CertifyKeyExtended(resp) => Ok(resp.as_bytes()),
            MailboxResp::AuthorizeAndStash(resp) => Ok(resp.as_bytes()),
            MailboxResp::GetIdevEccCsr(resp) => resp.as_bytes_partial(),
            MailboxResp::GetIdevMldsaCsr(resp) => Ok(resp.as_bytes()),
            MailboxResp::GetFmcAliasCsr(resp) => resp.as_bytes_partial(),
            MailboxResp::SignWithExportedEcdsa(resp) => Ok(resp.as_bytes()),
            MailboxResp::RevokeExportedCdiHandle(resp) => Ok(resp.as_bytes()),
            MailboxResp::GetImageInfo(resp) => Ok(resp.as_bytes()),
            MailboxResp::CmImport(resp) => Ok(resp.as_bytes()),
            MailboxResp::CmStatus(resp) => Ok(resp.as_bytes()),
            MailboxResp::CmShaInit(resp) => Ok(resp.as_bytes()),
            MailboxResp::CmShaFinal(resp) => resp.as_bytes_partial(),
            MailboxResp::CmRandomGenerate(resp) => resp.as_bytes_partial(),
            MailboxResp::CmAesEncryptInit(resp) => resp.as_bytes_partial(),
            MailboxResp::CmAesEncryptUpdate(resp) => resp.as_bytes_partial(),
            MailboxResp::CmAesDecryptInit(resp) => resp.as_bytes_partial(),
            MailboxResp::CmAesDecryptUpdate(resp) => resp.as_bytes_partial(),
            MailboxResp::CmAesGcmEncryptInit(resp) => Ok(resp.as_bytes()),
            MailboxResp::CmAesGcmSpdmEncryptInit(resp) => Ok(resp.as_bytes()),
            MailboxResp::CmAesGcmEncryptUpdate(resp) => resp.as_bytes_partial(),
            MailboxResp::CmAesGcmEncryptFinal(resp) => resp.as_bytes_partial(),
            MailboxResp::CmAesGcmDecryptInit(resp) => Ok(resp.as_bytes()),
            MailboxResp::CmAesGcmSpdmDecryptInit(resp) => Ok(resp.as_bytes()),
            MailboxResp::CmAesGcmDecryptUpdate(resp) => resp.as_bytes_partial(),
            MailboxResp::CmAesGcmDecryptFinal(resp) => resp.as_bytes_partial(),
            MailboxResp::CmEcdhGenerate(resp) => Ok(resp.as_bytes()),
            MailboxResp::CmEcdhFinish(resp) => Ok(resp.as_bytes()),
            MailboxResp::CmHmac(resp) => resp.as_bytes_partial(),
            MailboxResp::CmHmacKdfCounter(resp) => Ok(resp.as_bytes()),
            MailboxResp::CmHkdfExtract(resp) => Ok(resp.as_bytes()),
            MailboxResp::CmHkdfExpand(resp) => Ok(resp.as_bytes()),
            MailboxResp::CmMldsaPublicKey(resp) => Ok(resp.as_bytes()),
            MailboxResp::CmMldsaSign(resp) => Ok(resp.as_bytes()),
            MailboxResp::CmEcdsaPublicKey(resp) => Ok(resp.as_bytes()),
            MailboxResp::CmEcdsaSign(resp) => Ok(resp.as_bytes()),
            MailboxResp::CmDeriveStableKey(resp) => Ok(resp.as_bytes()),
            MailboxResp::CmAesGcmDecryptDma(resp) => Ok(resp.as_bytes()),
            MailboxResp::ProductionAuthDebugUnlockChallenge(resp) => Ok(resp.as_bytes()),
            MailboxResp::GetPcrLog(resp) => Ok(resp.as_bytes()),
            MailboxResp::ReallocateDpeContextLimits(resp) => Ok(resp.as_bytes()),
            MailboxResp::OcpLockReportHekMetadata(resp) => Ok(resp.as_bytes()),
            MailboxResp::OcpLockGetAlgorithms(resp) => Ok(resp.as_bytes()),
            MailboxResp::OcpLockEnumerateHpkeHandles(resp) => Ok(resp.as_bytes()),
            MailboxResp::OcpLockRotateHpkeKey(resp) => Ok(resp.as_bytes()),
            MailboxResp::OcpLockEndorseHpkePubKey(resp) => Ok(resp.as_bytes()),
            MailboxResp::OcpLockInitializeMekSecret(resp) => Ok(resp.as_bytes()),
            MailboxResp::OcpLockDeriveMek(resp) => Ok(resp.as_bytes()),
        }
    }

    pub fn as_mut_bytes(&mut self) -> CaliptraResult<&mut [u8]> {
        match self {
            MailboxResp::Header(resp) => Ok(resp.as_mut_bytes()),
            MailboxResp::GetIdevCert(resp) => resp.as_bytes_partial_mut(),
            MailboxResp::GetIdevEcc384Info(resp) => Ok(resp.as_mut_bytes()),
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
            MailboxResp::QuotePcrsEcc384(resp) => Ok(resp.as_mut_bytes()),
            MailboxResp::QuotePcrsMldsa87(resp) => Ok(resp.as_mut_bytes()),
            MailboxResp::CertifyKeyExtended(resp) => Ok(resp.as_mut_bytes()),
            MailboxResp::AuthorizeAndStash(resp) => Ok(resp.as_mut_bytes()),
            MailboxResp::GetIdevEccCsr(resp) => resp.as_bytes_partial_mut(),
            MailboxResp::GetIdevMldsaCsr(resp) => Ok(resp.as_mut_bytes()),
            MailboxResp::GetFmcAliasCsr(resp) => resp.as_bytes_partial_mut(),
            MailboxResp::SignWithExportedEcdsa(resp) => Ok(resp.as_mut_bytes()),
            MailboxResp::RevokeExportedCdiHandle(resp) => Ok(resp.as_mut_bytes()),
            MailboxResp::GetImageInfo(resp) => Ok(resp.as_mut_bytes()),
            MailboxResp::CmImport(resp) => Ok(resp.as_mut_bytes()),
            MailboxResp::CmStatus(resp) => Ok(resp.as_mut_bytes()),
            MailboxResp::CmShaInit(resp) => Ok(resp.as_mut_bytes()),
            MailboxResp::CmShaFinal(resp) => resp.as_bytes_partial_mut(),
            MailboxResp::CmRandomGenerate(resp) => resp.as_bytes_partial_mut(),
            MailboxResp::CmAesEncryptInit(resp) => resp.as_bytes_partial_mut(),
            MailboxResp::CmAesEncryptUpdate(resp) => resp.as_bytes_partial_mut(),
            MailboxResp::CmAesDecryptInit(resp) => resp.as_bytes_partial_mut(),
            MailboxResp::CmAesDecryptUpdate(resp) => resp.as_bytes_partial_mut(),
            MailboxResp::CmAesGcmEncryptInit(resp) => Ok(resp.as_mut_bytes()),
            MailboxResp::CmAesGcmSpdmEncryptInit(resp) => Ok(resp.as_mut_bytes()),
            MailboxResp::CmAesGcmEncryptUpdate(resp) => resp.as_bytes_partial_mut(),
            MailboxResp::CmAesGcmEncryptFinal(resp) => resp.as_bytes_partial_mut(),
            MailboxResp::CmAesGcmDecryptInit(resp) => Ok(resp.as_mut_bytes()),
            MailboxResp::CmAesGcmSpdmDecryptInit(resp) => Ok(resp.as_mut_bytes()),
            MailboxResp::CmAesGcmDecryptUpdate(resp) => resp.as_bytes_partial_mut(),
            MailboxResp::CmAesGcmDecryptFinal(resp) => resp.as_bytes_partial_mut(),
            MailboxResp::CmEcdhGenerate(resp) => Ok(resp.as_mut_bytes()),
            MailboxResp::CmEcdhFinish(resp) => Ok(resp.as_mut_bytes()),
            MailboxResp::CmHmac(resp) => resp.as_bytes_partial_mut(),
            MailboxResp::CmHmacKdfCounter(resp) => Ok(resp.as_mut_bytes()),
            MailboxResp::CmHkdfExtract(resp) => Ok(resp.as_mut_bytes()),
            MailboxResp::CmHkdfExpand(resp) => Ok(resp.as_mut_bytes()),
            MailboxResp::CmMldsaPublicKey(resp) => Ok(resp.as_mut_bytes()),
            MailboxResp::CmMldsaSign(resp) => Ok(resp.as_mut_bytes()),
            MailboxResp::CmEcdsaPublicKey(resp) => Ok(resp.as_mut_bytes()),
            MailboxResp::CmEcdsaSign(resp) => Ok(resp.as_mut_bytes()),
            MailboxResp::CmDeriveStableKey(resp) => Ok(resp.as_mut_bytes()),
            MailboxResp::CmAesGcmDecryptDma(resp) => Ok(resp.as_mut_bytes()),
            MailboxResp::ProductionAuthDebugUnlockChallenge(resp) => Ok(resp.as_mut_bytes()),
            MailboxResp::GetPcrLog(resp) => Ok(resp.as_mut_bytes()),
            MailboxResp::ReallocateDpeContextLimits(resp) => Ok(resp.as_mut_bytes()),
            MailboxResp::OcpLockReportHekMetadata(resp) => Ok(resp.as_mut_bytes()),
            MailboxResp::OcpLockGetAlgorithms(resp) => Ok(resp.as_mut_bytes()),
            MailboxResp::OcpLockEnumerateHpkeHandles(resp) => Ok(resp.as_mut_bytes()),
            MailboxResp::OcpLockRotateHpkeKey(resp) => Ok(resp.as_mut_bytes()),
            MailboxResp::OcpLockEndorseHpkePubKey(resp) => Ok(resp.as_mut_bytes()),
            MailboxResp::OcpLockInitializeMekSecret(resp) => Ok(resp.as_mut_bytes()),
            MailboxResp::OcpLockDeriveMek(resp) => Ok(resp.as_mut_bytes()),
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
pub enum RomMailboxResp {
    Header(MailboxRespHeader),
    FipsVersion(FipsVersionResp),
    Capabilities(CapabilitiesResp),
    StashMeasurement(StashMeasurementResp),
    GetIdevCsr(GetIdevCsrResp),
    CmDeriveStableKey(CmDeriveStableKeyResp),
    CmRandomGenerate(CmRandomGenerateResp),
    CmHmac(CmHmacResp),
    OcpLockReportHekMetaData(OcpLockReportHekMetadataReq),
    InstallOwnerPkHash(InstallOwnerPkHashResp),
    GetLdevCert(GetLdevCertResp),
    ZeroizeUdsFe(ZeroizeUdsFeResp),
}

pub const MAX_ROM_RESP_SIZE: usize = size_of::<RomMailboxResp>();

#[cfg_attr(test, derive(PartialEq, Debug, Eq))]
#[allow(clippy::large_enum_variant)]
pub enum MailboxReq {
    ActivateFirmware(ActivateFirmwareReq),
    EcdsaVerify(EcdsaVerifyReq),
    LmsVerify(LmsVerifyReq),
    MldsaVerify(MldsaVerifyReq),
    GetLdevEcc384Cert(GetLdevEcc384CertReq),
    GetLdevMldsa87Cert(GetLdevMldsa87CertReq),
    StashMeasurement(StashMeasurementReq),
    InvokeDpeCommand(InvokeDpeReq),
    FipsVersion(MailboxReqHeader),
    FwInfo(MailboxReqHeader),
    PopulateIdevEcc384Cert(PopulateIdevEcc384CertReq),
    PopulateIdevMldsa87Cert(PopulateIdevMldsa87CertReq),
    GetIdevEcc384Cert(GetIdevEcc384CertReq),
    GetIdevMldsa87Cert(GetIdevMldsa87CertReq),
    TagTci(TagTciReq),
    GetTaggedTci(GetTaggedTciReq),
    GetFmcAliasEcc384Cert(GetFmcAliasEcc384CertReq),
    GetRtAliasEcc384Cert(GetRtAliasEcc384CertReq),
    GetRtAliasMlDsa87Cert(GetRtAliasMlDsa87CertReq),
    IncrementPcrResetCounter(IncrementPcrResetCounterReq),
    QuotePcrsEcc384(QuotePcrsEcc384Req),
    QuotePcrsMldsa87(QuotePcrsMldsa87Req),
    ExtendPcr(ExtendPcrReq),
    AddSubjectAltName(AddSubjectAltNameReq),
    CertifyKeyExtended(CertifyKeyExtendedReq),
    SetAuthManifest(SetAuthManifestReq),
    VerifyAuthManifest(VerifyAuthManifestReq),
    AuthorizeAndStash(AuthorizeAndStashReq),
    SignWithExportedEcdsa(SignWithExportedEcdsaReq),
    RevokeExportedCdiHandle(RevokeExportedCdiHandleReq),
    GetImageInfo(GetImageInfoReq),
    CmStatus(MailboxReqHeader),
    CmImport(CmImportReq),
    CmDelete(CmDeleteReq),
    CmClear(MailboxReqHeader),
    CmShaInit(CmShaInitReq),
    CmShaUpdate(CmShaUpdateReq),
    CmShaFinal(CmShaFinalReq),
    CmRandomGenerate(CmRandomGenerateReq),
    CmRandomStir(CmRandomStirReq),
    CmAesEncryptInit(CmAesEncryptInitReq),
    CmAesEncryptUpdate(CmAesEncryptUpdateReq),
    CmAesDecryptInit(CmAesDecryptInitReq),
    CmAesDecryptUpdate(CmAesDecryptUpdateReq),
    CmAesGcmEncryptInit(CmAesGcmEncryptInitReq),
    CmAesGcmSpdmEncryptInit(CmAesGcmSpdmEncryptInitReq),
    CmAesGcmEncryptUpdate(CmAesGcmEncryptUpdateReq),
    CmAesGcmEncryptFinal(CmAesGcmEncryptFinalReq),
    CmAesGcmDecryptInit(CmAesGcmDecryptInitReq),
    CmAesGcmSpdmDecryptInit(CmAesGcmSpdmDecryptInitReq),
    CmAesGcmDecryptUpdate(CmAesGcmDecryptUpdateReq),
    CmAesGcmDecryptFinal(CmAesGcmDecryptFinalReq),
    CmEcdhGenerate(CmEcdhGenerateReq),
    CmEcdhFinish(CmEcdhFinishReq),
    CmHmac(CmHmacReq),
    CmHmacKdfCounter(CmHmacKdfCounterReq),
    CmHkdfExtract(CmHkdfExtractReq),
    CmHkdfExpand(CmHkdfExpandReq),
    CmMldsaPublicKey(CmMldsaPublicKeyReq),
    CmMldsaSign(CmMldsaSignReq),
    CmMldsaVerify(CmMldsaVerifyReq),
    CmEcdsaPublicKey(CmEcdsaPublicKeyReq),
    CmEcdsaSign(CmEcdsaSignReq),
    CmEcdsaVerify(CmEcdsaVerifyReq),
    CmDeriveStableKey(CmDeriveStableKeyReq),
    CmAesGcmDecryptDma(CmAesGcmDecryptDmaReq),
    OcpLockReportHekMetadata(OcpLockReportHekMetadataReq),
    OcpLockGetAlgorithms(OcpLockGetAlgorithmsReq),
    OcpLockEnumerateHpkeHandles(OcpLockEnumerateHpkeHandlesReq),
    OcpLockRotateHpkeKey(OcpLockRotateHpkeKeyReq),
    OcpLockEndorseHpkePubKey(OcpLockEndorseHpkePubKeyReq),
    OcpLockInitializeMekSecret(OcpLockInitializeMekSecretReq),
    OcpLockDeriveMek(OcpLockDeriveMekReq),
    OcpLockGenerateMek(OcpLockGenerateMekReq),
    ProductionAuthDebugUnlockReq(ProductionAuthDebugUnlockReq),
    ProductionAuthDebugUnlockToken(ProductionAuthDebugUnlockToken),
    GetPcrLog(MailboxReqHeader),
    ExternalMailboxCmd(ExternalMailboxCmdReq),
    FeProg(FeProgReq),
    ReallocateDpeContextLimits(ReallocateDpeContextLimitsReq),
}

pub const MAX_REQ_SIZE: usize = size_of::<MailboxReq>();

impl MailboxReq {
    pub fn as_bytes(&self) -> CaliptraResult<&[u8]> {
        match self {
            MailboxReq::ActivateFirmware(req) => Ok(req.as_bytes()),
            MailboxReq::EcdsaVerify(req) => Ok(req.as_bytes()),
            MailboxReq::LmsVerify(req) => Ok(req.as_bytes()),
            MailboxReq::MldsaVerify(req) => req.as_bytes_partial(),
            MailboxReq::StashMeasurement(req) => Ok(req.as_bytes()),
            MailboxReq::InvokeDpeCommand(req) => req.as_bytes_partial(),
            MailboxReq::FipsVersion(req) => Ok(req.as_bytes()),
            MailboxReq::FwInfo(req) => Ok(req.as_bytes()),
            MailboxReq::GetLdevEcc384Cert(req) => Ok(req.as_bytes()),
            MailboxReq::GetLdevMldsa87Cert(req) => Ok(req.as_bytes()),
            MailboxReq::PopulateIdevEcc384Cert(req) => req.as_bytes_partial(),
            MailboxReq::PopulateIdevMldsa87Cert(req) => req.as_bytes_partial(),
            MailboxReq::GetIdevEcc384Cert(req) => req.as_bytes_partial(),
            MailboxReq::GetIdevMldsa87Cert(req) => req.as_bytes_partial(),
            MailboxReq::TagTci(req) => Ok(req.as_bytes()),
            MailboxReq::GetTaggedTci(req) => Ok(req.as_bytes()),
            MailboxReq::GetFmcAliasEcc384Cert(req) => Ok(req.as_bytes()),
            MailboxReq::GetRtAliasEcc384Cert(req) => Ok(req.as_bytes()),
            MailboxReq::GetRtAliasMlDsa87Cert(req) => Ok(req.as_bytes()),
            MailboxReq::IncrementPcrResetCounter(req) => Ok(req.as_bytes()),
            MailboxReq::QuotePcrsEcc384(req) => Ok(req.as_bytes()),
            MailboxReq::QuotePcrsMldsa87(req) => Ok(req.as_bytes()),
            MailboxReq::ExtendPcr(req) => Ok(req.as_bytes()),
            MailboxReq::AddSubjectAltName(req) => req.as_bytes_partial(),
            MailboxReq::CertifyKeyExtended(req) => Ok(req.as_bytes()),
            MailboxReq::SetAuthManifest(req) => Ok(req.as_bytes()),
            MailboxReq::VerifyAuthManifest(req) => Ok(req.as_bytes()),
            MailboxReq::AuthorizeAndStash(req) => Ok(req.as_bytes()),
            MailboxReq::SignWithExportedEcdsa(req) => Ok(req.as_bytes()),
            MailboxReq::RevokeExportedCdiHandle(req) => Ok(req.as_bytes()),
            MailboxReq::GetImageInfo(req) => Ok(req.as_bytes()),
            MailboxReq::CmStatus(req) => Ok(req.as_bytes()),
            MailboxReq::CmImport(req) => req.as_bytes_partial(),
            MailboxReq::CmDelete(req) => Ok(req.as_bytes()),
            MailboxReq::CmClear(req) => Ok(req.as_bytes()),
            MailboxReq::CmShaInit(req) => req.as_bytes_partial(),
            MailboxReq::CmShaUpdate(req) => req.as_bytes_partial(),
            MailboxReq::CmShaFinal(req) => req.as_bytes_partial(),
            MailboxReq::CmRandomGenerate(req) => Ok(req.as_bytes()),
            MailboxReq::CmRandomStir(req) => req.as_bytes_partial(),
            MailboxReq::CmAesEncryptInit(req) => req.as_bytes_partial(),
            MailboxReq::CmAesEncryptUpdate(req) => req.as_bytes_partial(),
            MailboxReq::CmAesDecryptInit(req) => req.as_bytes_partial(),
            MailboxReq::CmAesDecryptUpdate(req) => req.as_bytes_partial(),
            MailboxReq::CmAesGcmEncryptInit(req) => req.as_bytes_partial(),
            MailboxReq::CmAesGcmSpdmEncryptInit(req) => req.as_bytes_partial(),
            MailboxReq::CmAesGcmEncryptUpdate(req) => req.as_bytes_partial(),
            MailboxReq::CmAesGcmEncryptFinal(req) => req.as_bytes_partial(),
            MailboxReq::CmAesGcmDecryptInit(req) => req.as_bytes_partial(),
            MailboxReq::CmAesGcmSpdmDecryptInit(req) => req.as_bytes_partial(),
            MailboxReq::CmAesGcmDecryptUpdate(req) => req.as_bytes_partial(),
            MailboxReq::CmAesGcmDecryptFinal(req) => req.as_bytes_partial(),
            MailboxReq::CmEcdhGenerate(req) => Ok(req.as_bytes()),
            MailboxReq::CmEcdhFinish(req) => Ok(req.as_bytes()),
            MailboxReq::CmHmac(req) => req.as_bytes_partial(),
            MailboxReq::CmHmacKdfCounter(req) => req.as_bytes_partial(),
            MailboxReq::CmHkdfExtract(req) => Ok(req.as_bytes()),
            MailboxReq::CmHkdfExpand(req) => req.as_bytes_partial(),
            MailboxReq::CmMldsaPublicKey(req) => Ok(req.as_bytes()),
            MailboxReq::CmMldsaSign(req) => req.as_bytes_partial(),
            MailboxReq::CmMldsaVerify(req) => req.as_bytes_partial(),
            MailboxReq::CmEcdsaPublicKey(req) => Ok(req.as_bytes()),
            MailboxReq::CmEcdsaSign(req) => req.as_bytes_partial(),
            MailboxReq::CmEcdsaVerify(req) => req.as_bytes_partial(),
            MailboxReq::CmDeriveStableKey(req) => Ok(req.as_bytes()),
            MailboxReq::CmAesGcmDecryptDma(req) => req.as_bytes_partial(),
            MailboxReq::OcpLockReportHekMetadata(req) => Ok(req.as_bytes()),
            MailboxReq::OcpLockGetAlgorithms(req) => Ok(req.as_bytes()),
            MailboxReq::OcpLockEnumerateHpkeHandles(req) => Ok(req.as_bytes()),
            MailboxReq::OcpLockRotateHpkeKey(req) => Ok(req.as_bytes()),
            MailboxReq::OcpLockEndorseHpkePubKey(req) => Ok(req.as_bytes()),
            MailboxReq::OcpLockInitializeMekSecret(req) => Ok(req.as_bytes()),
            MailboxReq::OcpLockDeriveMek(req) => Ok(req.as_bytes()),
            MailboxReq::OcpLockGenerateMek(req) => Ok(req.as_bytes()),
            MailboxReq::ProductionAuthDebugUnlockReq(req) => Ok(req.as_bytes()),
            MailboxReq::ProductionAuthDebugUnlockToken(req) => Ok(req.as_bytes()),
            MailboxReq::GetPcrLog(req) => Ok(req.as_bytes()),
            MailboxReq::ExternalMailboxCmd(req) => Ok(req.as_bytes()),
            MailboxReq::FeProg(req) => Ok(req.as_bytes()),
            MailboxReq::ReallocateDpeContextLimits(req) => Ok(req.as_bytes()),
        }
    }

    pub fn as_mut_bytes(&mut self) -> CaliptraResult<&mut [u8]> {
        match self {
            MailboxReq::ActivateFirmware(req) => Ok(req.as_mut_bytes()),
            MailboxReq::EcdsaVerify(req) => Ok(req.as_mut_bytes()),
            MailboxReq::LmsVerify(req) => Ok(req.as_mut_bytes()),
            MailboxReq::MldsaVerify(req) => req.as_bytes_partial_mut(),
            MailboxReq::GetLdevEcc384Cert(req) => Ok(req.as_mut_bytes()),
            MailboxReq::GetLdevMldsa87Cert(req) => Ok(req.as_mut_bytes()),
            MailboxReq::StashMeasurement(req) => Ok(req.as_mut_bytes()),
            MailboxReq::InvokeDpeCommand(req) => req.as_bytes_partial_mut(),
            MailboxReq::FipsVersion(req) => Ok(req.as_mut_bytes()),
            MailboxReq::FwInfo(req) => Ok(req.as_mut_bytes()),
            MailboxReq::PopulateIdevEcc384Cert(req) => req.as_bytes_partial_mut(),
            MailboxReq::PopulateIdevMldsa87Cert(req) => req.as_bytes_partial_mut(),
            MailboxReq::GetIdevEcc384Cert(req) => req.as_bytes_partial_mut(),
            MailboxReq::GetIdevMldsa87Cert(req) => req.as_bytes_partial_mut(),
            MailboxReq::TagTci(req) => Ok(req.as_mut_bytes()),
            MailboxReq::GetTaggedTci(req) => Ok(req.as_mut_bytes()),
            MailboxReq::GetFmcAliasEcc384Cert(req) => Ok(req.as_mut_bytes()),
            MailboxReq::GetRtAliasEcc384Cert(req) => Ok(req.as_mut_bytes()),
            MailboxReq::GetRtAliasMlDsa87Cert(req) => Ok(req.as_mut_bytes()),
            MailboxReq::IncrementPcrResetCounter(req) => Ok(req.as_mut_bytes()),
            MailboxReq::QuotePcrsEcc384(req) => Ok(req.as_mut_bytes()),
            MailboxReq::QuotePcrsMldsa87(req) => Ok(req.as_mut_bytes()),
            MailboxReq::ExtendPcr(req) => Ok(req.as_mut_bytes()),
            MailboxReq::AddSubjectAltName(req) => req.as_bytes_partial_mut(),
            MailboxReq::CertifyKeyExtended(req) => Ok(req.as_mut_bytes()),
            MailboxReq::SetAuthManifest(req) => Ok(req.as_mut_bytes()),
            MailboxReq::VerifyAuthManifest(req) => Ok(req.as_mut_bytes()),
            MailboxReq::AuthorizeAndStash(req) => Ok(req.as_mut_bytes()),
            MailboxReq::SignWithExportedEcdsa(req) => Ok(req.as_mut_bytes()),
            MailboxReq::RevokeExportedCdiHandle(req) => Ok(req.as_mut_bytes()),
            MailboxReq::GetImageInfo(req) => Ok(req.as_mut_bytes()),
            MailboxReq::CmStatus(req) => Ok(req.as_mut_bytes()),
            MailboxReq::CmImport(req) => Ok(req.as_mut_bytes()),
            MailboxReq::CmDelete(req) => Ok(req.as_mut_bytes()),
            MailboxReq::CmClear(req) => Ok(req.as_mut_bytes()),
            MailboxReq::CmShaInit(req) => req.as_bytes_partial_mut(),
            MailboxReq::CmShaUpdate(req) => req.as_bytes_partial_mut(),
            MailboxReq::CmShaFinal(req) => req.as_bytes_partial_mut(),
            MailboxReq::CmRandomGenerate(req) => Ok(req.as_mut_bytes()),
            MailboxReq::CmRandomStir(req) => req.as_bytes_partial_mut(),
            MailboxReq::CmAesEncryptInit(req) => req.as_bytes_partial_mut(),
            MailboxReq::CmAesEncryptUpdate(req) => req.as_bytes_partial_mut(),
            MailboxReq::CmAesDecryptInit(req) => req.as_bytes_partial_mut(),
            MailboxReq::CmAesDecryptUpdate(req) => req.as_bytes_partial_mut(),
            MailboxReq::CmAesGcmEncryptInit(req) => req.as_bytes_partial_mut(),
            MailboxReq::CmAesGcmSpdmEncryptInit(req) => req.as_bytes_partial_mut(),
            MailboxReq::CmAesGcmEncryptUpdate(req) => req.as_bytes_partial_mut(),
            MailboxReq::CmAesGcmEncryptFinal(req) => req.as_bytes_partial_mut(),
            MailboxReq::CmAesGcmSpdmDecryptInit(req) => req.as_bytes_partial_mut(),
            MailboxReq::CmAesGcmDecryptInit(req) => req.as_bytes_partial_mut(),
            MailboxReq::CmAesGcmDecryptUpdate(req) => req.as_bytes_partial_mut(),
            MailboxReq::CmAesGcmDecryptFinal(req) => req.as_bytes_partial_mut(),
            MailboxReq::CmEcdhGenerate(req) => Ok(req.as_mut_bytes()),
            MailboxReq::CmEcdhFinish(req) => Ok(req.as_mut_bytes()),
            MailboxReq::CmHmac(req) => req.as_bytes_partial_mut(),
            MailboxReq::CmHmacKdfCounter(req) => req.as_bytes_partial_mut(),
            MailboxReq::CmHkdfExtract(req) => Ok(req.as_mut_bytes()),
            MailboxReq::CmHkdfExpand(req) => req.as_bytes_partial_mut(),
            MailboxReq::CmMldsaPublicKey(req) => Ok(req.as_mut_bytes()),
            MailboxReq::CmMldsaSign(req) => req.as_bytes_partial_mut(),
            MailboxReq::CmMldsaVerify(req) => req.as_bytes_partial_mut(),
            MailboxReq::CmEcdsaPublicKey(req) => Ok(req.as_mut_bytes()),
            MailboxReq::CmEcdsaSign(req) => req.as_bytes_partial_mut(),
            MailboxReq::CmEcdsaVerify(req) => req.as_bytes_partial_mut(),
            MailboxReq::CmDeriveStableKey(req) => Ok(req.as_mut_bytes()),
            MailboxReq::CmAesGcmDecryptDma(req) => req.as_bytes_partial_mut(),
            MailboxReq::OcpLockReportHekMetadata(req) => Ok(req.as_mut_bytes()),
            MailboxReq::OcpLockGetAlgorithms(req) => Ok(req.as_mut_bytes()),
            MailboxReq::OcpLockInitializeMekSecret(req) => Ok(req.as_mut_bytes()),
            MailboxReq::OcpLockDeriveMek(req) => Ok(req.as_mut_bytes()),
            MailboxReq::OcpLockEnumerateHpkeHandles(req) => Ok(req.as_mut_bytes()),
            MailboxReq::OcpLockRotateHpkeKey(req) => Ok(req.as_mut_bytes()),
            MailboxReq::OcpLockGenerateMek(req) => Ok(req.as_mut_bytes()),
            MailboxReq::OcpLockEndorseHpkePubKey(req) => Ok(req.as_mut_bytes()),
            MailboxReq::ProductionAuthDebugUnlockReq(req) => Ok(req.as_mut_bytes()),
            MailboxReq::ProductionAuthDebugUnlockToken(req) => Ok(req.as_mut_bytes()),
            MailboxReq::GetPcrLog(req) => Ok(req.as_mut_bytes()),
            MailboxReq::ExternalMailboxCmd(req) => Ok(req.as_mut_bytes()),
            MailboxReq::FeProg(req) => Ok(req.as_mut_bytes()),
            MailboxReq::ReallocateDpeContextLimits(req) => Ok(req.as_mut_bytes()),
        }
    }

    pub fn cmd_code(&self) -> CommandId {
        match self {
            MailboxReq::ActivateFirmware(_) => CommandId::ACTIVATE_FIRMWARE,
            MailboxReq::EcdsaVerify(_) => CommandId::ECDSA384_SIGNATURE_VERIFY,
            MailboxReq::LmsVerify(_) => CommandId::LMS_SIGNATURE_VERIFY,
            MailboxReq::MldsaVerify(_) => CommandId::MLDSA87_SIGNATURE_VERIFY,
            MailboxReq::GetLdevEcc384Cert(_) => CommandId::GET_LDEV_ECC384_CERT,
            MailboxReq::GetLdevMldsa87Cert(_) => CommandId::GET_LDEV_MLDSA87_CERT,
            MailboxReq::StashMeasurement(_) => CommandId::STASH_MEASUREMENT,
            MailboxReq::InvokeDpeCommand(_) => CommandId::INVOKE_DPE,
            MailboxReq::FipsVersion(_) => CommandId::VERSION,
            MailboxReq::FwInfo(_) => CommandId::FW_INFO,
            MailboxReq::PopulateIdevEcc384Cert(_) => CommandId::POPULATE_IDEV_ECC384_CERT,
            MailboxReq::PopulateIdevMldsa87Cert(_) => CommandId::POPULATE_IDEV_MLDSA87_CERT,
            MailboxReq::GetIdevEcc384Cert(_) => CommandId::GET_IDEV_ECC384_CERT,
            MailboxReq::GetIdevMldsa87Cert(_) => CommandId::GET_IDEV_MLDSA87_CERT,
            MailboxReq::TagTci(_) => CommandId::DPE_TAG_TCI,
            MailboxReq::GetTaggedTci(_) => CommandId::DPE_GET_TAGGED_TCI,
            MailboxReq::GetFmcAliasEcc384Cert(_) => CommandId::GET_FMC_ALIAS_ECC384_CERT,
            MailboxReq::GetRtAliasEcc384Cert(_) => CommandId::GET_RT_ALIAS_ECC384_CERT,
            MailboxReq::GetRtAliasMlDsa87Cert(_) => CommandId::GET_RT_ALIAS_MLDSA87_CERT,
            MailboxReq::IncrementPcrResetCounter(_) => CommandId::INCREMENT_PCR_RESET_COUNTER,
            MailboxReq::QuotePcrsEcc384(_) => CommandId::QUOTE_PCRS_ECC384,
            MailboxReq::QuotePcrsMldsa87(_) => CommandId::QUOTE_PCRS_MLDSA87,
            MailboxReq::ExtendPcr(_) => CommandId::EXTEND_PCR,
            MailboxReq::AddSubjectAltName(_) => CommandId::ADD_SUBJECT_ALT_NAME,
            MailboxReq::CertifyKeyExtended(_) => CommandId::CERTIFY_KEY_EXTENDED,
            MailboxReq::SetAuthManifest(_) => CommandId::SET_AUTH_MANIFEST,
            MailboxReq::VerifyAuthManifest(_) => CommandId::VERIFY_AUTH_MANIFEST,
            MailboxReq::AuthorizeAndStash(_) => CommandId::AUTHORIZE_AND_STASH,
            MailboxReq::SignWithExportedEcdsa(_) => CommandId::SIGN_WITH_EXPORTED_ECDSA,
            MailboxReq::RevokeExportedCdiHandle(_) => CommandId::REVOKE_EXPORTED_CDI_HANDLE,
            MailboxReq::GetImageInfo(_) => CommandId::GET_IMAGE_INFO,
            MailboxReq::CmStatus(_) => CommandId::CM_STATUS,
            MailboxReq::CmImport(_) => CommandId::CM_IMPORT,
            MailboxReq::CmDelete(_) => CommandId::CM_DELETE,
            MailboxReq::CmClear(_) => CommandId::CM_CLEAR,
            MailboxReq::CmShaInit(_) => CommandId::CM_SHA_INIT,
            MailboxReq::CmShaUpdate(_) => CommandId::CM_SHA_UPDATE,
            MailboxReq::CmShaFinal(_) => CommandId::CM_SHA_FINAL,
            MailboxReq::CmRandomGenerate(_) => CommandId::CM_RANDOM_GENERATE,
            MailboxReq::CmRandomStir(_) => CommandId::CM_RANDOM_STIR,
            MailboxReq::CmAesEncryptInit(_) => CommandId::CM_AES_ENCRYPT_INIT,
            MailboxReq::CmAesEncryptUpdate(_) => CommandId::CM_AES_ENCRYPT_UPDATE,
            MailboxReq::CmAesDecryptInit(_) => CommandId::CM_AES_DECRYPT_INIT,
            MailboxReq::CmAesDecryptUpdate(_) => CommandId::CM_AES_DECRYPT_UPDATE,
            MailboxReq::CmAesGcmEncryptInit(_) => CommandId::CM_AES_GCM_ENCRYPT_INIT,
            MailboxReq::CmAesGcmSpdmEncryptInit(_) => CommandId::CM_AES_GCM_SPDM_ENCRYPT_INIT,
            MailboxReq::CmAesGcmEncryptUpdate(_) => CommandId::CM_AES_GCM_ENCRYPT_UPDATE,
            MailboxReq::CmAesGcmEncryptFinal(_) => CommandId::CM_AES_GCM_ENCRYPT_FINAL,
            MailboxReq::CmAesGcmDecryptInit(_) => CommandId::CM_AES_GCM_DECRYPT_INIT,
            MailboxReq::CmAesGcmSpdmDecryptInit(_) => CommandId::CM_AES_GCM_SPDM_DECRYPT_INIT,
            MailboxReq::CmAesGcmDecryptUpdate(_) => CommandId::CM_AES_GCM_DECRYPT_UPDATE,
            MailboxReq::CmAesGcmDecryptFinal(_) => CommandId::CM_AES_GCM_DECRYPT_FINAL,
            MailboxReq::CmEcdhGenerate(_) => CommandId::CM_ECDH_GENERATE,
            MailboxReq::CmEcdhFinish(_) => CommandId::CM_ECDH_FINISH,
            MailboxReq::CmHmac(_) => CommandId::CM_HMAC,
            MailboxReq::CmHmacKdfCounter(_) => CommandId::CM_HMAC_KDF_COUNTER,
            MailboxReq::CmHkdfExtract(_) => CommandId::CM_HKDF_EXTRACT,
            MailboxReq::CmHkdfExpand(_) => CommandId::CM_HKDF_EXPAND,
            MailboxReq::CmMldsaPublicKey(_) => CommandId::CM_MLDSA_PUBLIC_KEY,
            MailboxReq::CmMldsaSign(_) => CommandId::CM_MLDSA_SIGN,
            MailboxReq::CmMldsaVerify(_) => CommandId::CM_MLDSA_VERIFY,
            MailboxReq::CmEcdsaPublicKey(_) => CommandId::CM_ECDSA_PUBLIC_KEY,
            MailboxReq::CmEcdsaSign(_) => CommandId::CM_ECDSA_SIGN,
            MailboxReq::CmEcdsaVerify(_) => CommandId::CM_ECDSA_VERIFY,
            MailboxReq::CmDeriveStableKey(_) => CommandId::CM_DERIVE_STABLE_KEY,
            MailboxReq::CmAesGcmDecryptDma(_) => CommandId::CM_AES_GCM_DECRYPT_DMA,
            MailboxReq::GetPcrLog(_) => CommandId::GET_PCR_LOG,
            MailboxReq::FeProg(_) => CommandId::FE_PROG,
            MailboxReq::ProductionAuthDebugUnlockReq(_) => {
                CommandId::PRODUCTION_AUTH_DEBUG_UNLOCK_REQ
            }
            MailboxReq::ProductionAuthDebugUnlockToken(_) => {
                CommandId::PRODUCTION_AUTH_DEBUG_UNLOCK_TOKEN
            }
            MailboxReq::ExternalMailboxCmd(_) => CommandId::EXTERNAL_MAILBOX_CMD,
            MailboxReq::ReallocateDpeContextLimits(_) => CommandId::REALLOCATE_DPE_CONTEXT_LIMITS,
            MailboxReq::OcpLockReportHekMetadata(_) => CommandId::OCP_LOCK_REPORT_HEK_METADATA,
            MailboxReq::OcpLockGetAlgorithms(_) => CommandId::OCP_LOCK_GET_ALGORITHMS,
            MailboxReq::OcpLockInitializeMekSecret(_) => CommandId::OCP_LOCK_INITIALIZE_MEK_SECRET,
            MailboxReq::OcpLockDeriveMek(_) => CommandId::OCP_LOCK_DERIVE_MEK,
            MailboxReq::OcpLockEnumerateHpkeHandles(_) => {
                CommandId::OCP_LOCK_ENUMERATE_HPKE_HANDLES
            }
            MailboxReq::OcpLockRotateHpkeKey(_) => CommandId::OCP_LOCK_ROTATE_HPKE_KEY,
            MailboxReq::OcpLockGenerateMek(_) => CommandId::OCP_LOCK_GENERATE_MEK,
            MailboxReq::OcpLockEndorseHpkePubKey(_) => CommandId::OCP_LOCK_ENDORSE_HPKE_PUB_KEY,
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
#[derive(Debug, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq, Clone)]
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
#[derive(Debug, IntoBytes, FromBytes, Immutable, KnownLayout, PartialEq, Eq, Clone)]
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

// ACTIVATE_FIRMWARE
#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, Immutable, KnownLayout, PartialEq, Eq)]
pub struct ActivateFirmwareReq {
    pub hdr: MailboxReqHeader,
    pub fw_id_count: u32,
    pub fw_ids: [u32; ActivateFirmwareReq::MAX_FW_ID_COUNT],
    pub mcu_fw_image_size: u32,
}
impl Request for ActivateFirmwareReq {
    const ID: CommandId = CommandId::ACTIVATE_FIRMWARE;
    type Resp = GetImageInfoResp;
}
impl ActivateFirmwareReq {
    pub const MAX_FW_ID_COUNT: usize = 128;
    pub const RESERVED0_IMAGE_ID: u32 = 0;
    pub const RESERVED1_IMAGE_ID: u32 = 0;
    pub const MCU_IMAGE_ID: u32 = 2;
    pub const SOC_IMAGE_ID_START: u32 = 3;
}
impl Default for ActivateFirmwareReq {
    fn default() -> Self {
        Self {
            hdr: MailboxReqHeader::default(),
            fw_id_count: 0,
            mcu_fw_image_size: 0,
            fw_ids: [0; ActivateFirmwareReq::MAX_FW_ID_COUNT],
        }
    }
}

#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, Immutable, KnownLayout, PartialEq, Eq)]
pub struct ActivateFirmwareResp {
    pub hdr: MailboxRespHeader,
}
impl Response for ActivateFirmwareResp {}

// FIRMWARE_VERIFY
#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, Immutable, KnownLayout, PartialEq, Eq, Default)]
pub struct FirmwareVerifyReq {
    // Caliptra Firmware Bundle
}
impl Request for FirmwareVerifyReq {
    const ID: CommandId = CommandId::FIRMWARE_VERIFY;
    type Resp = FirmwareVerifyResp;
}

#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, Immutable, KnownLayout, PartialEq, Eq)]
pub struct FirmwareVerifyResp {
    pub hdr: MailboxRespHeader,
    pub verify_result: u32, // FirmwareVerifyResult
}
impl Response for FirmwareVerifyResp {}

#[repr(u32)]
pub enum FirmwareVerifyResult {
    Success = 0xDEAD_C0DE,
    Failure = 0x2152_3F21,
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
    pub const DATA_MAX_SIZE: usize = 2820;

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
pub struct GetIdevEcc384InfoResp {
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

// GET_RT_ALIAS_MLDSA87_CERT
#[repr(C)]
#[derive(Default, Debug, IntoBytes, FromBytes, Immutable, KnownLayout, PartialEq, Eq)]
pub struct GetRtAliasMlDsa87CertReq {
    pub header: MailboxReqHeader,
}
impl Request for GetRtAliasMlDsa87CertReq {
    const ID: CommandId = CommandId::GET_RT_ALIAS_MLDSA87_CERT;
    type Resp = GetRtAliasCertResp;
}

pub type GetRtAliasCertResp = VarSizeDataResp;

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
    const ID: CommandId = CommandId::ECDSA384_SIGNATURE_VERIFY;
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
    const ID: CommandId = CommandId::LMS_SIGNATURE_VERIFY;
    type Resp = MailboxRespHeader;
}
// No command-specific output args

// MLDSA87_SIGNATURE_VERIFY
#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, Immutable, KnownLayout, PartialEq, Eq)]
pub struct MldsaVerifyReq {
    pub hdr: MailboxReqHeader,
    pub pub_key: [u8; MLDSA87_PUB_KEY_BYTE_SIZE],
    pub signature: [u8; MLDSA87_SIGNATURE_BYTE_SIZE],
    pub message_size: u32,
    pub message: [u8; MAX_CMB_DATA_SIZE],
}

impl MldsaVerifyReq {
    pub fn as_bytes_partial(&self) -> CaliptraResult<&[u8]> {
        if self.message_size as usize > MAX_CMB_DATA_SIZE {
            return Err(CaliptraError::RUNTIME_MAILBOX_API_REQUEST_DATA_LEN_TOO_LARGE);
        }
        let unused_byte_count = MAX_CMB_DATA_SIZE - self.message_size as usize;
        Ok(&self.as_bytes()[..size_of::<Self>() - unused_byte_count])
    }

    pub fn as_bytes_partial_mut(&mut self) -> CaliptraResult<&mut [u8]> {
        if self.message_size as usize > MAX_CMB_DATA_SIZE {
            return Err(CaliptraError::RUNTIME_MAILBOX_API_REQUEST_DATA_LEN_TOO_LARGE);
        }
        let unused_byte_count = MAX_CMB_DATA_SIZE - self.message_size as usize;
        Ok(&mut self.as_mut_bytes()[..size_of::<Self>() - unused_byte_count])
    }

    // We avoid using zerocopy because it requires the entire object to reside either
    // on the stack or in mailbox SRAM with sufficient space. Instead, we prefer methods
    // that can return references to portions of the struct. This involves no copying.
    /// Extract the header from a byte slice
    pub fn hdr(bytes: &[u8]) -> Option<&MailboxReqHeader> {
        let offset = core::mem::offset_of!(Self, hdr);
        let end = offset + core::mem::size_of::<MailboxReqHeader>();
        let slice = bytes.get(offset..end)?;
        MailboxReqHeader::ref_from_bytes(slice).ok()
    }

    /// Extract the public key from a byte slice
    pub fn pub_key(bytes: &[u8]) -> Option<&[u8; MLDSA87_PUB_KEY_BYTE_SIZE]> {
        let offset = core::mem::offset_of!(Self, pub_key);
        let end = offset + MLDSA87_PUB_KEY_BYTE_SIZE;
        let slice = bytes.get(offset..end)?;
        slice.try_into().ok()
    }

    /// Extract the signature from a byte slice
    pub fn signature(bytes: &[u8]) -> Option<&[u8; MLDSA87_SIGNATURE_BYTE_SIZE]> {
        let offset = core::mem::offset_of!(Self, signature);
        let end = offset + MLDSA87_SIGNATURE_BYTE_SIZE;
        let slice = bytes.get(offset..end)?;
        slice.try_into().ok()
    }

    /// Extract the message size from a byte slice
    pub fn message_size(bytes: &[u8]) -> Option<u32> {
        let offset = core::mem::offset_of!(Self, message_size);
        let end = offset + core::mem::size_of::<u32>();
        let slice = bytes.get(offset..end)?;
        let bytes_array: &[u8; 4] = slice.try_into().ok()?;
        Some(u32::from_le_bytes(*bytes_array))
    }

    /// Extract the message from a byte slice, using the decoded message_size for proper length
    pub fn message(bytes: &[u8]) -> Option<&[u8]> {
        let msg_size = Self::message_size(bytes)? as usize;
        if msg_size > MAX_CMB_DATA_SIZE {
            return None;
        }
        let offset = core::mem::offset_of!(Self, message);
        let slice = bytes.get(offset..)?;
        slice.get(..msg_size)
    }
}

impl Default for MldsaVerifyReq {
    fn default() -> Self {
        Self {
            hdr: MailboxReqHeader::default(),
            pub_key: [0u8; MLDSA87_PUB_KEY_BYTE_SIZE],
            signature: [0u8; MLDSA87_SIGNATURE_BYTE_SIZE],
            message_size: 0,
            message: [0u8; MAX_CMB_DATA_SIZE],
        }
    }
}

impl Request for MldsaVerifyReq {
    const ID: CommandId = CommandId::MLDSA87_SIGNATURE_VERIFY;
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

// GET_FMC_ALIAS_ECC384_CERT
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

// GET_FMC_ALIAS_MLDSA87_CERT
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

pub type GetPcrLogResp = VarSizeDataResp;

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
    pub authman_sha384_digest: [u32; 12],
    pub most_recent_fw_error: u32,
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

// POPULATE_IDEV_ECC384_CERT
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

// POPULATE_IDEV_MLDSA87_CERT
// No command-specific output args
#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, Immutable, KnownLayout, PartialEq, Eq)]
pub struct PopulateIdevMldsa87CertReq {
    pub hdr: MailboxReqHeader,
    pub cert_size: u32,
    pub cert: [u8; PopulateIdevMldsa87CertReq::MAX_CERT_SIZE], // variable length
}
impl PopulateIdevMldsa87CertReq {
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
impl Default for PopulateIdevMldsa87CertReq {
    fn default() -> Self {
        Self {
            hdr: MailboxReqHeader::default(),
            cert_size: 0,
            cert: [0u8; PopulateIdevMldsa87CertReq::MAX_CERT_SIZE],
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
pub struct QuotePcrsEcc384Req {
    pub hdr: MailboxReqHeader,
    pub nonce: [u8; 32],
}

pub type PcrValue = [u8; 48];

/// QUOTE_PCRS_ECC384 output
#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, Immutable, KnownLayout, PartialEq, Eq)]
pub struct QuotePcrsEcc384Resp {
    pub hdr: MailboxRespHeader,
    /// The PCR values
    pub pcrs: [PcrValue; 32],
    pub nonce: [u8; 32],
    pub reset_ctrs: [u32; 32],
    pub digest: [u8; 48],
    pub signature_r: [u8; 48],
    pub signature_s: [u8; 48],
}

impl Response for QuotePcrsEcc384Resp {}

impl Request for QuotePcrsEcc384Req {
    const ID: CommandId = CommandId::QUOTE_PCRS_ECC384;
    type Resp = QuotePcrsEcc384Resp;
}

#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, Immutable, KnownLayout, PartialEq, Eq)]
pub struct QuotePcrsMldsa87Req {
    pub hdr: MailboxReqHeader,
    pub nonce: [u8; 32],
}

/// QUOTE_PCRS_MLDSA87 output
#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, Immutable, KnownLayout, PartialEq, Eq)]
pub struct QuotePcrsMldsa87Resp {
    pub hdr: MailboxRespHeader,
    /// The PCR values
    pub pcrs: [PcrValue; 32],
    pub nonce: [u8; 32],
    pub reset_ctrs: [u32; 32],
    pub digest: [u8; 64],
    pub signature: [u8; MLDSA87_SIGNATURE_BYTE_SIZE],
}

impl Response for QuotePcrsMldsa87Resp {}

impl Request for QuotePcrsMldsa87Req {
    const ID: CommandId = CommandId::QUOTE_PCRS_MLDSA87;
    type Resp = QuotePcrsMldsa87Resp;
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
    pub const MAX_MAN_SIZE: usize = 34 * 1024;

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

// VERIFY_AUTH_MANIFEST
#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, Immutable, KnownLayout, PartialEq, Eq)]
pub struct VerifyAuthManifestReq {
    // This should be the same as SetAuthManifestReq
    pub hdr: MailboxReqHeader,
    pub manifest_size: u32,
    pub manifest: [u8; SetAuthManifestReq::MAX_MAN_SIZE],
}
impl VerifyAuthManifestReq {
    pub fn as_bytes_partial(&self) -> CaliptraResult<&[u8]> {
        if self.manifest_size as usize > SetAuthManifestReq::MAX_MAN_SIZE {
            return Err(CaliptraError::RUNTIME_MAILBOX_API_REQUEST_DATA_LEN_TOO_LARGE);
        }
        let unused_byte_count = SetAuthManifestReq::MAX_MAN_SIZE - self.manifest_size as usize;
        Ok(&self.as_bytes()[..size_of::<Self>() - unused_byte_count])
    }

    pub fn as_bytes_partial_mut(&mut self) -> CaliptraResult<&mut [u8]> {
        if self.manifest_size as usize > SetAuthManifestReq::MAX_MAN_SIZE {
            return Err(CaliptraError::RUNTIME_MAILBOX_API_REQUEST_DATA_LEN_TOO_LARGE);
        }
        let unused_byte_count = SetAuthManifestReq::MAX_MAN_SIZE - self.manifest_size as usize;
        Ok(&mut self.as_mut_bytes()[..size_of::<Self>() - unused_byte_count])
    }
}
impl Default for VerifyAuthManifestReq {
    fn default() -> Self {
        Self {
            hdr: MailboxReqHeader::default(),
            manifest_size: 0,
            manifest: [0u8; SetAuthManifestReq::MAX_MAN_SIZE],
        }
    }
}
impl Request for VerifyAuthManifestReq {
    const ID: CommandId = CommandId::VERIFY_AUTH_MANIFEST;
    type Resp = MailboxRespHeader;
}

// GET_IDEV_ECC384_CSR
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

// GET_IDEV_MLDSA87_CSR
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

// GET_FMC_ALIAS_ECC384_CSR
#[repr(C)]
#[derive(Default, Debug, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct GetFmcAliasEccCsrReq {
    pub hdr: MailboxReqHeader,
}

impl Request for GetFmcAliasEccCsrReq {
    const ID: CommandId = CommandId::GET_FMC_ALIAS_ECC384_CSR;
    type Resp = GetFmcAliasCsrResp;
}

// GET_FMC_ALIAS_MLDSA87_CSR
#[repr(C)]
#[derive(Default, Debug, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct GetFmcAliasMldsaCsrReq {
    pub hdr: MailboxReqHeader,
}

impl Request for GetFmcAliasMldsaCsrReq {
    const ID: CommandId = CommandId::GET_FMC_ALIAS_MLDSA87_CSR;
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
    LoadAddress,
    StagingAddress,
}

impl From<u32> for ImageHashSource {
    fn from(val: u32) -> Self {
        match val {
            1_u32 => ImageHashSource::InRequest,
            2_u32 => ImageHashSource::LoadAddress,
            3_u32 => ImageHashSource::StagingAddress,
            _ => ImageHashSource::Invalid,
        }
    }
}

impl From<ImageHashSource> for u32 {
    fn from(val: ImageHashSource) -> Self {
        match val {
            ImageHashSource::InRequest => 1,
            ImageHashSource::LoadAddress => 2,
            ImageHashSource::StagingAddress => 3,
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
    pub image_size: u32, // Image size in bytes if source is LoadAddress or StagingAddress
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
            image_size: 0,
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
#[derive(Debug, FromBytes, Immutable, IntoBytes, KnownLayout, PartialEq, Eq, Clone)]
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

// EXTERNAL_MAILBOX_CMD
#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, Immutable, KnownLayout, PartialEq, Eq, Default)]
pub struct ExternalMailboxCmdReq {
    pub hdr: MailboxReqHeader,
    pub command_id: u32,
    pub command_size: u32,
    pub axi_address_start_low: u32,
    pub axi_address_start_high: u32,
}

impl Request for ExternalMailboxCmdReq {
    const ID: CommandId = CommandId::EXTERNAL_MAILBOX_CMD;
    type Resp = MailboxRespHeader;
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
    Aes = 2,
    Ecdsa = 3,
    Mldsa = 4,
}

impl From<u32> for CmKeyUsage {
    fn from(val: u32) -> Self {
        match val {
            1_u32 => CmKeyUsage::Hmac,
            2_u32 => CmKeyUsage::Aes,
            3_u32 => CmKeyUsage::Ecdsa,
            4_u32 => CmKeyUsage::Mldsa,
            _ => CmKeyUsage::Reserved,
        }
    }
}

impl From<CmKeyUsage> for u32 {
    fn from(value: CmKeyUsage) -> Self {
        match value {
            CmKeyUsage::Hmac => 1,
            CmKeyUsage::Aes => 2,
            CmKeyUsage::Ecdsa => 3,
            CmKeyUsage::Mldsa => 4,
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

// CM_DELETE
#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq, Default)]
pub struct CmDeleteReq {
    pub hdr: MailboxReqHeader,
    pub cmk: Cmk,
}

impl Request for CmDeleteReq {
    const ID: CommandId = CommandId::CM_DELETE;
    type Resp = MailboxRespHeader;
}

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

// GET_IMAGE_INFO
#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, Immutable, KnownLayout, PartialEq, Eq, Default)]
pub struct GetImageInfoReq {
    pub hdr: MailboxReqHeader,
    pub fw_id: [u8; 4],
}
impl Request for GetImageInfoReq {
    const ID: CommandId = CommandId::GET_IMAGE_INFO;
    type Resp = GetImageInfoResp;
}

#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, Immutable, KnownLayout, PartialEq, Eq)]
pub struct GetImageInfoResp {
    pub hdr: MailboxRespHeader,
    pub component_id: u32,
    pub flags: u32,
    pub image_load_address_high: u32,
    pub image_load_address_low: u32,
    pub image_staging_address_high: u32,
    pub image_staging_address_low: u32,
}
impl Response for GetImageInfoResp {}

#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CmAesMode {
    Reserved = 0,
    Cbc = 1,
    Ctr = 2,
}

impl From<u32> for CmAesMode {
    fn from(val: u32) -> Self {
        match val {
            1_u32 => CmAesMode::Cbc,
            2_u32 => CmAesMode::Ctr,
            _ => CmAesMode::Reserved,
        }
    }
}

impl From<CmAesMode> for u32 {
    fn from(value: CmAesMode) -> Self {
        match value {
            CmAesMode::Cbc => 1,
            CmAesMode::Ctr => 2,
            _ => 0,
        }
    }
}

// CM_AES_ENCRYPT_INIT
#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct CmAesEncryptInitReq {
    pub hdr: MailboxReqHeader,
    pub cmk: Cmk,
    pub mode: u32,
    pub plaintext_size: u32,
    pub plaintext: [u8; MAX_CMB_DATA_SIZE],
}

impl Default for CmAesEncryptInitReq {
    fn default() -> Self {
        Self {
            hdr: MailboxReqHeader::default(),
            cmk: Cmk::default(),
            mode: CmAesMode::Reserved as u32,
            plaintext_size: 0,
            plaintext: [0u8; MAX_CMB_DATA_SIZE],
        }
    }
}

impl CmAesEncryptInitReq {
    pub fn as_bytes_partial(&self) -> CaliptraResult<&[u8]> {
        if self.plaintext_size as usize > MAX_CMB_DATA_SIZE {
            return Err(CaliptraError::RUNTIME_MAILBOX_API_REQUEST_DATA_LEN_TOO_LARGE);
        }
        let unused_byte_count = MAX_CMB_DATA_SIZE - self.plaintext_size as usize;
        Ok(&self.as_bytes()[..size_of::<Self>() - unused_byte_count])
    }

    pub fn as_bytes_partial_mut(&mut self) -> CaliptraResult<&mut [u8]> {
        if self.plaintext_size as usize > MAX_CMB_DATA_SIZE {
            return Err(CaliptraError::RUNTIME_MAILBOX_API_REQUEST_DATA_LEN_TOO_LARGE);
        }
        let unused_byte_count = MAX_CMB_DATA_SIZE - self.plaintext_size as usize;
        Ok(&mut self.as_mut_bytes()[..size_of::<Self>() - unused_byte_count])
    }
}

impl Request for CmAesEncryptInitReq {
    const ID: CommandId = CommandId::CM_AES_ENCRYPT_INIT;
    type Resp = CmAesEncryptInitResp;
}

#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct CmAesEncryptInitResp {
    pub hdr: CmAesEncryptInitRespHeader,
    pub ciphertext: [u8; MAX_CMB_DATA_SIZE],
}

#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct CmAesEncryptInitRespHeader {
    pub hdr: MailboxRespHeader,
    pub context: [u8; CMB_AES_ENCRYPTED_CONTEXT_SIZE],
    pub iv: [u8; 16],
    pub ciphertext_size: u32,
}

impl Default for CmAesEncryptInitResp {
    fn default() -> Self {
        Self {
            hdr: CmAesEncryptInitRespHeader::default(),
            ciphertext: [0u8; MAX_CMB_DATA_SIZE],
        }
    }
}

impl Default for CmAesEncryptInitRespHeader {
    fn default() -> Self {
        Self {
            hdr: MailboxRespHeader::default(),
            context: [0u8; CMB_AES_ENCRYPTED_CONTEXT_SIZE],
            iv: [0u8; 16],
            ciphertext_size: 0,
        }
    }
}

impl ResponseVarSize for CmAesEncryptInitResp {
    fn data(&self) -> CaliptraResult<&[u8]> {
        // Will panic if sizeof<Self>() is smaller than CmAesEncryptInitRespHeader
        // or Self doesn't have compatible alignment with
        // CmAesEncryptInitRespHeader (should be impossible)
        let (hdr, data) = CmAesEncryptInitRespHeader::ref_from_prefix(self.as_bytes())
            .map_err(|_| CaliptraError::RUNTIME_MAILBOX_API_RESPONSE_DATA_LEN_TOO_LARGE)?;
        data.get(..hdr.ciphertext_size as usize)
            .ok_or(CaliptraError::RUNTIME_MAILBOX_API_RESPONSE_DATA_LEN_TOO_LARGE)
    }

    fn partial_len(&self) -> CaliptraResult<usize> {
        let (hdr, _) = CmAesEncryptInitRespHeader::ref_from_prefix(self.as_bytes())
            .map_err(|_| CaliptraError::RUNTIME_MAILBOX_API_RESPONSE_DATA_LEN_TOO_LARGE)?;
        Ok(size_of::<CmAesEncryptInitRespHeader>() + hdr.ciphertext_size as usize)
    }
}

// CM_AES_ENCRYPT_UPDATE
#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct CmAesEncryptUpdateReq {
    pub hdr: MailboxReqHeader,
    pub context: [u8; CMB_AES_ENCRYPTED_CONTEXT_SIZE],
    pub plaintext_size: u32,
    pub plaintext: [u8; MAX_CMB_DATA_SIZE],
}

impl Default for CmAesEncryptUpdateReq {
    fn default() -> Self {
        Self {
            hdr: MailboxReqHeader::default(),
            context: [0u8; CMB_AES_ENCRYPTED_CONTEXT_SIZE],
            plaintext_size: 0,
            plaintext: [0u8; MAX_CMB_DATA_SIZE],
        }
    }
}

impl CmAesEncryptUpdateReq {
    pub fn as_bytes_partial(&self) -> CaliptraResult<&[u8]> {
        if self.plaintext_size as usize > MAX_CMB_DATA_SIZE {
            return Err(CaliptraError::RUNTIME_MAILBOX_API_REQUEST_DATA_LEN_TOO_LARGE);
        }
        let unused_byte_count = MAX_CMB_DATA_SIZE - self.plaintext_size as usize;
        Ok(&self.as_bytes()[..size_of::<Self>() - unused_byte_count])
    }

    pub fn as_bytes_partial_mut(&mut self) -> CaliptraResult<&mut [u8]> {
        if self.plaintext_size as usize > MAX_CMB_DATA_SIZE {
            return Err(CaliptraError::RUNTIME_MAILBOX_API_REQUEST_DATA_LEN_TOO_LARGE);
        }
        let unused_byte_count = MAX_CMB_DATA_SIZE - self.plaintext_size as usize;
        Ok(&mut self.as_mut_bytes()[..size_of::<Self>() - unused_byte_count])
    }
}

impl Request for CmAesEncryptUpdateReq {
    const ID: CommandId = CommandId::CM_AES_ENCRYPT_UPDATE;
    type Resp = CmAesResp;
}

// CM_AES_DECRYPT_INIT
#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct CmAesDecryptInitReq {
    pub hdr: MailboxReqHeader,
    pub cmk: Cmk,
    pub mode: u32,
    pub iv: [u8; 16],
    pub ciphertext_size: u32,
    pub ciphertext: [u8; MAX_CMB_DATA_SIZE],
}

impl Default for CmAesDecryptInitReq {
    fn default() -> Self {
        Self {
            hdr: MailboxReqHeader::default(),
            cmk: Cmk::default(),
            mode: CmAesMode::Reserved as u32,
            iv: [0u8; 16],
            ciphertext_size: 0,
            ciphertext: [0u8; MAX_CMB_DATA_SIZE],
        }
    }
}

impl CmAesDecryptInitReq {
    pub fn as_bytes_partial(&self) -> CaliptraResult<&[u8]> {
        if self.ciphertext_size as usize > MAX_CMB_DATA_SIZE {
            return Err(CaliptraError::RUNTIME_MAILBOX_API_REQUEST_DATA_LEN_TOO_LARGE);
        }
        let unused_byte_count = MAX_CMB_DATA_SIZE - self.ciphertext_size as usize;
        Ok(&self.as_bytes()[..size_of::<Self>() - unused_byte_count])
    }

    pub fn as_bytes_partial_mut(&mut self) -> CaliptraResult<&mut [u8]> {
        if self.ciphertext_size as usize > MAX_CMB_DATA_SIZE {
            return Err(CaliptraError::RUNTIME_MAILBOX_API_REQUEST_DATA_LEN_TOO_LARGE);
        }
        let unused_byte_count = MAX_CMB_DATA_SIZE - self.ciphertext_size as usize;
        Ok(&mut self.as_mut_bytes()[..size_of::<Self>() - unused_byte_count])
    }
}

impl Request for CmAesDecryptInitReq {
    const ID: CommandId = CommandId::CM_AES_DECRYPT_INIT;
    type Resp = CmAesResp;
}

// CM_AES_DECRYPT_UPDATE
#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct CmAesDecryptUpdateReq {
    pub hdr: MailboxReqHeader,
    pub context: [u8; CMB_AES_ENCRYPTED_CONTEXT_SIZE],
    pub ciphertext_size: u32,
    pub ciphertext: [u8; MAX_CMB_DATA_SIZE],
}

impl Default for CmAesDecryptUpdateReq {
    fn default() -> Self {
        Self {
            hdr: MailboxReqHeader::default(),
            context: [0u8; CMB_AES_ENCRYPTED_CONTEXT_SIZE],
            ciphertext_size: 0,
            ciphertext: [0u8; MAX_CMB_DATA_SIZE],
        }
    }
}

impl CmAesDecryptUpdateReq {
    pub fn as_bytes_partial(&self) -> CaliptraResult<&[u8]> {
        if self.ciphertext_size as usize > MAX_CMB_DATA_SIZE {
            return Err(CaliptraError::RUNTIME_MAILBOX_API_REQUEST_DATA_LEN_TOO_LARGE);
        }
        let unused_byte_count = MAX_CMB_DATA_SIZE - self.ciphertext_size as usize;
        Ok(&self.as_bytes()[..size_of::<Self>() - unused_byte_count])
    }

    pub fn as_bytes_partial_mut(&mut self) -> CaliptraResult<&mut [u8]> {
        if self.ciphertext_size as usize > MAX_CMB_DATA_SIZE {
            return Err(CaliptraError::RUNTIME_MAILBOX_API_REQUEST_DATA_LEN_TOO_LARGE);
        }
        let unused_byte_count = MAX_CMB_DATA_SIZE - self.ciphertext_size as usize;
        Ok(&mut self.as_mut_bytes()[..size_of::<Self>() - unused_byte_count])
    }
}

impl Request for CmAesDecryptUpdateReq {
    const ID: CommandId = CommandId::CM_AES_DECRYPT_UPDATE;
    type Resp = CmAesResp;
}

// Generic response for AES operations that only return a context and data.
#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct CmAesResp {
    pub hdr: CmAesRespHeader,
    pub output: [u8; MAX_CMB_DATA_SIZE],
}

#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct CmAesRespHeader {
    pub hdr: MailboxRespHeader,
    pub context: [u8; CMB_AES_ENCRYPTED_CONTEXT_SIZE],
    pub output_size: u32,
}

impl Default for CmAesResp {
    fn default() -> Self {
        Self {
            hdr: CmAesRespHeader::default(),
            output: [0u8; MAX_CMB_DATA_SIZE],
        }
    }
}

impl Default for CmAesRespHeader {
    fn default() -> Self {
        Self {
            hdr: MailboxRespHeader::default(),
            context: [0u8; CMB_AES_ENCRYPTED_CONTEXT_SIZE],
            output_size: 0,
        }
    }
}

impl ResponseVarSize for CmAesResp {
    fn data(&self) -> CaliptraResult<&[u8]> {
        // Will panic if sizeof<Self>() is smaller than CmAesRespHeader
        // or Self doesn't have compatible alignment with
        // CmAesRespHeader (should be impossible)
        let (hdr, data) = CmAesRespHeader::ref_from_prefix(self.as_bytes())
            .map_err(|_| CaliptraError::RUNTIME_MAILBOX_API_RESPONSE_DATA_LEN_TOO_LARGE)?;
        data.get(..hdr.output_size as usize)
            .ok_or(CaliptraError::RUNTIME_MAILBOX_API_RESPONSE_DATA_LEN_TOO_LARGE)
    }

    fn partial_len(&self) -> CaliptraResult<usize> {
        let (hdr, _) = CmAesRespHeader::ref_from_prefix(self.as_bytes())
            .map_err(|_| CaliptraError::RUNTIME_MAILBOX_API_RESPONSE_DATA_LEN_TOO_LARGE)?;
        Ok(size_of::<CmAesRespHeader>() + hdr.output_size as usize)
    }
}

// CM_AES_GCM_ENCRYPT_INIT
#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct CmAesGcmEncryptInitReq {
    pub hdr: MailboxReqHeader,
    pub flags: u32,
    pub cmk: Cmk,
    pub aad_size: u32,
    pub aad: [u8; MAX_CMB_DATA_SIZE],
}

impl Default for CmAesGcmEncryptInitReq {
    fn default() -> Self {
        Self {
            hdr: MailboxReqHeader::default(),
            flags: 0,
            cmk: Cmk::default(),
            aad_size: 0,
            aad: [0u8; MAX_CMB_DATA_SIZE],
        }
    }
}

impl CmAesGcmEncryptInitReq {
    pub fn as_bytes_partial(&self) -> CaliptraResult<&[u8]> {
        if self.aad_size as usize > MAX_CMB_DATA_SIZE {
            return Err(CaliptraError::RUNTIME_MAILBOX_API_REQUEST_DATA_LEN_TOO_LARGE);
        }
        let unused_byte_count = MAX_CMB_DATA_SIZE - self.aad_size as usize;
        Ok(&self.as_bytes()[..size_of::<Self>() - unused_byte_count])
    }

    pub fn as_bytes_partial_mut(&mut self) -> CaliptraResult<&mut [u8]> {
        if self.aad_size as usize > MAX_CMB_DATA_SIZE {
            return Err(CaliptraError::RUNTIME_MAILBOX_API_REQUEST_DATA_LEN_TOO_LARGE);
        }
        let unused_byte_count = MAX_CMB_DATA_SIZE - self.aad_size as usize;
        Ok(&mut self.as_mut_bytes()[..size_of::<Self>() - unused_byte_count])
    }
}

impl Request for CmAesGcmEncryptInitReq {
    const ID: CommandId = CommandId::CM_AES_GCM_ENCRYPT_INIT;
    type Resp = CmAesGcmEncryptInitResp;
}

#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct CmAesGcmEncryptInitResp {
    pub hdr: MailboxRespHeader,
    pub context: [u8; CMB_AES_GCM_ENCRYPTED_CONTEXT_SIZE],
    pub iv: [u32; 3],
}

impl Default for CmAesGcmEncryptInitResp {
    fn default() -> Self {
        Self {
            hdr: MailboxRespHeader::default(),
            context: [0u8; CMB_AES_GCM_ENCRYPTED_CONTEXT_SIZE],
            iv: [0u32; 3],
        }
    }
}

impl Response for CmAesGcmEncryptInitResp {}

// CM_AES_GCM_SPDM_ENCRYPT_INIT
#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct CmAesGcmSpdmEncryptInitReq {
    pub hdr: MailboxReqHeader,
    pub spdm_flags: u32,
    pub spdm_counter: [u8; 8],
    pub cmk: Cmk,
    pub aad_size: u32,
    pub aad: [u8; MAX_CMB_DATA_SIZE],
}

impl Default for CmAesGcmSpdmEncryptInitReq {
    fn default() -> Self {
        Self {
            hdr: MailboxReqHeader::default(),
            spdm_flags: 0,
            spdm_counter: [0u8; 8],
            cmk: Cmk::default(),
            aad_size: 0,
            aad: [0u8; MAX_CMB_DATA_SIZE],
        }
    }
}

impl CmAesGcmSpdmEncryptInitReq {
    pub fn as_bytes_partial(&self) -> CaliptraResult<&[u8]> {
        if self.aad_size as usize > MAX_CMB_DATA_SIZE {
            return Err(CaliptraError::RUNTIME_MAILBOX_API_REQUEST_DATA_LEN_TOO_LARGE);
        }
        let unused_byte_count = MAX_CMB_DATA_SIZE - self.aad_size as usize;
        Ok(&self.as_bytes()[..size_of::<Self>() - unused_byte_count])
    }

    pub fn as_bytes_partial_mut(&mut self) -> CaliptraResult<&mut [u8]> {
        if self.aad_size as usize > MAX_CMB_DATA_SIZE {
            return Err(CaliptraError::RUNTIME_MAILBOX_API_REQUEST_DATA_LEN_TOO_LARGE);
        }
        let unused_byte_count = MAX_CMB_DATA_SIZE - self.aad_size as usize;
        Ok(&mut self.as_mut_bytes()[..size_of::<Self>() - unused_byte_count])
    }
}

impl Request for CmAesGcmSpdmEncryptInitReq {
    const ID: CommandId = CommandId::CM_AES_GCM_SPDM_ENCRYPT_INIT;
    type Resp = CmAesGcmSpdmEncryptInitResp;
}

#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct CmAesGcmSpdmEncryptInitResp {
    pub hdr: MailboxRespHeader,
    pub context: [u8; CMB_AES_GCM_ENCRYPTED_CONTEXT_SIZE],
}

impl Default for CmAesGcmSpdmEncryptInitResp {
    fn default() -> Self {
        Self {
            hdr: MailboxRespHeader::default(),
            context: [0u8; CMB_AES_GCM_ENCRYPTED_CONTEXT_SIZE],
        }
    }
}

impl Response for CmAesGcmSpdmEncryptInitResp {}

// CM_AES_GCM_ENCRYPT_UPDATE
#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct CmAesGcmEncryptUpdateReq {
    pub hdr: MailboxReqHeader,
    pub context: [u8; CMB_AES_GCM_ENCRYPTED_CONTEXT_SIZE],
    pub plaintext_size: u32,
    pub plaintext: [u8; MAX_CMB_DATA_SIZE],
}

impl Default for CmAesGcmEncryptUpdateReq {
    fn default() -> Self {
        Self {
            hdr: MailboxReqHeader::default(),
            context: [0u8; CMB_AES_GCM_ENCRYPTED_CONTEXT_SIZE],
            plaintext_size: 0,
            plaintext: [0u8; MAX_CMB_DATA_SIZE],
        }
    }
}

impl CmAesGcmEncryptUpdateReq {
    pub fn as_bytes_partial(&self) -> CaliptraResult<&[u8]> {
        if self.plaintext_size as usize > MAX_CMB_DATA_SIZE {
            return Err(CaliptraError::RUNTIME_MAILBOX_API_REQUEST_DATA_LEN_TOO_LARGE);
        }
        let unused_byte_count = MAX_CMB_DATA_SIZE - self.plaintext_size as usize;
        Ok(&self.as_bytes()[..size_of::<Self>() - unused_byte_count])
    }

    pub fn as_bytes_partial_mut(&mut self) -> CaliptraResult<&mut [u8]> {
        if self.plaintext_size as usize > MAX_CMB_DATA_SIZE {
            return Err(CaliptraError::RUNTIME_MAILBOX_API_REQUEST_DATA_LEN_TOO_LARGE);
        }
        let unused_byte_count = MAX_CMB_DATA_SIZE - self.plaintext_size as usize;
        Ok(&mut self.as_mut_bytes()[..size_of::<Self>() - unused_byte_count])
    }
}

impl Request for CmAesGcmEncryptUpdateReq {
    const ID: CommandId = CommandId::CM_AES_GCM_ENCRYPT_UPDATE;
    type Resp = CmAesGcmEncryptUpdateResp;
}

#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct CmAesGcmEncryptUpdateResp {
    pub hdr: CmAesGcmEncryptUpdateRespHeader,
    pub ciphertext: [u8; MAX_CMB_AES_GCM_OUTPUT_SIZE],
}

#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct CmAesGcmEncryptUpdateRespHeader {
    pub hdr: MailboxRespHeader,
    pub context: [u8; CMB_AES_GCM_ENCRYPTED_CONTEXT_SIZE],
    pub ciphertext_size: u32,
}

impl Default for CmAesGcmEncryptUpdateResp {
    fn default() -> Self {
        Self {
            hdr: CmAesGcmEncryptUpdateRespHeader::default(),
            ciphertext: [0u8; MAX_CMB_AES_GCM_OUTPUT_SIZE],
        }
    }
}

impl Default for CmAesGcmEncryptUpdateRespHeader {
    fn default() -> Self {
        Self {
            hdr: MailboxRespHeader::default(),
            context: [0u8; CMB_AES_GCM_ENCRYPTED_CONTEXT_SIZE],
            ciphertext_size: 0,
        }
    }
}

impl ResponseVarSize for CmAesGcmEncryptUpdateResp {
    fn data(&self) -> CaliptraResult<&[u8]> {
        // Will panic if sizeof<Self>() is smaller than CmAesGcmEncryptUpdateRespHeader
        // or Self doesn't have compatible alignment with
        // CmAesGcmEncryptUpdateRespHeader (should be impossible)
        let (hdr, data) = CmAesGcmEncryptUpdateRespHeader::ref_from_prefix(self.as_bytes())
            .map_err(|_| CaliptraError::RUNTIME_MAILBOX_API_RESPONSE_DATA_LEN_TOO_LARGE)?;
        data.get(..hdr.ciphertext_size as usize)
            .ok_or(CaliptraError::RUNTIME_MAILBOX_API_RESPONSE_DATA_LEN_TOO_LARGE)
    }

    fn partial_len(&self) -> CaliptraResult<usize> {
        let (hdr, _) = CmAesGcmEncryptUpdateRespHeader::ref_from_prefix(self.as_bytes())
            .map_err(|_| CaliptraError::RUNTIME_MAILBOX_API_RESPONSE_DATA_LEN_TOO_LARGE)?;
        Ok(size_of::<CmAesGcmEncryptUpdateRespHeader>() + hdr.ciphertext_size as usize)
    }
}

// CM_AES_GCM_ENCRYPT_FINAL
#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct CmAesGcmEncryptFinalReq {
    pub hdr: MailboxReqHeader,
    pub context: [u8; CMB_AES_GCM_ENCRYPTED_CONTEXT_SIZE],
    pub plaintext_size: u32,
    pub plaintext: [u8; MAX_CMB_DATA_SIZE],
}

impl Default for CmAesGcmEncryptFinalReq {
    fn default() -> Self {
        Self {
            hdr: MailboxReqHeader::default(),
            context: [0u8; CMB_AES_GCM_ENCRYPTED_CONTEXT_SIZE],
            plaintext_size: 0,
            plaintext: [0u8; MAX_CMB_DATA_SIZE],
        }
    }
}

impl CmAesGcmEncryptFinalReq {
    pub fn as_bytes_partial(&self) -> CaliptraResult<&[u8]> {
        if self.plaintext_size as usize > MAX_CMB_DATA_SIZE {
            return Err(CaliptraError::RUNTIME_MAILBOX_API_REQUEST_DATA_LEN_TOO_LARGE);
        }
        let unused_byte_count = MAX_CMB_DATA_SIZE - self.plaintext_size as usize;
        Ok(&self.as_bytes()[..size_of::<Self>() - unused_byte_count])
    }

    pub fn as_bytes_partial_mut(&mut self) -> CaliptraResult<&mut [u8]> {
        if self.plaintext_size as usize > MAX_CMB_DATA_SIZE {
            return Err(CaliptraError::RUNTIME_MAILBOX_API_REQUEST_DATA_LEN_TOO_LARGE);
        }
        let unused_byte_count = MAX_CMB_DATA_SIZE - self.plaintext_size as usize;
        Ok(&mut self.as_mut_bytes()[..size_of::<Self>() - unused_byte_count])
    }
}

impl Request for CmAesGcmEncryptFinalReq {
    const ID: CommandId = CommandId::CM_AES_GCM_ENCRYPT_FINAL;
    type Resp = CmAesGcmEncryptFinalResp;
}

#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct CmAesGcmEncryptFinalResp {
    pub hdr: CmAesGcmEncryptFinalRespHeader,
    pub ciphertext: [u8; MAX_CMB_AES_GCM_OUTPUT_SIZE],
}

#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq, Default)]
pub struct CmAesGcmEncryptFinalRespHeader {
    pub hdr: MailboxRespHeader,
    pub tag: [u32; 4],
    pub ciphertext_size: u32,
}

impl Default for CmAesGcmEncryptFinalResp {
    fn default() -> Self {
        Self {
            hdr: CmAesGcmEncryptFinalRespHeader::default(),
            ciphertext: [0u8; MAX_CMB_AES_GCM_OUTPUT_SIZE],
        }
    }
}

impl ResponseVarSize for CmAesGcmEncryptFinalResp {
    fn data(&self) -> CaliptraResult<&[u8]> {
        // Will panic if sizeof<Self>() is smaller than CmAesGcmEncryptFinalRespHeader
        // or Self doesn't have compatible alignment with
        // CmAesGcmEncryptFinalRespHeader (should be impossible)
        let (hdr, data) = CmAesGcmEncryptFinalRespHeader::ref_from_prefix(self.as_bytes())
            .map_err(|_| CaliptraError::RUNTIME_MAILBOX_API_RESPONSE_DATA_LEN_TOO_LARGE)?;
        data.get(..hdr.ciphertext_size as usize)
            .ok_or(CaliptraError::RUNTIME_MAILBOX_API_RESPONSE_DATA_LEN_TOO_LARGE)
    }

    fn partial_len(&self) -> CaliptraResult<usize> {
        let (hdr, _) = CmAesGcmEncryptFinalRespHeader::ref_from_prefix(self.as_bytes())
            .map_err(|_| CaliptraError::RUNTIME_MAILBOX_API_RESPONSE_DATA_LEN_TOO_LARGE)?;
        Ok(size_of::<CmAesGcmEncryptFinalRespHeader>() + hdr.ciphertext_size as usize)
    }
}

// CM_AES_GCM_DECRYPT_INIT
#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct CmAesGcmDecryptInitReq {
    pub hdr: MailboxReqHeader,
    pub flags: u32,
    pub cmk: Cmk,
    pub iv: [u32; 3],
    pub aad_size: u32,
    pub aad: [u8; MAX_CMB_DATA_SIZE],
}

impl Default for CmAesGcmDecryptInitReq {
    fn default() -> Self {
        Self {
            hdr: MailboxReqHeader::default(),
            flags: 0,
            cmk: Cmk::default(),
            iv: [0u32; 3],
            aad_size: 0,
            aad: [0u8; MAX_CMB_DATA_SIZE],
        }
    }
}

impl CmAesGcmDecryptInitReq {
    pub fn as_bytes_partial(&self) -> CaliptraResult<&[u8]> {
        if self.aad_size as usize > MAX_CMB_DATA_SIZE {
            return Err(CaliptraError::RUNTIME_MAILBOX_API_REQUEST_DATA_LEN_TOO_LARGE);
        }
        let unused_byte_count = MAX_CMB_DATA_SIZE - self.aad_size as usize;
        Ok(&self.as_bytes()[..size_of::<Self>() - unused_byte_count])
    }

    pub fn as_bytes_partial_mut(&mut self) -> CaliptraResult<&mut [u8]> {
        if self.aad_size as usize > MAX_CMB_DATA_SIZE {
            return Err(CaliptraError::RUNTIME_MAILBOX_API_REQUEST_DATA_LEN_TOO_LARGE);
        }
        let unused_byte_count = MAX_CMB_DATA_SIZE - self.aad_size as usize;
        Ok(&mut self.as_mut_bytes()[..size_of::<Self>() - unused_byte_count])
    }
}

impl Request for CmAesGcmDecryptInitReq {
    const ID: CommandId = CommandId::CM_AES_GCM_DECRYPT_INIT;
    type Resp = CmAesGcmDecryptInitResp;
}

#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct CmAesGcmDecryptInitResp {
    pub hdr: MailboxRespHeader,
    pub context: [u8; CMB_AES_GCM_ENCRYPTED_CONTEXT_SIZE],
    pub iv: [u32; 3],
}

impl Default for CmAesGcmDecryptInitResp {
    fn default() -> Self {
        Self {
            hdr: MailboxRespHeader::default(),
            context: [0u8; CMB_AES_GCM_ENCRYPTED_CONTEXT_SIZE],
            iv: [0u32; 3],
        }
    }
}

impl Response for CmAesGcmDecryptInitResp {}

// CM_AES_GCM_SPDM_DECRYPT_INIT
#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct CmAesGcmSpdmDecryptInitReq {
    pub hdr: MailboxReqHeader,
    pub spdm_flags: u32,
    pub spdm_counter: [u8; 8],
    pub cmk: Cmk,
    pub aad_size: u32,
    pub aad: [u8; MAX_CMB_DATA_SIZE],
}

impl Default for CmAesGcmSpdmDecryptInitReq {
    fn default() -> Self {
        Self {
            hdr: MailboxReqHeader::default(),
            spdm_flags: 0,
            spdm_counter: [0u8; 8],
            cmk: Cmk::default(),
            aad_size: 0,
            aad: [0u8; MAX_CMB_DATA_SIZE],
        }
    }
}

impl CmAesGcmSpdmDecryptInitReq {
    pub fn as_bytes_partial(&self) -> CaliptraResult<&[u8]> {
        if self.aad_size as usize > MAX_CMB_DATA_SIZE {
            return Err(CaliptraError::RUNTIME_MAILBOX_API_REQUEST_DATA_LEN_TOO_LARGE);
        }
        let unused_byte_count = MAX_CMB_DATA_SIZE - self.aad_size as usize;
        Ok(&self.as_bytes()[..size_of::<Self>() - unused_byte_count])
    }

    pub fn as_bytes_partial_mut(&mut self) -> CaliptraResult<&mut [u8]> {
        if self.aad_size as usize > MAX_CMB_DATA_SIZE {
            return Err(CaliptraError::RUNTIME_MAILBOX_API_REQUEST_DATA_LEN_TOO_LARGE);
        }
        let unused_byte_count = MAX_CMB_DATA_SIZE - self.aad_size as usize;
        Ok(&mut self.as_mut_bytes()[..size_of::<Self>() - unused_byte_count])
    }
}

impl Request for CmAesGcmSpdmDecryptInitReq {
    const ID: CommandId = CommandId::CM_AES_GCM_SPDM_DECRYPT_INIT;
    type Resp = CmAesGcmSpdmDecryptInitResp;
}

#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct CmAesGcmSpdmDecryptInitResp {
    pub hdr: MailboxRespHeader,
    pub context: [u8; CMB_AES_GCM_ENCRYPTED_CONTEXT_SIZE],
}

impl Default for CmAesGcmSpdmDecryptInitResp {
    fn default() -> Self {
        Self {
            hdr: MailboxRespHeader::default(),
            context: [0u8; CMB_AES_GCM_ENCRYPTED_CONTEXT_SIZE],
        }
    }
}

impl Response for CmAesGcmSpdmDecryptInitResp {}

// CM_AES_GCM_DECRYPT_UPDATE
#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct CmAesGcmDecryptUpdateReq {
    pub hdr: MailboxReqHeader,
    pub context: [u8; CMB_AES_GCM_ENCRYPTED_CONTEXT_SIZE],
    pub ciphertext_size: u32,
    pub ciphertext: [u8; MAX_CMB_DATA_SIZE],
}

impl Default for CmAesGcmDecryptUpdateReq {
    fn default() -> Self {
        Self {
            hdr: MailboxReqHeader::default(),
            context: [0u8; CMB_AES_GCM_ENCRYPTED_CONTEXT_SIZE],
            ciphertext_size: 0,
            ciphertext: [0u8; MAX_CMB_DATA_SIZE],
        }
    }
}

impl CmAesGcmDecryptUpdateReq {
    pub fn as_bytes_partial(&self) -> CaliptraResult<&[u8]> {
        if self.ciphertext_size as usize > MAX_CMB_DATA_SIZE {
            return Err(CaliptraError::RUNTIME_MAILBOX_API_REQUEST_DATA_LEN_TOO_LARGE);
        }
        let unused_byte_count = MAX_CMB_DATA_SIZE - self.ciphertext_size as usize;
        Ok(&self.as_bytes()[..size_of::<Self>() - unused_byte_count])
    }

    pub fn as_bytes_partial_mut(&mut self) -> CaliptraResult<&mut [u8]> {
        if self.ciphertext_size as usize > MAX_CMB_DATA_SIZE {
            return Err(CaliptraError::RUNTIME_MAILBOX_API_REQUEST_DATA_LEN_TOO_LARGE);
        }
        let unused_byte_count = MAX_CMB_DATA_SIZE - self.ciphertext_size as usize;
        Ok(&mut self.as_mut_bytes()[..size_of::<Self>() - unused_byte_count])
    }
}

impl Request for CmAesGcmDecryptUpdateReq {
    const ID: CommandId = CommandId::CM_AES_GCM_DECRYPT_UPDATE;
    type Resp = CmAesGcmDecryptUpdateResp;
}

#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct CmAesGcmDecryptUpdateResp {
    pub hdr: CmAesGcmDecryptUpdateRespHeader,
    pub plaintext: [u8; MAX_CMB_AES_GCM_OUTPUT_SIZE],
}

#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct CmAesGcmDecryptUpdateRespHeader {
    pub hdr: MailboxRespHeader,
    pub context: [u8; CMB_AES_GCM_ENCRYPTED_CONTEXT_SIZE],
    pub plaintext_size: u32,
}

impl Default for CmAesGcmDecryptUpdateResp {
    fn default() -> Self {
        Self {
            hdr: CmAesGcmDecryptUpdateRespHeader::default(),
            plaintext: [0u8; MAX_CMB_AES_GCM_OUTPUT_SIZE],
        }
    }
}

impl Default for CmAesGcmDecryptUpdateRespHeader {
    fn default() -> Self {
        Self {
            hdr: MailboxRespHeader::default(),
            context: [0u8; CMB_AES_GCM_ENCRYPTED_CONTEXT_SIZE],
            plaintext_size: 0,
        }
    }
}

impl ResponseVarSize for CmAesGcmDecryptUpdateResp {
    fn data(&self) -> CaliptraResult<&[u8]> {
        // Will panic if sizeof<Self>() is smaller than CmAesGcmDecryptUpdateRespHeader
        // or Self doesn't have compatible alignment with
        // CmAesGcmDecryptUpdateRespHeader (should be impossible)
        let (hdr, data) = CmAesGcmDecryptUpdateRespHeader::ref_from_prefix(self.as_bytes())
            .map_err(|_| CaliptraError::RUNTIME_MAILBOX_API_RESPONSE_DATA_LEN_TOO_LARGE)?;
        data.get(..hdr.plaintext_size as usize)
            .ok_or(CaliptraError::RUNTIME_MAILBOX_API_RESPONSE_DATA_LEN_TOO_LARGE)
    }

    fn partial_len(&self) -> CaliptraResult<usize> {
        let (hdr, _) = CmAesGcmDecryptUpdateRespHeader::ref_from_prefix(self.as_bytes())
            .map_err(|_| CaliptraError::RUNTIME_MAILBOX_API_RESPONSE_DATA_LEN_TOO_LARGE)?;
        Ok(size_of::<CmAesGcmDecryptUpdateRespHeader>() + hdr.plaintext_size as usize)
    }
}

// CM_AES_GCM_DECRYPT_FINAL
#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct CmAesGcmDecryptFinalReq {
    pub hdr: MailboxReqHeader,
    pub context: [u8; CMB_AES_GCM_ENCRYPTED_CONTEXT_SIZE],
    pub tag_len: u32,
    pub tag: [u32; 4],
    pub ciphertext_size: u32,
    pub ciphertext: [u8; MAX_CMB_DATA_SIZE],
}

impl Default for CmAesGcmDecryptFinalReq {
    fn default() -> Self {
        Self {
            hdr: MailboxReqHeader::default(),
            context: [0u8; CMB_AES_GCM_ENCRYPTED_CONTEXT_SIZE],
            tag_len: 0,
            tag: [0u32; 4],
            ciphertext_size: 0,
            ciphertext: [0u8; MAX_CMB_DATA_SIZE],
        }
    }
}

impl CmAesGcmDecryptFinalReq {
    pub fn as_bytes_partial(&self) -> CaliptraResult<&[u8]> {
        if self.ciphertext_size as usize > MAX_CMB_DATA_SIZE {
            return Err(CaliptraError::RUNTIME_MAILBOX_API_REQUEST_DATA_LEN_TOO_LARGE);
        }
        let unused_byte_count = MAX_CMB_DATA_SIZE - self.ciphertext_size as usize;
        Ok(&self.as_bytes()[..size_of::<Self>() - unused_byte_count])
    }

    pub fn as_bytes_partial_mut(&mut self) -> CaliptraResult<&mut [u8]> {
        if self.ciphertext_size as usize > MAX_CMB_DATA_SIZE {
            return Err(CaliptraError::RUNTIME_MAILBOX_API_REQUEST_DATA_LEN_TOO_LARGE);
        }
        let unused_byte_count = MAX_CMB_DATA_SIZE - self.ciphertext_size as usize;
        Ok(&mut self.as_mut_bytes()[..size_of::<Self>() - unused_byte_count])
    }
}

impl Request for CmAesGcmDecryptFinalReq {
    const ID: CommandId = CommandId::CM_AES_GCM_DECRYPT_FINAL;
    type Resp = CmAesGcmDecryptFinalResp;
}

#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct CmAesGcmDecryptFinalResp {
    pub hdr: CmAesGcmDecryptFinalRespHeader,
    pub plaintext: [u8; MAX_CMB_AES_GCM_OUTPUT_SIZE],
}

#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq, Default)]
pub struct CmAesGcmDecryptFinalRespHeader {
    pub hdr: MailboxRespHeader,
    pub tag_verified: u32,
    pub plaintext_size: u32,
}

impl Default for CmAesGcmDecryptFinalResp {
    fn default() -> Self {
        Self {
            hdr: CmAesGcmDecryptFinalRespHeader::default(),
            plaintext: [0u8; MAX_CMB_AES_GCM_OUTPUT_SIZE],
        }
    }
}

impl ResponseVarSize for CmAesGcmDecryptFinalResp {
    fn data(&self) -> CaliptraResult<&[u8]> {
        // Will panic if sizeof<Self>() is smaller than CmAesGcmDecryptFinalRespHeader
        // or Self doesn't have compatible alignment with
        // CmAesGcmDecryptFinalRespHeader (should be impossible)
        let (hdr, data) = CmAesGcmDecryptFinalRespHeader::ref_from_prefix(self.as_bytes())
            .map_err(|_| CaliptraError::RUNTIME_MAILBOX_API_RESPONSE_DATA_LEN_TOO_LARGE)?;
        data.get(..hdr.plaintext_size as usize)
            .ok_or(CaliptraError::RUNTIME_MAILBOX_API_RESPONSE_DATA_LEN_TOO_LARGE)
    }

    fn partial_len(&self) -> CaliptraResult<usize> {
        let (hdr, _) = CmAesGcmDecryptFinalRespHeader::ref_from_prefix(self.as_bytes())
            .map_err(|_| CaliptraError::RUNTIME_MAILBOX_API_RESPONSE_DATA_LEN_TOO_LARGE)?;
        Ok(size_of::<CmAesGcmDecryptFinalRespHeader>() + hdr.plaintext_size as usize)
    }
}

// CM_ECDH_GENERATE
#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct CmEcdhGenerateReq {
    pub hdr: MailboxReqHeader,
}

impl Request for CmEcdhGenerateReq {
    const ID: CommandId = CommandId::CM_ECDH_GENERATE;
    type Resp = CmEcdhGenerateResp;
}

#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct CmEcdhGenerateResp {
    pub hdr: MailboxRespHeader,
    pub context: [u8; CMB_ECDH_ENCRYPTED_CONTEXT_SIZE],
    pub exchange_data: [u8; CMB_ECDH_EXCHANGE_DATA_MAX_SIZE],
}

impl Default for CmEcdhGenerateResp {
    fn default() -> Self {
        Self {
            hdr: MailboxRespHeader::default(),
            context: [0u8; CMB_ECDH_ENCRYPTED_CONTEXT_SIZE],
            exchange_data: [0u8; CMB_ECDH_EXCHANGE_DATA_MAX_SIZE],
        }
    }
}

impl Response for CmEcdhGenerateResp {}
// CM_ECDH_FINISH
#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct CmEcdhFinishReq {
    pub hdr: MailboxReqHeader,
    pub context: [u8; CMB_ECDH_ENCRYPTED_CONTEXT_SIZE],
    pub key_usage: u32,
    pub incoming_exchange_data: [u8; CMB_ECDH_EXCHANGE_DATA_MAX_SIZE],
}

impl Default for CmEcdhFinishReq {
    fn default() -> Self {
        Self {
            hdr: MailboxReqHeader::default(),
            context: [0u8; CMB_ECDH_ENCRYPTED_CONTEXT_SIZE],
            key_usage: 0,
            incoming_exchange_data: [0u8; CMB_ECDH_EXCHANGE_DATA_MAX_SIZE],
        }
    }
}

impl Request for CmEcdhFinishReq {
    const ID: CommandId = CommandId::CM_ECDH_FINISH;
    type Resp = CmEcdhFinishResp;
}

#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct CmEcdhFinishResp {
    pub hdr: MailboxRespHeader,
    pub output: Cmk,
}

impl Response for CmEcdhFinishResp {}

// CM_HMAC
#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct CmHmacReq {
    pub hdr: MailboxReqHeader,
    pub cmk: Cmk,
    pub hash_algorithm: u32,
    pub data_size: u32,
    pub data: [u8; MAX_CMB_DATA_SIZE],
}

impl Default for CmHmacReq {
    fn default() -> Self {
        Self {
            hdr: MailboxReqHeader::default(),
            cmk: Cmk::default(),
            hash_algorithm: 0,
            data_size: 0,
            data: [0u8; MAX_CMB_DATA_SIZE],
        }
    }
}

impl CmHmacReq {
    pub fn as_bytes_partial(&self) -> CaliptraResult<&[u8]> {
        if self.data_size as usize > MAX_CMB_DATA_SIZE {
            return Err(CaliptraError::RUNTIME_MAILBOX_API_REQUEST_DATA_LEN_TOO_LARGE);
        }
        let unused_byte_count = MAX_CMB_DATA_SIZE - self.data_size as usize;
        Ok(&self.as_bytes()[..size_of::<Self>() - unused_byte_count])
    }

    pub fn as_bytes_partial_mut(&mut self) -> CaliptraResult<&mut [u8]> {
        if self.data_size as usize > MAX_CMB_DATA_SIZE {
            return Err(CaliptraError::RUNTIME_MAILBOX_API_REQUEST_DATA_LEN_TOO_LARGE);
        }
        let unused_byte_count = MAX_CMB_DATA_SIZE - self.data_size as usize;
        Ok(&mut self.as_mut_bytes()[..size_of::<Self>() - unused_byte_count])
    }
}

impl Request for CmHmacReq {
    const ID: CommandId = CommandId::CM_HMAC;
    type Resp = CmHmacResp;
}

#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct CmHmacResp {
    pub hdr: MailboxRespHeaderVarSize,
    pub mac: [u8; CMB_HMAC_MAX_SIZE],
}

impl Default for CmHmacResp {
    fn default() -> Self {
        Self {
            hdr: MailboxRespHeaderVarSize::default(),
            mac: [0u8; CMB_HMAC_MAX_SIZE],
        }
    }
}

impl ResponseVarSize for CmHmacResp {}

// CM_HMAC_KDF_COUNTER
#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct CmHmacKdfCounterReq {
    pub hdr: MailboxReqHeader,
    pub kin: Cmk,
    pub hash_algorithm: u32,
    pub key_usage: u32,
    pub key_size: u32,
    pub label_size: u32,
    pub label: [u8; MAX_CMB_DATA_SIZE],
}

impl Default for CmHmacKdfCounterReq {
    fn default() -> Self {
        Self {
            hdr: MailboxReqHeader::default(),
            kin: Cmk::default(),
            hash_algorithm: 0,
            key_size: 0,
            key_usage: 0,
            label_size: 0,
            label: [0u8; MAX_CMB_DATA_SIZE],
        }
    }
}

impl CmHmacKdfCounterReq {
    pub fn as_bytes_partial(&self) -> CaliptraResult<&[u8]> {
        if self.label_size as usize > MAX_CMB_DATA_SIZE {
            return Err(CaliptraError::RUNTIME_MAILBOX_API_REQUEST_DATA_LEN_TOO_LARGE);
        }
        let unused_byte_count = MAX_CMB_DATA_SIZE - self.label_size as usize;
        Ok(&self.as_bytes()[..size_of::<Self>() - unused_byte_count])
    }

    pub fn as_bytes_partial_mut(&mut self) -> CaliptraResult<&mut [u8]> {
        if self.label_size as usize > MAX_CMB_DATA_SIZE {
            return Err(CaliptraError::RUNTIME_MAILBOX_API_REQUEST_DATA_LEN_TOO_LARGE);
        }
        let unused_byte_count = MAX_CMB_DATA_SIZE - self.label_size as usize;
        Ok(&mut self.as_mut_bytes()[..size_of::<Self>() - unused_byte_count])
    }
}

impl Request for CmHmacKdfCounterReq {
    const ID: CommandId = CommandId::CM_HMAC_KDF_COUNTER;
    type Resp = CmHmacKdfCounterResp;
}

#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct CmHmacKdfCounterResp {
    pub hdr: MailboxRespHeader,
    pub kout: Cmk,
}

impl Response for CmHmacKdfCounterResp {}

// CM_HKDF_EXTRACT
#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq, Default)]
pub struct CmHkdfExtractReq {
    pub hdr: MailboxReqHeader,
    pub hash_algorithm: u32,
    pub salt: Cmk,
    pub ikm: Cmk,
}

impl Request for CmHkdfExtractReq {
    const ID: CommandId = CommandId::CM_HKDF_EXTRACT;
    type Resp = CmHkdfExtractResp;
}

#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct CmHkdfExtractResp {
    pub hdr: MailboxRespHeader,
    pub prk: Cmk,
}

impl Response for CmHkdfExtractResp {}

// CM_HKDF_EXPAND
#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct CmHkdfExpandReq {
    pub hdr: MailboxReqHeader,
    pub prk: Cmk,
    pub hash_algorithm: u32,
    pub key_usage: u32,
    pub key_size: u32,
    pub info_size: u32,
    pub info: [u8; MAX_CMB_DATA_SIZE],
}

impl Default for CmHkdfExpandReq {
    fn default() -> Self {
        Self {
            hdr: MailboxReqHeader::default(),
            prk: Cmk::default(),
            hash_algorithm: 0,
            key_size: 0,
            key_usage: 0,
            info_size: 0,
            info: [0u8; MAX_CMB_DATA_SIZE],
        }
    }
}

impl CmHkdfExpandReq {
    pub fn as_bytes_partial(&self) -> CaliptraResult<&[u8]> {
        if self.info_size as usize > MAX_CMB_DATA_SIZE {
            return Err(CaliptraError::RUNTIME_MAILBOX_API_REQUEST_DATA_LEN_TOO_LARGE);
        }
        let unused_byte_count = MAX_CMB_DATA_SIZE - self.info_size as usize;
        Ok(&self.as_bytes()[..size_of::<Self>() - unused_byte_count])
    }

    pub fn as_bytes_partial_mut(&mut self) -> CaliptraResult<&mut [u8]> {
        if self.info_size as usize > MAX_CMB_DATA_SIZE {
            return Err(CaliptraError::RUNTIME_MAILBOX_API_REQUEST_DATA_LEN_TOO_LARGE);
        }
        let unused_byte_count = MAX_CMB_DATA_SIZE - self.info_size as usize;
        Ok(&mut self.as_mut_bytes()[..size_of::<Self>() - unused_byte_count])
    }
}

impl Request for CmHkdfExpandReq {
    const ID: CommandId = CommandId::CM_HKDF_EXPAND;
    type Resp = CmHkdfExpandResp;
}

#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct CmHkdfExpandResp {
    pub hdr: MailboxRespHeader,
    pub okm: Cmk,
}

impl Response for CmHkdfExpandResp {}

// CM_MLDSA_PUBLIC_KEY
#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq, Default)]
pub struct CmMldsaPublicKeyReq {
    pub hdr: MailboxReqHeader,
    pub cmk: Cmk,
}

impl Request for CmMldsaPublicKeyReq {
    const ID: CommandId = CommandId::CM_MLDSA_PUBLIC_KEY;
    type Resp = CmMldsaPublicKeyResp;
}

#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct CmMldsaPublicKeyResp {
    pub hdr: MailboxRespHeader,
    pub public_key: [u8; MLDSA87_PUB_KEY_BYTE_SIZE],
}

impl Default for CmMldsaPublicKeyResp {
    fn default() -> Self {
        Self {
            hdr: MailboxRespHeader::default(),
            public_key: [0u8; MLDSA87_PUB_KEY_BYTE_SIZE],
        }
    }
}

impl Response for CmMldsaPublicKeyResp {}

// CM_MLDSA_SIGN
#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct CmMldsaSignReq {
    pub hdr: MailboxReqHeader,
    pub cmk: Cmk,
    pub message_size: u32,
    pub message: [u8; MAX_CMB_DATA_SIZE],
}

impl Default for CmMldsaSignReq {
    fn default() -> Self {
        Self {
            hdr: MailboxReqHeader::default(),
            cmk: Cmk::default(),
            message_size: 0,
            message: [0u8; MAX_CMB_DATA_SIZE],
        }
    }
}

impl CmMldsaSignReq {
    pub fn as_bytes_partial(&self) -> CaliptraResult<&[u8]> {
        if self.message_size as usize > MAX_CMB_DATA_SIZE {
            return Err(CaliptraError::RUNTIME_MAILBOX_API_REQUEST_DATA_LEN_TOO_LARGE);
        }
        let unused_byte_count = MAX_CMB_DATA_SIZE - self.message_size as usize;
        Ok(&self.as_bytes()[..size_of::<Self>() - unused_byte_count])
    }

    pub fn as_bytes_partial_mut(&mut self) -> CaliptraResult<&mut [u8]> {
        if self.message_size as usize > MAX_CMB_DATA_SIZE {
            return Err(CaliptraError::RUNTIME_MAILBOX_API_REQUEST_DATA_LEN_TOO_LARGE);
        }
        let unused_byte_count = MAX_CMB_DATA_SIZE - self.message_size as usize;
        Ok(&mut self.as_mut_bytes()[..size_of::<Self>() - unused_byte_count])
    }
}

impl Request for CmMldsaSignReq {
    const ID: CommandId = CommandId::CM_MLDSA_SIGN;
    type Resp = CmMldsaSignResp;
}

#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct CmMldsaSignResp {
    pub hdr: MailboxRespHeader,
    pub signature: [u8; MLDSA87_SIGNATURE_BYTE_SIZE],
}

impl Default for CmMldsaSignResp {
    fn default() -> Self {
        Self {
            hdr: MailboxRespHeader::default(),
            signature: [0u8; MLDSA87_SIGNATURE_BYTE_SIZE],
        }
    }
}

impl Response for CmMldsaSignResp {}

// CM_MLDSA_VERIFY
#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct CmMldsaVerifyReq {
    pub hdr: MailboxReqHeader,
    pub cmk: Cmk,
    pub signature: [u8; MLDSA87_SIGNATURE_BYTE_SIZE],
    pub message_size: u32,
    pub message: [u8; MAX_CMB_DATA_SIZE],
}

impl Default for CmMldsaVerifyReq {
    fn default() -> Self {
        Self {
            hdr: MailboxReqHeader::default(),
            cmk: Cmk::default(),
            signature: [0u8; MLDSA87_SIGNATURE_BYTE_SIZE],
            message_size: 0,
            message: [0u8; MAX_CMB_DATA_SIZE],
        }
    }
}

impl CmMldsaVerifyReq {
    pub fn as_bytes_partial(&self) -> CaliptraResult<&[u8]> {
        if self.message_size as usize > MAX_CMB_DATA_SIZE {
            return Err(CaliptraError::RUNTIME_MAILBOX_API_REQUEST_DATA_LEN_TOO_LARGE);
        }
        let unused_byte_count = MAX_CMB_DATA_SIZE - self.message_size as usize;
        Ok(&self.as_bytes()[..size_of::<Self>() - unused_byte_count])
    }

    pub fn as_bytes_partial_mut(&mut self) -> CaliptraResult<&mut [u8]> {
        if self.message_size as usize > MAX_CMB_DATA_SIZE {
            return Err(CaliptraError::RUNTIME_MAILBOX_API_REQUEST_DATA_LEN_TOO_LARGE);
        }
        let unused_byte_count = MAX_CMB_DATA_SIZE - self.message_size as usize;
        Ok(&mut self.as_mut_bytes()[..size_of::<Self>() - unused_byte_count])
    }
}

impl Request for CmMldsaVerifyReq {
    const ID: CommandId = CommandId::CM_MLDSA_VERIFY;
    type Resp = MailboxRespHeader;
}

// CM_ECDSA_PUBLIC_KEY
#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq, Default)]
pub struct CmEcdsaPublicKeyReq {
    pub hdr: MailboxReqHeader,
    pub cmk: Cmk,
}

impl Request for CmEcdsaPublicKeyReq {
    const ID: CommandId = CommandId::CM_ECDSA_PUBLIC_KEY;
    type Resp = CmEcdsaPublicKeyResp;
}

#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct CmEcdsaPublicKeyResp {
    pub hdr: MailboxRespHeader,
    pub public_key_x: [u8; ECC384_SCALAR_BYTE_SIZE],
    pub public_key_y: [u8; ECC384_SCALAR_BYTE_SIZE],
}

impl Default for CmEcdsaPublicKeyResp {
    fn default() -> Self {
        Self {
            hdr: MailboxRespHeader::default(),
            public_key_x: [0u8; ECC384_SCALAR_BYTE_SIZE],
            public_key_y: [0u8; ECC384_SCALAR_BYTE_SIZE],
        }
    }
}

impl Response for CmEcdsaPublicKeyResp {}

// CM_ECDSA_SIGN
#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct CmEcdsaSignReq {
    pub hdr: MailboxReqHeader,
    pub cmk: Cmk,
    pub message_size: u32,
    pub message: [u8; MAX_CMB_DATA_SIZE],
}

impl Default for CmEcdsaSignReq {
    fn default() -> Self {
        Self {
            hdr: MailboxReqHeader::default(),
            cmk: Cmk::default(),
            message_size: 0,
            message: [0u8; MAX_CMB_DATA_SIZE],
        }
    }
}

impl CmEcdsaSignReq {
    pub fn as_bytes_partial(&self) -> CaliptraResult<&[u8]> {
        if self.message_size as usize > MAX_CMB_DATA_SIZE {
            return Err(CaliptraError::RUNTIME_MAILBOX_API_REQUEST_DATA_LEN_TOO_LARGE);
        }
        let unused_byte_count = MAX_CMB_DATA_SIZE - self.message_size as usize;
        Ok(&self.as_bytes()[..size_of::<Self>() - unused_byte_count])
    }

    pub fn as_bytes_partial_mut(&mut self) -> CaliptraResult<&mut [u8]> {
        if self.message_size as usize > MAX_CMB_DATA_SIZE {
            return Err(CaliptraError::RUNTIME_MAILBOX_API_REQUEST_DATA_LEN_TOO_LARGE);
        }
        let unused_byte_count = MAX_CMB_DATA_SIZE - self.message_size as usize;
        Ok(&mut self.as_mut_bytes()[..size_of::<Self>() - unused_byte_count])
    }
}

impl Request for CmEcdsaSignReq {
    const ID: CommandId = CommandId::CM_ECDSA_SIGN;
    type Resp = CmMldsaSignResp;
}

#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct CmEcdsaSignResp {
    pub hdr: MailboxRespHeader,
    pub signature_r: [u8; ECC384_SCALAR_BYTE_SIZE],
    pub signature_s: [u8; ECC384_SCALAR_BYTE_SIZE],
}

impl Default for CmEcdsaSignResp {
    fn default() -> Self {
        Self {
            hdr: MailboxRespHeader::default(),
            signature_r: [0u8; ECC384_SCALAR_BYTE_SIZE],
            signature_s: [0u8; ECC384_SCALAR_BYTE_SIZE],
        }
    }
}

impl Response for CmEcdsaSignResp {}

// FE (Field Entropy) Programming
//
// FE partitions are limited to values 0-3 (4 total partitions).
// Valid partition numbers: 0, 1, 2, 3
#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq, Default)]
pub struct FeProgReq {
    pub hdr: MailboxReqHeader,
    pub partition: u32,
}

// CM_ECDSA_VERIFY
#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct CmEcdsaVerifyReq {
    pub hdr: MailboxReqHeader,
    pub cmk: Cmk,
    pub signature_r: [u8; ECC384_SCALAR_BYTE_SIZE],
    pub signature_s: [u8; ECC384_SCALAR_BYTE_SIZE],
    pub message_size: u32,
    pub message: [u8; MAX_CMB_DATA_SIZE],
}

impl Default for CmEcdsaVerifyReq {
    fn default() -> Self {
        Self {
            hdr: MailboxReqHeader::default(),
            cmk: Cmk::default(),
            signature_r: [0u8; ECC384_SCALAR_BYTE_SIZE],
            signature_s: [0u8; ECC384_SCALAR_BYTE_SIZE],
            message_size: 0,
            message: [0u8; MAX_CMB_DATA_SIZE],
        }
    }
}

impl CmEcdsaVerifyReq {
    pub fn as_bytes_partial(&self) -> CaliptraResult<&[u8]> {
        if self.message_size as usize > MAX_CMB_DATA_SIZE {
            return Err(CaliptraError::RUNTIME_MAILBOX_API_REQUEST_DATA_LEN_TOO_LARGE);
        }
        let unused_byte_count = MAX_CMB_DATA_SIZE - self.message_size as usize;
        Ok(&self.as_bytes()[..size_of::<Self>() - unused_byte_count])
    }

    pub fn as_bytes_partial_mut(&mut self) -> CaliptraResult<&mut [u8]> {
        if self.message_size as usize > MAX_CMB_DATA_SIZE {
            return Err(CaliptraError::RUNTIME_MAILBOX_API_REQUEST_DATA_LEN_TOO_LARGE);
        }
        let unused_byte_count = MAX_CMB_DATA_SIZE - self.message_size as usize;
        Ok(&mut self.as_mut_bytes()[..size_of::<Self>() - unused_byte_count])
    }
}

impl Request for CmEcdsaVerifyReq {
    const ID: CommandId = CommandId::CM_ECDSA_VERIFY;
    type Resp = MailboxRespHeader;
}

// CM_DERIVE_STABLE_KEY
pub const CM_STABLE_KEY_INFO_SIZE_BYTES: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CmStableKeyType {
    Reserved = 0,
    IDevId,
    LDevId,
}

impl From<u32> for CmStableKeyType {
    fn from(val: u32) -> Self {
        match val {
            1_u32 => CmStableKeyType::IDevId,
            2_u32 => CmStableKeyType::LDevId,
            _ => CmStableKeyType::Reserved,
        }
    }
}

impl From<CmStableKeyType> for u32 {
    fn from(val: CmStableKeyType) -> Self {
        match val {
            CmStableKeyType::IDevId => 1,
            CmStableKeyType::LDevId => 2,
            CmStableKeyType::Reserved => 0,
        }
    }
}

#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, Immutable, KnownLayout, PartialEq, Eq)]
pub struct CmDeriveStableKeyReq {
    pub hdr: MailboxReqHeader,
    pub key_type: u32,
    pub info: [u8; CM_STABLE_KEY_INFO_SIZE_BYTES],
}
impl Default for CmDeriveStableKeyReq {
    fn default() -> Self {
        Self {
            hdr: Default::default(),
            info: [0u8; CM_STABLE_KEY_INFO_SIZE_BYTES],
            key_type: CmStableKeyType::Reserved as u32,
        }
    }
}
impl Request for CmDeriveStableKeyReq {
    const ID: CommandId = CommandId::CM_DERIVE_STABLE_KEY;
    type Resp = CmDeriveStableKeyResp;
}

#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, Immutable, KnownLayout, PartialEq, Eq)]
pub struct CmDeriveStableKeyResp {
    pub hdr: MailboxRespHeader,
    pub cmk: Cmk,
}
impl Response for CmDeriveStableKeyResp {}

/// Maximum AAD size for CM_AES_GCM_DECRYPT_DMA command
pub const CM_AES_GCM_DECRYPT_DMA_MAX_AAD_SIZE: usize = MAX_CMB_DATA_SIZE;

// CM_AES_GCM_DECRYPT_DMA
// This command performs in-place AES-GCM decryption of data at an AXI address using DMA.
// It first verifies the SHA384 of the encrypted data, then performs decryption.
#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct CmAesGcmDecryptDmaReq {
    pub hdr: MailboxReqHeader,
    /// CMK (Cryptographic Mailbox Key) - 128 bytes
    pub cmk: Cmk,
    /// AES-GCM IV (12 bytes)
    pub iv: [u32; 3],
    /// AES-GCM tag (16 bytes)
    pub tag: [u32; 4],
    /// SHA384 hash of the encrypted data (48 bytes)
    pub encrypted_data_sha384: [u8; 48],
    /// AXI address (64 bits - low 32 bits)
    pub axi_addr_lo: u32,
    /// AXI address (64 bits - high 32 bits)
    pub axi_addr_hi: u32,
    /// Length of data to decrypt in bytes
    pub length: u32,
    /// Length of AAD in bytes
    pub aad_length: u32,
    /// AAD data (0..=4095 bytes)
    pub aad: [u8; CM_AES_GCM_DECRYPT_DMA_MAX_AAD_SIZE],
}

impl Default for CmAesGcmDecryptDmaReq {
    fn default() -> Self {
        Self {
            hdr: MailboxReqHeader::default(),
            cmk: Cmk::default(),
            iv: [0u32; 3],
            tag: [0u32; 4],
            encrypted_data_sha384: [0u8; 48],
            axi_addr_lo: 0,
            axi_addr_hi: 0,
            length: 0,
            aad_length: 0,
            aad: [0u8; CM_AES_GCM_DECRYPT_DMA_MAX_AAD_SIZE],
        }
    }
}

impl CmAesGcmDecryptDmaReq {
    pub fn as_bytes_partial(&self) -> CaliptraResult<&[u8]> {
        if self.aad_length as usize > CM_AES_GCM_DECRYPT_DMA_MAX_AAD_SIZE {
            return Err(CaliptraError::RUNTIME_MAILBOX_API_REQUEST_DATA_LEN_TOO_LARGE);
        }
        let unused_byte_count = CM_AES_GCM_DECRYPT_DMA_MAX_AAD_SIZE - self.aad_length as usize;
        Ok(&self.as_bytes()[..size_of::<Self>() - unused_byte_count])
    }

    pub fn as_bytes_partial_mut(&mut self) -> CaliptraResult<&mut [u8]> {
        if self.aad_length as usize > CM_AES_GCM_DECRYPT_DMA_MAX_AAD_SIZE {
            return Err(CaliptraError::RUNTIME_MAILBOX_API_REQUEST_DATA_LEN_TOO_LARGE);
        }
        let unused_byte_count = CM_AES_GCM_DECRYPT_DMA_MAX_AAD_SIZE - self.aad_length as usize;
        Ok(&mut self.as_mut_bytes()[..size_of::<Self>() - unused_byte_count])
    }
}

impl Request for CmAesGcmDecryptDmaReq {
    const ID: CommandId = CommandId::CM_AES_GCM_DECRYPT_DMA;
    type Resp = CmAesGcmDecryptDmaResp;
}

#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct CmAesGcmDecryptDmaResp {
    pub hdr: MailboxRespHeader,
    /// Indicates whether the GCM tag was verified successfully (1 = success, 0 = failure)
    pub tag_verified: u32,
}

impl Response for CmAesGcmDecryptDmaResp {}

// OCP_LOCK_REPORT_HEK_METADATA
#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, Immutable, KnownLayout, PartialEq, Eq)]
pub struct OcpLockReportHekMetadataReq {
    pub hdr: MailboxReqHeader,
    pub reserved0: u32,
    pub total_slots: u16,
    pub active_slots: u16,
    pub seed_state: u16,
    pub padding0: u16,
}
impl Request for OcpLockReportHekMetadataReq {
    const ID: CommandId = CommandId::OCP_LOCK_REPORT_HEK_METADATA;
    type Resp = OcpLockReportHekMetadataResp;
}

#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, Immutable, KnownLayout, PartialEq, Eq)]
pub struct OcpLockReportHekMetadataRespFlags(u32);

bitflags! {
    impl OcpLockReportHekMetadataRespFlags: u32 {
        const HEK_AVAILABLE = 1u32 << 31;
    }
}

#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, Immutable, KnownLayout, PartialEq, Eq)]
pub struct OcpLockReportHekMetadataResp {
    pub hdr: MailboxRespHeader,
    pub flags: OcpLockReportHekMetadataRespFlags,
    pub reserved: [u32; 3],
}
impl Response for OcpLockReportHekMetadataResp {}

// OCP_LOCK_GET_ALGORITHMS
#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, Immutable, KnownLayout, PartialEq, Eq)]
pub struct OcpLockGetAlgorithmsReq {
    pub hdr: MailboxReqHeader,
}
impl Request for OcpLockGetAlgorithmsReq {
    const ID: CommandId = CommandId::OCP_LOCK_GET_ALGORITHMS;
    type Resp = OcpLockGetAlgorithmsResp;
}

#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, Immutable, KnownLayout, PartialEq, Eq)]
pub struct EndorsementAlgorithms(u32);

bitflags! {
    impl EndorsementAlgorithms: u32 {
        const ECDSA_P384_SHA384 = 1 << 0;
        const ML_DSA_87 = 1 << 1;
    }
}

#[repr(C)]
#[derive(Clone, Debug, Default, IntoBytes, FromBytes, Immutable, KnownLayout, PartialEq, Eq)]
pub struct HpkeAlgorithms(u32);

bitflags! {
    impl HpkeAlgorithms: u32 {
        const ECDH_P384_HKDF_SHA384_AES_256_GCM = 1 << 0;
        const ML_KEM_1024_HKDF_SHA384_AES_256_GCM = 1 << 1;
        const ML_KEM_1024_ECDH_P384_HKDF_SHA384_AES_256_GCM = 1 << 2;
    }
}

#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, Immutable, KnownLayout, PartialEq, Eq)]
pub struct AccessKeySizes(u32);

bitflags! {
    impl AccessKeySizes: u32 {
        const LEN_256 = 1 << 0;
    }
}

#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, Immutable, KnownLayout, PartialEq, Eq)]
pub struct OcpLockGetAlgorithmsResp {
    pub hdr: MailboxRespHeader,
    pub reserved: [u32; 4],
    pub endorsement_algorithms: EndorsementAlgorithms,
    pub hpke_algorithms: HpkeAlgorithms,
    pub access_key_sizes: AccessKeySizes,
}
impl Response for OcpLockGetAlgorithmsResp {}

// OCP_LOCK_INITIALIZE_MEK_SECRET
#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, Immutable, KnownLayout, PartialEq, Eq)]
pub struct OcpLockInitializeMekSecretReq {
    pub hdr: MailboxReqHeader,
    pub reserved: u32,
    pub sek: [u8; 32],
    pub dpk: [u8; 32],
}
impl Request for OcpLockInitializeMekSecretReq {
    const ID: CommandId = CommandId::OCP_LOCK_INITIALIZE_MEK_SECRET;
    type Resp = OcpLockInitializeMekSecretResp;
}

#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, Immutable, KnownLayout, PartialEq, Eq)]
pub struct OcpLockInitializeMekSecretResp {
    pub hdr: MailboxRespHeader,
    pub reserved: u32,
}
impl Response for OcpLockInitializeMekSecretResp {}

// OCP_LOCK_DERIVE_MEK
#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, Immutable, KnownLayout, PartialEq, Eq)]
pub struct OcpLockDeriveMekReq {
    pub hdr: MailboxReqHeader,
    pub reserved: u32,
    pub mek_checksum: [u8; 16],
    pub metadata: [u8; 20],
    pub aux_metadata: [u8; 32],
    pub cmd_timeout: u32,
}
impl Request for OcpLockDeriveMekReq {
    const ID: CommandId = CommandId::OCP_LOCK_DERIVE_MEK;
    type Resp = OcpLockDeriveMekResp;
}

#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, Immutable, KnownLayout, PartialEq, Eq)]
pub struct OcpLockDeriveMekResp {
    pub hdr: MailboxRespHeader,
    pub reserved: u32,
    pub mek_checksum: [u8; 16],
}
impl Response for OcpLockDeriveMekResp {}

// OCP_LOCK_ENUMERATE_HPKE_HANDLES

#[derive(Clone, Debug, Default, IntoBytes, FromBytes, Immutable, KnownLayout, PartialEq, Eq)]
pub struct HpkeHandle {
    pub handle: u32,
    pub hpke_algorithm: HpkeAlgorithms,
}

#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, Immutable, KnownLayout, PartialEq, Eq)]
pub struct OcpLockEnumerateHpkeHandlesReq {
    pub hdr: MailboxReqHeader,
    pub reserved: u32,
}
impl Request for OcpLockEnumerateHpkeHandlesReq {
    const ID: CommandId = CommandId::OCP_LOCK_ENUMERATE_HPKE_HANDLES;
    type Resp = OcpLockEnumerateHpkeHandlesResp;
}

#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, Immutable, KnownLayout, PartialEq, Eq)]
pub struct OcpLockEnumerateHpkeHandlesResp {
    pub hdr: MailboxRespHeader,
    pub reserved: u32,
    pub hpke_handle_count: u32,
    pub hpke_handles: [HpkeHandle; OCP_LOCK_MAX_HPKE_HANDLES],
}
impl Response for OcpLockEnumerateHpkeHandlesResp {}

// OCP_LOCK_ROTATE_HPKE_KEY

#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, Immutable, KnownLayout, PartialEq, Eq)]
pub struct OcpLockRotateHpkeKeyReq {
    pub hdr: MailboxReqHeader,
    pub reserved: u32,
    pub hpke_handle: u32,
}
impl Request for OcpLockRotateHpkeKeyReq {
    const ID: CommandId = CommandId::OCP_LOCK_ROTATE_HPKE_KEY;
    type Resp = OcpLockRotateHpkeKeyResp;
}

#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, Immutable, KnownLayout, PartialEq, Eq)]
pub struct OcpLockRotateHpkeKeyResp {
    pub hdr: MailboxRespHeader,
    pub reserved: u32,
    pub hpke_handle: u32,
}
impl Response for OcpLockRotateHpkeKeyResp {}

// OCP_LOCK_GENERATE_MEK

#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, Immutable, KnownLayout, PartialEq, Eq)]
pub struct WrappedKey {
    pub key_type: u16,
    pub reserved: u16,
    pub salt: [u8; 12],
    pub metadata_len: u32,
    pub key_len: u32,
    pub iv: [u8; 12],
    pub metadata: [u8; OCP_LOCK_WRAPPED_KEY_MAX_METADATA_LEN],
    pub cipher_text_and_auth_tag: [u8; 80],
}

impl Default for WrappedKey {
    fn default() -> Self {
        WrappedKey {
            key_type: 0,
            reserved: 0,
            salt: [0; 12],
            metadata_len: 0,
            key_len: 0,
            iv: [0; 12],
            metadata: [0; OCP_LOCK_WRAPPED_KEY_MAX_METADATA_LEN],
            cipher_text_and_auth_tag: [0; 80],
        }
    }
}

#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, Immutable, KnownLayout, PartialEq, Eq)]
pub struct OcpLockGenerateMekReq {
    pub hdr: MailboxReqHeader,
    pub reserved: u32,
}
impl Request for OcpLockGenerateMekReq {
    const ID: CommandId = CommandId::OCP_LOCK_GENERATE_MEK;
    type Resp = OcpLockGenerateMekResp;
}

#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, Immutable, KnownLayout, PartialEq, Eq)]
pub struct OcpLockGenerateMekResp {
    pub hdr: MailboxRespHeader,
    pub reserved: u32,
    pub wrapped_mek: WrappedKey,
}
impl Response for OcpLockGenerateMekResp {}
// OCP_LOCK_ENDORSE_HPKE_PUB_KEY

#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, Immutable, KnownLayout, PartialEq, Eq)]
pub struct OcpLockEndorseHpkePubKeyReq {
    pub hdr: MailboxReqHeader,
    pub reserved: u32,
    pub hpke_handle: u32,
    pub endorsement_algorithm: EndorsementAlgorithms,
}
impl Request for OcpLockEndorseHpkePubKeyReq {
    const ID: CommandId = CommandId::OCP_LOCK_ENDORSE_HPKE_PUB_KEY;
    type Resp = OcpLockEndorseHpkePubKeyResp;
}

#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, Immutable, KnownLayout, PartialEq, Eq)]
pub struct OcpLockEndorseHpkePubKeyResp {
    pub hdr: MailboxRespHeader,
    pub reserved: u32,
    pub pub_key_len: u32,
    pub endorsement_len: u32,
    pub pub_key: [u8; OCP_LOCK_MAX_HPKE_PUBKEY_LEN],
    pub endorsement: [u8; OCP_LOCK_MAX_ENDORSEMENT_CERT_SIZE],
    pub padding: [u8; 7],
}

impl Default for OcpLockEndorseHpkePubKeyResp {
    fn default() -> Self {
        Self {
            hdr: MailboxRespHeader::default(),
            reserved: 0,
            pub_key_len: 0,
            endorsement_len: 0,
            pub_key: [0; OCP_LOCK_MAX_HPKE_PUBKEY_LEN],
            endorsement: [0; OCP_LOCK_MAX_ENDORSEMENT_CERT_SIZE],
            padding: [0; 7],
        }
    }
}

impl Response for OcpLockEndorseHpkePubKeyResp {}

// INSTALL_OWNER_PK_HASH
#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, Immutable, KnownLayout, PartialEq, Eq)]
pub struct InstallOwnerPkHashReq {
    pub hdr: MailboxReqHeader,
    pub digest: [u32; 12],
}

impl Request for InstallOwnerPkHashReq {
    const ID: CommandId = CommandId::INSTALL_OWNER_PK_HASH;
    type Resp = InstallOwnerPkHashResp;
}

#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, Immutable, KnownLayout, PartialEq, Eq)]
pub struct InstallOwnerPkHashResp {
    pub hdr: MailboxRespHeader,
    pub dpe_result: u32,
}
impl Response for InstallOwnerPkHashResp {}

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

// ZeroizeUdsFe command flags
pub const ZEROIZE_UDS_FLAG: u32 = 0x01; // Bit 0: UDS partition
pub const ZEROIZE_FE0_FLAG: u32 = 0x02; // Bit 1: FE partition 0
pub const ZEROIZE_FE1_FLAG: u32 = 0x04; // Bit 2: FE partition 1
pub const ZEROIZE_FE2_FLAG: u32 = 0x08; // Bit 3: FE partition 2
pub const ZEROIZE_FE3_FLAG: u32 = 0x10; // Bit 4: FE partition 3

#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, Immutable, KnownLayout, PartialEq, Eq)]
pub struct ZeroizeUdsFeReq {
    pub hdr: MailboxReqHeader,
    /// Zeroize flags
    pub flags: u32,
}

#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, Immutable, KnownLayout, PartialEq, Eq)]
pub struct ZeroizeUdsFeResp {
    pub hdr: MailboxRespHeader,
    pub dpe_result: u32,
}

impl Request for ZeroizeUdsFeReq {
    const ID: CommandId = CommandId::ZEROIZE_UDS_FE;
    type Resp = ZeroizeUdsFeResp;
}

impl Response for ZeroizeUdsFeResp {}

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
