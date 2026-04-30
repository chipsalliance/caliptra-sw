// Licensed under the Apache-2.0 license

use crate::Drivers;
use caliptra_common::x509;
use caliptra_drivers::{KeyReadArgs, Mldsa87Seed, Mldsa87SignRnd};
use caliptra_error::{CaliptraError, CaliptraResult};
use caliptra_ocp_eat::csr_eat::{oids, CsrEatClaims};
use caliptra_ocp_eat::{cbor::TaggedOid, cbor_tags, CborEncoder, CoseSign1, ProtectedHeader};
use caliptra_registers::mbox::enums::MboxStatusE;
use core::mem::size_of;

mod fmc_alias;
mod ldevid;
mod rt_alias;

use fmc_alias::{generate_fmc_alias_ecc_csr, generate_fmc_alias_mldsa_csr};
use ldevid::{generate_ldevid_ecc_csr, generate_ldevid_mldsa_csr};
use rt_alias::{generate_rt_alias_ecc_csr, generate_rt_alias_mldsa_csr};

// Maximum size for CSR EAT claims payload (CBOR encoded)
// Calculation for ML-DSA CSR (worst case, assuming 7680-byte CSR):
// - Map header (3 items): 1 byte
// - Nonce claim (32 bytes): 1 (key 10) + 2 (bstr header) + 32 (data) = 35 bytes
// - CSR claim (7680 bytes): 5 (key -70001) + 3 (bstr header) + 7680 (data) = 7688 bytes
// - Attributes claim (1 OID, 11 bytes): 5 (key -70002) + 1 (array header) + 2 (tag 111) + 1 (bstr header) + 11 (OID) = 20 bytes
// Total: 7744 bytes, rounded up to 8KB for safety
pub(crate) const MAX_CSR_EAT_CLAIMS_SIZE: usize = 8192;

// Maximum size for COSE Sign1 signature context (Sig_structure)
// Calculation (worst case with ML-DSA-87, kid = 20 bytes):
// - Array header (4 items): 1 byte
// - Context string "Signature1": 1 (text header) + 10 (chars) = 11 bytes
// - Protected header (byte string): 2 (bstr header) + 30 (serialized map) = 32 bytes
//     Map header (3 entries): 1 byte
//     Algorithm (key 1: 1 byte + alg -51/-50: 2 bytes): 3 bytes
//     Content-type (key 3: 1 byte + uint 263: 3 bytes): 4 bytes
//     Key ID (key 4: 1 byte + bstr 20: 1 + 20 bytes): 22 bytes
// - External AAD (empty bstr): 1 byte
// - Payload (CSR EAT claims, up to 7744 bytes): 3 (bstr header) + 7744 (data) = 7747 bytes
// Total: 7792 bytes, rounded up to 8KB for safety
pub(crate) const MAX_SIGN_CONTEXT_SIZE: usize = 8192;
pub(crate) const MAX_CSR_SIZE: usize = 8192;

enum CryptoType {
    ECC384,
    MLDSA87,
}

pub(crate) enum DevIdKeyType {
    LdevId = 1,
    FmcAlias = 2,
    RtAlias = 3,
}

impl TryFrom<u32> for DevIdKeyType {
    type Error = CaliptraError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(DevIdKeyType::LdevId),
            2 => Ok(DevIdKeyType::FmcAlias),
            3 => Ok(DevIdKeyType::RtAlias),
            _ => Err(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS),
        }
    }
}

impl DevIdKeyType {
    pub fn to_kda_oid(&self) -> TaggedOid {
        match self {
            DevIdKeyType::LdevId => TaggedOid::new(oids::OCP_SECURITY_OID_KDA_OWNER_ENTROPY_FUSE),
            DevIdKeyType::FmcAlias => TaggedOid::new(oids::OCP_SECURITY_OID_KDA_FIRST_MUTABLE_CODE),
            DevIdKeyType::RtAlias => {
                TaggedOid::new(oids::OCP_SECURITY_OID_KDA_NON_FIRST_MUTABLE_CODE)
            }
        }
    }

    pub fn generate_ecc_csr(
        &self,
        drivers: &mut Drivers,
        csr_buf: &mut [u8; MAX_CSR_SIZE],
    ) -> CaliptraResult<usize> {
        match self {
            DevIdKeyType::LdevId => generate_ldevid_ecc_csr(drivers, csr_buf),
            DevIdKeyType::FmcAlias => generate_fmc_alias_ecc_csr(drivers, csr_buf),
            DevIdKeyType::RtAlias => generate_rt_alias_ecc_csr(drivers, csr_buf),
        }
    }

    pub fn generate_mldsa_csr(
        &self,
        drivers: &mut Drivers,
        csr_buf: &mut [u8; MAX_CSR_SIZE],
    ) -> CaliptraResult<usize> {
        match self {
            DevIdKeyType::LdevId => generate_ldevid_mldsa_csr(drivers, csr_buf),
            DevIdKeyType::FmcAlias => generate_fmc_alias_mldsa_csr(drivers, csr_buf),
            DevIdKeyType::RtAlias => generate_rt_alias_mldsa_csr(drivers, csr_buf),
        }
    }

    fn generate_csr_eat_claims(
        &self,
        drivers: &mut Drivers,
        nonce: &[u8; 32],
        csr_buf: &mut [u8; MAX_CSR_SIZE],
        eat_buffer: &mut [u8],
        crypto: CryptoType,
    ) -> CaliptraResult<usize> {
        let attributes = [self.to_kda_oid()];
        let csr_len = match crypto {
            CryptoType::ECC384 => self.generate_ecc_csr(drivers, csr_buf),
            CryptoType::MLDSA87 => self.generate_mldsa_csr(drivers, csr_buf),
        }?;

        let attested_csr = CsrEatClaims::with_nonce(
            csr_buf
                .get(..csr_len)
                .ok_or(CaliptraError::RUNTIME_ATTESTED_CSR_EAT_ENCODING_ERROR)?,
            &attributes,
            nonce,
        );
        let mut cbor_eat_encoder = CborEncoder::new(eat_buffer);

        attested_csr
            .encode(&mut cbor_eat_encoder)
            .map_err(|_| CaliptraError::RUNTIME_ATTESTED_CSR_EAT_ENCODING_ERROR)?;

        Ok(cbor_eat_encoder.len())
    }

    pub fn generate_attested_ecc_csr(
        &self,
        drivers: &mut Drivers,
        payload: &[u8],
        rt_key_id: &[u8; 20],
        rt_pub_key: &caliptra_drivers::Ecc384PubKey,
        sign_ctx_buf: &mut [u8; MAX_SIGN_CONTEXT_SIZE],
        signed_eat_buffer: &mut [u8],
    ) -> CaliptraResult<usize> {
        // Create protected header
        let mut protected_header = ProtectedHeader::new_es384();
        protected_header.kid = Some(rt_key_id);

        let cose_sign1 = CoseSign1::new(signed_eat_buffer)
            .protected_header(&protected_header)
            .payload(payload);

        let sign_ctx_len = cose_sign1
            .get_signature_context(sign_ctx_buf)
            .map_err(|_| CaliptraError::RUNTIME_ATTESTED_CSR_COSE_SIGN1_ENCODING_ERROR)?;

        // Hash the signature context using SHA384
        let signature_slice = &sign_ctx_buf
            .get(..sign_ctx_len)
            .ok_or(CaliptraError::RUNTIME_ATTESTED_CSR_COSE_SIGN1_ENCODING_ERROR)?;
        let digest = drivers.sha2_512_384.sha384_digest(signature_slice);
        let digest = caliptra_drivers::okref(&digest)?;

        // Get RT Alias private key from key vault
        let key_id_rt_priv_key = Drivers::get_key_id_rt_ecc_priv_key(drivers)?;

        // Sign the digest with RT Alias private key
        let priv_key_args = KeyReadArgs::new(key_id_rt_priv_key);
        let priv_key = caliptra_drivers::Ecc384PrivKeyIn::Key(priv_key_args);
        let signature = drivers
            .ecc384
            .sign(priv_key, rt_pub_key, digest, &mut drivers.trng)?;

        // Convert signature to [u8; 96] format (r || s)
        let mut ecc384_signature = [0u8; 96];
        let r_bytes: [u8; 48] = signature.r.into();
        let s_bytes: [u8; 48] = signature.s.into();
        ecc384_signature[..48].copy_from_slice(&r_bytes);
        ecc384_signature[48..].copy_from_slice(&s_bytes);

        // Complete encoding COSE Sign1 structure with signature and CWT tag
        let signed_eat_len = cose_sign1
            .signature(&ecc384_signature)
            .encode(Some(&[cbor_tags::CWT]))
            .map_err(|_| CaliptraError::RUNTIME_ATTESTED_CSR_COSE_SIGN1_ENCODING_ERROR)?;

        Ok(signed_eat_len)
    }

    pub fn generate_attested_mldsa_csr(
        &self,
        drivers: &mut Drivers,
        payload: &[u8],
        rt_key_id: &[u8; 20],
        rt_pub_key: &caliptra_drivers::Mldsa87PubKey,
        sign_ctx_buf: &mut [u8; MAX_SIGN_CONTEXT_SIZE],
        signed_eat_buffer: &mut [u8],
    ) -> CaliptraResult<usize> {
        // Create protected header
        let mut protected_header = ProtectedHeader::new_mldsa87();
        protected_header.kid = Some(rt_key_id);

        let cose_sign1 = CoseSign1::new(signed_eat_buffer)
            .protected_header(&protected_header)
            .payload(payload);

        let sign_ctx_len = cose_sign1
            .get_signature_context(sign_ctx_buf)
            .map_err(|_| CaliptraError::RUNTIME_ATTESTED_CSR_COSE_SIGN1_ENCODING_ERROR)?;

        // Hash the signature context using SHA384
        let signature_slice = &sign_ctx_buf
            .get(..sign_ctx_len)
            .ok_or(CaliptraError::RUNTIME_ATTESTED_CSR_COSE_SIGN1_ENCODING_ERROR)?;
        let digest = drivers.sha2_512_384.sha384_digest(signature_slice);
        let digest = caliptra_drivers::okref(&digest)?;

        let rt_seed = Drivers::get_key_id_rt_mldsa_keypair_seed(drivers)?;
        let key_args = KeyReadArgs::new(rt_seed);

        let signature = drivers.mldsa87.sign_var(
            Mldsa87Seed::Key(key_args),
            rt_pub_key,
            digest.as_bytes(),
            &Mldsa87SignRnd::default(),
            &mut drivers.trng,
        )?;

        // Complete encoding COSE Sign1 structure with signature and CWT tag
        let signed_eat_len = cose_sign1
            .signature(signature.as_bytes())
            .encode(Some(&[cbor_tags::CWT]))
            .map_err(|_| CaliptraError::RUNTIME_ATTESTED_CSR_COSE_SIGN1_ENCODING_ERROR)?;

        Ok(signed_eat_len)
    }
}

// --- Mailbox command handlers ---

use crate::mutrefbytes;
use caliptra_api::mailbox::{GetAttestedEccCsrReq, GetAttestedMldsaCsrReq};
use caliptra_cfi_derive_git::cfi_impl_fn;
use caliptra_common::mailbox_api::{AttestedCsrResp, ResponseVarSize};
use zerocopy::{FromBytes, IntoBytes};

pub struct AttestedEccCsrCmd;

impl AttestedEccCsrCmd {
    /// Heavy phase: generates the CSR EAT claims and the RT alias ECC
    /// public key + subject key identifier. Runs in a frame that does
    /// NOT have the mailbox response buffer alive, keeping peak stack
    /// usage low.
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    #[inline(never)]
    fn prepare(
        drivers: &mut Drivers,
        nonce: &[u8; 32],
        key_type: &DevIdKeyType,
        scratch: &mut [u8; MAX_CSR_SIZE],
        env_csr_eat: &mut [u8; MAX_CSR_EAT_CLAIMS_SIZE],
    ) -> CaliptraResult<(usize, caliptra_drivers::Ecc384PubKey, [u8; 20])> {
        let csr_eat_len = key_type.generate_csr_eat_claims(
            drivers,
            nonce,
            scratch,
            env_csr_eat,
            CryptoType::ECC384,
        )?;

        let rt_pub_key = drivers.persistent_data.get().fht.rt_dice_ecc_pub_key;
        let rt_subj_sn = x509::subj_key_id(
            &mut drivers.sha256,
            &caliptra_common::crypto::PubKey::Ecc(&rt_pub_key),
        )?;
        Ok((csr_eat_len, rt_pub_key, rt_subj_sn))
    }

    /// Signing phase: allocates the mailbox response buffer and writes
    /// the COSE-Sign1-encoded attested CSR EAT into it. This runs after
    /// [`prepare`] so the heavy CSR/key generation does not overlap with
    /// the response buffer.
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    #[inline(never)]
    fn sign_and_finalize(
        drivers: &mut Drivers,
        key_type: &DevIdKeyType,
        csr_eat: &[u8],
        rt_subj_sn: &[u8; 20],
        rt_pub_key: &caliptra_drivers::Ecc384PubKey,
        scratch: &mut [u8; MAX_SIGN_CONTEXT_SIZE],
    ) -> CaliptraResult<MboxStatusE> {
        let mut resp_buf = [0u8; size_of::<AttestedCsrResp>()];
        let resp = mutrefbytes::<AttestedCsrResp>(&mut resp_buf)?;
        let signed_eat_len = key_type.generate_attested_ecc_csr(
            drivers,
            csr_eat,
            rt_subj_sn,
            rt_pub_key,
            scratch,
            resp.data.as_mut(),
        )?;
        resp.data_size = signed_eat_len as u32;
        let len = resp.partial_len()?;
        crate::finalize_response(drivers, &mut resp_buf, len)
    }

    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    #[inline(never)]
    pub(crate) fn execute(drivers: &mut Drivers, cmd_args: &[u8]) -> CaliptraResult<MboxStatusE> {
        let cmd = GetAttestedEccCsrReq::ref_from_bytes(cmd_args)
            .map_err(|_| CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;

        let key_type = DevIdKeyType::try_from(cmd.key_id)?;
        let nonce = cmd.nonce;

        // Single scratch buffer reused: first as CSR temp, then as signature context
        let mut scratch = [0u8; MAX_CSR_SIZE];
        let mut env_csr_eat = [0u8; MAX_CSR_EAT_CLAIMS_SIZE];

        let (csr_eat_len, rt_pub_key, rt_subj_sn) =
            Self::prepare(drivers, &nonce, &key_type, &mut scratch, &mut env_csr_eat)?;

        let csr_slice = env_csr_eat
            .get(..csr_eat_len)
            .ok_or(CaliptraError::RUNTIME_ATTESTED_CSR_EAT_ENCODING_ERROR)?;
        Self::sign_and_finalize(
            drivers,
            &key_type,
            csr_slice,
            &rt_subj_sn,
            &rt_pub_key,
            &mut scratch,
        )
    }
}

pub struct AttestedMldsaCsrCmd;

impl AttestedMldsaCsrCmd {
    /// Heavy phase: generates the CSR EAT claims and the RT alias MLDSA
    /// public key + subject key identifier. This runs the expensive MLDSA
    /// key-pair generation (with its PCT) in a frame that does NOT have
    /// the mailbox response buffer alive, so the peak stack usage is
    /// minimized.
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    #[inline(never)]
    fn prepare(
        drivers: &mut Drivers,
        nonce: &[u8; 32],
        key_type: &DevIdKeyType,
        scratch: &mut [u8; MAX_CSR_SIZE],
        env_csr_eat: &mut [u8; MAX_CSR_EAT_CLAIMS_SIZE],
    ) -> CaliptraResult<(usize, caliptra_drivers::Mldsa87PubKey, [u8; 20])> {
        let csr_eat_len = key_type.generate_csr_eat_claims(
            drivers,
            nonce,
            scratch,
            env_csr_eat,
            CryptoType::MLDSA87,
        )?;

        // Compute RT Alias MLDSA public key (expensive: triggers
        // key-pair generation + PCT) and subject key identifier.
        let rt_pub_key = Drivers::get_key_id_rt_mldsa_pub_key(drivers)?;
        let rt_subj_sn = x509::subj_key_id(
            &mut drivers.sha256,
            &caliptra_common::crypto::PubKey::Mldsa(&rt_pub_key),
        )?;
        Ok((csr_eat_len, rt_pub_key, rt_subj_sn))
    }

    /// Signing phase: allocates the mailbox response buffer and writes
    /// the COSE-Sign1-encoded attested CSR EAT into it. This runs after
    /// [`prepare`] so the heavy CSR/key generation does not overlap with
    /// the response buffer.
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    #[inline(never)]
    fn sign_and_finalize(
        drivers: &mut Drivers,
        key_type: &DevIdKeyType,
        csr_eat: &[u8],
        rt_subj_sn: &[u8; 20],
        rt_pub_key: &caliptra_drivers::Mldsa87PubKey,
        scratch: &mut [u8; MAX_SIGN_CONTEXT_SIZE],
    ) -> CaliptraResult<MboxStatusE> {
        let mut resp_buf = [0u8; size_of::<AttestedCsrResp>()];
        let resp = mutrefbytes::<AttestedCsrResp>(&mut resp_buf)?;
        let signed_eat_len = key_type.generate_attested_mldsa_csr(
            drivers,
            csr_eat,
            rt_subj_sn,
            rt_pub_key,
            scratch,
            resp.data.as_mut(),
        )?;
        resp.data_size = signed_eat_len as u32;
        let len = resp.partial_len()?;
        crate::finalize_response(drivers, &mut resp_buf, len)
    }

    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    #[inline(never)]
    pub(crate) fn execute(drivers: &mut Drivers, cmd_args: &[u8]) -> CaliptraResult<MboxStatusE> {
        let cmd = GetAttestedMldsaCsrReq::ref_from_bytes(cmd_args)
            .map_err(|_| CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;

        let key_type = DevIdKeyType::try_from(cmd.key_id)?;
        let nonce = cmd.nonce;

        // Single scratch buffer reused: first as CSR temp, then as signature context
        let mut scratch = [0u8; MAX_CSR_SIZE];
        let mut env_csr_eat = [0u8; MAX_CSR_EAT_CLAIMS_SIZE];

        let (csr_eat_len, rt_pub_key, rt_subj_sn) =
            Self::prepare(drivers, &nonce, &key_type, &mut scratch, &mut env_csr_eat)?;

        let csr_slice = env_csr_eat
            .get(..csr_eat_len)
            .ok_or(CaliptraError::RUNTIME_ATTESTED_CSR_EAT_ENCODING_ERROR)?;
        Self::sign_and_finalize(
            drivers,
            &key_type,
            csr_slice,
            &rt_subj_sn,
            &rt_pub_key,
            &mut scratch,
        )
    }
}
