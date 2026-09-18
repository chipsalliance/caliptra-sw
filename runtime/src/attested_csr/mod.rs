// Licensed under the Apache-2.0 license

use crate::Drivers;
use caliptra_common::x509;
use caliptra_drivers::sha2_512_384::Sha2DigestOpTrait;
use caliptra_drivers::{Array4x12, KeyReadArgs, Mldsa87Seed, Mldsa87SignRnd};
use caliptra_error::{CaliptraError, CaliptraResult};
use caliptra_registers::mbox::enums::MboxStatusE;
use core::mem::size_of;
use zerocopy::IntoBytes;

mod fmc_alias;
mod ldevid;
mod rt_alias;

use fmc_alias::{generate_fmc_alias_ecc_csr, generate_fmc_alias_mldsa_csr};
use ldevid::{generate_ldevid_ecc_csr, generate_ldevid_mldsa_csr};
use rt_alias::{generate_rt_alias_ecc_csr, generate_rt_alias_mldsa_csr};

include!(concat!(env!("OUT_DIR"), "/attested_csr_template.rs"));

// Maximum size for CSR EAT claims payload (CBOR encoded)
pub(crate) const MAX_CSR_EAT_CLAIMS_SIZE: usize = 8192;
const MAX_CSR_BSTR_HEADER_LEN: usize = 3;

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

fn write_cbor_bstr_header(buf: &mut [u8], len: usize) -> CaliptraResult<usize> {
    if len <= CBOR_MAX_INLINE_LEN {
        let b = buf
            .get_mut(0)
            .ok_or(CaliptraError::RUNTIME_INSUFFICIENT_MEMORY)?;
        *b = CBOR_BYTE_STRING_TINY_BASE | (len as u8);
        Ok(1)
    } else if len <= u8::MAX as usize {
        if buf.len() < 2 {
            return Err(CaliptraError::RUNTIME_INSUFFICIENT_MEMORY);
        }
        buf[0] = CBOR_BYTE_STRING_1BYTE_LEN;
        buf[1] = len as u8;
        Ok(2)
    } else if len <= u16::MAX as usize {
        if buf.len() < 3 {
            return Err(CaliptraError::RUNTIME_INSUFFICIENT_MEMORY);
        }
        buf[0] = CBOR_BYTE_STRING_2BYTE_LEN;
        buf[1] = (len >> 8) as u8;
        buf[2] = (len & 0xff) as u8;
        Ok(3)
    } else {
        Err(CaliptraError::RUNTIME_ATTESTED_CSR_EAT_ENCODING_ERROR)
    }
}

impl DevIdKeyType {
    fn generate_csr(
        &self,
        drivers: &mut Drivers,
        crypto: CryptoType,
        buf: &mut [u8],
    ) -> CaliptraResult<usize> {
        match (self, crypto) {
            (DevIdKeyType::LdevId, CryptoType::ECC384) => generate_ldevid_ecc_csr(drivers, buf),
            (DevIdKeyType::LdevId, CryptoType::MLDSA87) => generate_ldevid_mldsa_csr(drivers, buf),
            (DevIdKeyType::FmcAlias, CryptoType::ECC384) => {
                generate_fmc_alias_ecc_csr(drivers, buf)
            }
            (DevIdKeyType::FmcAlias, CryptoType::MLDSA87) => {
                generate_fmc_alias_mldsa_csr(drivers, buf)
            }
            (DevIdKeyType::RtAlias, CryptoType::ECC384) => generate_rt_alias_ecc_csr(drivers, buf),
            (DevIdKeyType::RtAlias, CryptoType::MLDSA87) => {
                generate_rt_alias_mldsa_csr(drivers, buf)
            }
        }
    }

    fn generate_csr_eat_claims(
        &self,
        drivers: &mut Drivers,
        nonce: &[u8; 32],
        eat_buffer: &mut [u8],
        crypto: CryptoType,
    ) -> CaliptraResult<usize> {
        let suffix = match self {
            DevIdKeyType::LdevId => &CSR_EAT_SUFFIX_LDEVID[..],
            DevIdKeyType::FmcAlias => &CSR_EAT_SUFFIX_FMC_ALIAS[..],
            DevIdKeyType::RtAlias => &CSR_EAT_SUFFIX_RT_ALIAS[..],
        };

        let prefix_len = CSR_EAT_PREFIX.len() + nonce.len() + CSR_EAT_CLAIM_KEY_CSR.len();
        let reserved_csr_start = prefix_len + MAX_CSR_BSTR_HEADER_LEN;

        if eat_buffer.len() < reserved_csr_start {
            return Err(CaliptraError::RUNTIME_INSUFFICIENT_MEMORY);
        }

        // Write prefix before CSR
        eat_buffer[..CSR_EAT_PREFIX.len()].copy_from_slice(&CSR_EAT_PREFIX);
        let mut offset = CSR_EAT_PREFIX.len();
        eat_buffer[offset..offset + nonce.len()].copy_from_slice(nonce);
        offset += nonce.len();
        eat_buffer[offset..offset + CSR_EAT_CLAIM_KEY_CSR.len()]
            .copy_from_slice(&CSR_EAT_CLAIM_KEY_CSR);

        // Generate CSR directly into eat_buffer after reserved bstr header
        let csr_len = self.generate_csr(drivers, crypto, &mut eat_buffer[reserved_csr_start..])?;

        // Determine actual bstr header length
        let mut bstr_hdr = [0u8; 3];
        let bstr_hdr_len = write_cbor_bstr_header(&mut bstr_hdr, csr_len)?;

        // If actual bstr header is shorter than reserved 3 bytes, shift CSR data left
        let actual_csr_start = prefix_len + bstr_hdr_len;
        if bstr_hdr_len < MAX_CSR_BSTR_HEADER_LEN {
            eat_buffer.copy_within(
                reserved_csr_start..reserved_csr_start + csr_len,
                actual_csr_start,
            );
        }
        eat_buffer[prefix_len..actual_csr_start].copy_from_slice(&bstr_hdr[..bstr_hdr_len]);

        let csr_end = actual_csr_start
            .checked_add(csr_len)
            .ok_or(CaliptraError::RUNTIME_INSUFFICIENT_MEMORY)?;
        let total_len = csr_end
            .checked_add(suffix.len())
            .ok_or(CaliptraError::RUNTIME_INSUFFICIENT_MEMORY)?;
        if eat_buffer.len() < total_len {
            return Err(CaliptraError::RUNTIME_INSUFFICIENT_MEMORY);
        }

        let suffix_dest = eat_buffer
            .get_mut(csr_end..total_len)
            .ok_or(CaliptraError::RUNTIME_INSUFFICIENT_MEMORY)?;
        if suffix_dest.len() != suffix.len() {
            return Err(CaliptraError::RUNTIME_INSUFFICIENT_MEMORY);
        }
        suffix_dest.copy_from_slice(suffix);
        Ok(total_len)
    }
}

fn generate_keypair_inventory_eat_claims(
    nonce: &[u8; 32],
    eat_buffer: &mut [u8],
) -> CaliptraResult<usize> {
    let total_len = KEYPAIR_INVENTORY_PREFIX.len() + nonce.len() + KEYPAIR_INVENTORY_SUFFIX.len();
    if eat_buffer.len() < total_len {
        return Err(CaliptraError::RUNTIME_INSUFFICIENT_MEMORY);
    }
    let mut offset = 0;
    eat_buffer[offset..offset + KEYPAIR_INVENTORY_PREFIX.len()]
        .copy_from_slice(&KEYPAIR_INVENTORY_PREFIX);
    offset += KEYPAIR_INVENTORY_PREFIX.len();
    eat_buffer[offset..offset + nonce.len()].copy_from_slice(nonce);
    offset += nonce.len();
    eat_buffer[offset..offset + KEYPAIR_INVENTORY_SUFFIX.len()]
        .copy_from_slice(&KEYPAIR_INVENTORY_SUFFIX);
    offset += KEYPAIR_INVENTORY_SUFFIX.len();
    Ok(offset)
}

fn sign_attested_ecc_csr(
    drivers: &mut Drivers,
    payload: &[u8],
    rt_key_id: &[u8; 20],
    rt_pub_key: &caliptra_drivers::Ecc384PubKey,
    signed_eat_buffer: &mut [u8],
) -> CaliptraResult<usize> {
    let mut payload_bstr_hdr = [0u8; 3];
    let payload_bstr_hdr_len = write_cbor_bstr_header(&mut payload_bstr_hdr, payload.len())?;

    // Hash Sig_structure by streaming into SHA384 without stack buffers
    let mut op = drivers.sha2_512_384.sha384_digest_init()?;
    op.update(&SIG_PREAMBLE_ECC_BEFORE_KID)?;
    op.update(rt_key_id)?;
    op.update(&SIG_ECC_AFTER_KID_BEFORE_PAYLOAD_LEN)?;
    op.update(&payload_bstr_hdr[..payload_bstr_hdr_len])?;
    op.update(payload)?;
    let mut digest = Array4x12::default();
    op.finalize(&mut digest)?;

    // Get RT Alias private key and sign digest
    let key_id_rt_priv_key = Drivers::get_key_id_rt_ecc_priv_key(drivers)?;
    let priv_key_args = KeyReadArgs::new(key_id_rt_priv_key);
    let priv_key = caliptra_drivers::Ecc384PrivKeyIn::Key(priv_key_args);
    let signature = drivers
        .ecc384
        .sign(priv_key, rt_pub_key, &digest, &mut drivers.trng)?;

    let mut ecc384_signature = [0u8; 96];
    let r_bytes: [u8; 48] = signature.r.into();
    let s_bytes: [u8; 48] = signature.s.into();
    ecc384_signature[..48].copy_from_slice(&r_bytes);
    ecc384_signature[48..].copy_from_slice(&s_bytes);

    // Assemble COSE Sign1 envelope into signed_eat_buffer
    let total_len = COSE_PREAMBLE_ECC_BEFORE_KID.len()
        + 20
        + COSE_ECC_AFTER_KID_BEFORE_PAYLOAD_LEN.len()
        + payload_bstr_hdr_len
        + payload.len()
        + COSE_ECC_SIG_BSTR_HEADER.len()
        + 96;
    if signed_eat_buffer.len() < total_len {
        return Err(CaliptraError::RUNTIME_INSUFFICIENT_MEMORY);
    }

    let mut offset = 0;
    signed_eat_buffer[offset..offset + COSE_PREAMBLE_ECC_BEFORE_KID.len()]
        .copy_from_slice(&COSE_PREAMBLE_ECC_BEFORE_KID);
    offset += COSE_PREAMBLE_ECC_BEFORE_KID.len();
    signed_eat_buffer[offset..offset + 20].copy_from_slice(rt_key_id);
    offset += 20;
    signed_eat_buffer[offset..offset + COSE_ECC_AFTER_KID_BEFORE_PAYLOAD_LEN.len()]
        .copy_from_slice(&COSE_ECC_AFTER_KID_BEFORE_PAYLOAD_LEN);
    offset += COSE_ECC_AFTER_KID_BEFORE_PAYLOAD_LEN.len();
    signed_eat_buffer[offset..offset + payload_bstr_hdr_len]
        .copy_from_slice(&payload_bstr_hdr[..payload_bstr_hdr_len]);
    offset += payload_bstr_hdr_len;
    signed_eat_buffer[offset..offset + payload.len()].copy_from_slice(payload);
    offset += payload.len();
    signed_eat_buffer[offset..offset + COSE_ECC_SIG_BSTR_HEADER.len()]
        .copy_from_slice(&COSE_ECC_SIG_BSTR_HEADER);
    offset += COSE_ECC_SIG_BSTR_HEADER.len();
    signed_eat_buffer[offset..offset + 96].copy_from_slice(&ecc384_signature);
    offset += 96;

    Ok(offset)
}

fn sign_attested_mldsa_csr(
    drivers: &mut Drivers,
    payload: &[u8],
    rt_key_id: &[u8; 20],
    rt_pub_key: &caliptra_drivers::Mldsa87PubKey,
    signed_eat_buffer: &mut [u8],
) -> CaliptraResult<usize> {
    let mut payload_bstr_hdr = [0u8; 3];
    let payload_bstr_hdr_len = write_cbor_bstr_header(&mut payload_bstr_hdr, payload.len())?;

    let sig_ctx_len = SIG_PREAMBLE_MLDSA_BEFORE_KID.len()
        + 20
        + SIG_MLDSA_AFTER_KID_BEFORE_PAYLOAD_LEN.len()
        + payload_bstr_hdr_len
        + payload.len();
    let total_len = COSE_PREAMBLE_MLDSA_BEFORE_KID.len()
        + 20
        + COSE_MLDSA_AFTER_KID_BEFORE_PAYLOAD_LEN.len()
        + payload_bstr_hdr_len
        + payload.len()
        + COSE_MLDSA_SIG_BSTR_HEADER.len()
        + 4627;

    if signed_eat_buffer.len() < sig_ctx_len || signed_eat_buffer.len() < total_len {
        return Err(CaliptraError::RUNTIME_INSUFFICIENT_MEMORY);
    }

    // Assemble Sig_structure in place directly into signed_eat_buffer (pure ML-DSA-87 per RFC 9964)
    let mut offset = 0;
    signed_eat_buffer[offset..offset + SIG_PREAMBLE_MLDSA_BEFORE_KID.len()]
        .copy_from_slice(&SIG_PREAMBLE_MLDSA_BEFORE_KID);
    offset += SIG_PREAMBLE_MLDSA_BEFORE_KID.len();
    signed_eat_buffer[offset..offset + 20].copy_from_slice(rt_key_id);
    offset += 20;
    signed_eat_buffer[offset..offset + SIG_MLDSA_AFTER_KID_BEFORE_PAYLOAD_LEN.len()]
        .copy_from_slice(&SIG_MLDSA_AFTER_KID_BEFORE_PAYLOAD_LEN);
    offset += SIG_MLDSA_AFTER_KID_BEFORE_PAYLOAD_LEN.len();
    signed_eat_buffer[offset..offset + payload_bstr_hdr_len]
        .copy_from_slice(&payload_bstr_hdr[..payload_bstr_hdr_len]);
    offset += payload_bstr_hdr_len;
    signed_eat_buffer[offset..offset + payload.len()].copy_from_slice(payload);
    offset += payload.len();

    let rt_seed = Drivers::get_key_id_rt_mldsa_keypair_seed(drivers)?;
    let key_args = KeyReadArgs::new(rt_seed);

    let signature = drivers.mldsa87.sign_var(
        Mldsa87Seed::Key(key_args),
        rt_pub_key,
        &signed_eat_buffer[..offset],
        &Mldsa87SignRnd::default(),
        &mut drivers.trng,
    )?;

    // Assemble final COSE Sign1 envelope in place into signed_eat_buffer (ML-DSA-87 signature is 4627 bytes)
    let sig_bytes = signature
        .as_bytes()
        .get(..4627)
        .ok_or(CaliptraError::RUNTIME_INTERNAL)?;

    let mut offset = 0;
    signed_eat_buffer[offset..offset + COSE_PREAMBLE_MLDSA_BEFORE_KID.len()]
        .copy_from_slice(&COSE_PREAMBLE_MLDSA_BEFORE_KID);
    offset += COSE_PREAMBLE_MLDSA_BEFORE_KID.len();
    signed_eat_buffer[offset..offset + 20].copy_from_slice(rt_key_id);
    offset += 20;
    signed_eat_buffer[offset..offset + COSE_MLDSA_AFTER_KID_BEFORE_PAYLOAD_LEN.len()]
        .copy_from_slice(&COSE_MLDSA_AFTER_KID_BEFORE_PAYLOAD_LEN);
    offset += COSE_MLDSA_AFTER_KID_BEFORE_PAYLOAD_LEN.len();
    signed_eat_buffer[offset..offset + payload_bstr_hdr_len]
        .copy_from_slice(&payload_bstr_hdr[..payload_bstr_hdr_len]);
    offset += payload_bstr_hdr_len;
    signed_eat_buffer[offset..offset + payload.len()].copy_from_slice(payload);
    offset += payload.len();
    signed_eat_buffer[offset..offset + COSE_MLDSA_SIG_BSTR_HEADER.len()]
        .copy_from_slice(&COSE_MLDSA_SIG_BSTR_HEADER);
    offset += COSE_MLDSA_SIG_BSTR_HEADER.len();
    signed_eat_buffer[offset..offset + 4627].copy_from_slice(sig_bytes);
    offset += 4627;

    Ok(offset)
}

// --- Mailbox command handlers ---

use crate::mutrefbytes;
use caliptra_api::mailbox::{GetAttestedEccCsrReq, GetAttestedMldsaCsrReq};
#[cfg(feature = "cfi")]
use caliptra_cfi_derive::cfi_impl_fn;
use caliptra_common::mailbox_api::{AttestedCsrResp, ResponseVarSize};
use zerocopy::FromBytes;

pub struct AttestedEccCsrCmd;

impl AttestedEccCsrCmd {
    /// Heavy phase: generates the CSR EAT claims and the RT alias ECC
    /// public key + subject key identifier. Runs in a frame that does
    /// NOT have the mailbox response buffer alive, keeping peak stack
    /// usage low.
    #[cfg_attr(feature = "cfi", cfi_impl_fn)]
    #[inline(never)]
    fn prepare(
        drivers: &mut Drivers,
        nonce: &[u8; 32],
        key_id: u32,
        env_csr_eat: &mut [u8; MAX_CSR_EAT_CLAIMS_SIZE],
    ) -> CaliptraResult<(usize, caliptra_drivers::Ecc384PubKey, [u8; 20])> {
        let csr_eat_len = if key_id == 0 {
            generate_keypair_inventory_eat_claims(nonce, env_csr_eat)?
        } else {
            let key_type = DevIdKeyType::try_from(key_id)?;
            key_type.generate_csr_eat_claims(drivers, nonce, env_csr_eat, CryptoType::ECC384)?
        };

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
    #[cfg_attr(feature = "cfi", cfi_impl_fn)]
    #[inline(never)]
    fn sign_and_finalize(
        drivers: &mut Drivers,
        csr_eat: &[u8],
        rt_subj_sn: &[u8; 20],
        rt_pub_key: &caliptra_drivers::Ecc384PubKey,
    ) -> CaliptraResult<MboxStatusE> {
        let mut resp_buf = [0u8; size_of::<AttestedCsrResp>()];
        let resp = mutrefbytes::<AttestedCsrResp>(&mut resp_buf)?;
        let signed_eat_len =
            sign_attested_ecc_csr(drivers, csr_eat, rt_subj_sn, rt_pub_key, resp.data.as_mut())?;
        resp.data_size = signed_eat_len as u32;
        let len = resp.partial_len()?;
        crate::finalize_response(drivers, &mut resp_buf, len)
    }

    #[cfg_attr(feature = "cfi", cfi_impl_fn)]
    #[inline(never)]
    pub(crate) fn execute(drivers: &mut Drivers, cmd_args: &[u8]) -> CaliptraResult<MboxStatusE> {
        let cmd = GetAttestedEccCsrReq::ref_from_bytes(cmd_args)
            .map_err(|_| CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;
        let nonce = cmd.nonce;

        let mut env_csr_eat = [0u8; MAX_CSR_EAT_CLAIMS_SIZE];

        let (csr_eat_len, rt_pub_key, rt_subj_sn) =
            Self::prepare(drivers, &nonce, cmd.key_id, &mut env_csr_eat)?;

        let csr_slice = env_csr_eat
            .get(..csr_eat_len)
            .ok_or(CaliptraError::RUNTIME_ATTESTED_CSR_EAT_ENCODING_ERROR)?;
        Self::sign_and_finalize(drivers, csr_slice, &rt_subj_sn, &rt_pub_key)
    }
}

pub struct AttestedMldsaCsrCmd;

impl AttestedMldsaCsrCmd {
    /// Heavy phase: generates the CSR EAT claims and the RT alias MLDSA
    /// public key + subject key identifier. This runs the expensive MLDSA
    /// key-pair generation (with its PCT) in a frame that does NOT have
    /// the mailbox response buffer alive, so the peak stack usage is
    /// minimized.
    #[cfg_attr(feature = "cfi", cfi_impl_fn)]
    #[inline(never)]
    fn prepare(
        drivers: &mut Drivers,
        nonce: &[u8; 32],
        key_id: u32,
        env_csr_eat: &mut [u8; MAX_CSR_EAT_CLAIMS_SIZE],
    ) -> CaliptraResult<(usize, caliptra_drivers::Mldsa87PubKey, [u8; 20])> {
        let csr_eat_len = if key_id == 0 {
            generate_keypair_inventory_eat_claims(nonce, env_csr_eat)?
        } else {
            let key_type = DevIdKeyType::try_from(key_id)?;
            key_type.generate_csr_eat_claims(drivers, nonce, env_csr_eat, CryptoType::MLDSA87)?
        };

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
    #[cfg_attr(feature = "cfi", cfi_impl_fn)]
    #[inline(never)]
    fn sign_and_finalize(
        drivers: &mut Drivers,
        csr_eat: &[u8],
        rt_subj_sn: &[u8; 20],
        rt_pub_key: &caliptra_drivers::Mldsa87PubKey,
    ) -> CaliptraResult<MboxStatusE> {
        let mut resp_buf = [0u8; size_of::<AttestedCsrResp>()];
        let resp = mutrefbytes::<AttestedCsrResp>(&mut resp_buf)?;
        let signed_eat_len =
            sign_attested_mldsa_csr(drivers, csr_eat, rt_subj_sn, rt_pub_key, resp.data.as_mut())?;
        resp.data_size = signed_eat_len as u32;
        let len = resp.partial_len()?;
        crate::finalize_response(drivers, &mut resp_buf, len)
    }

    #[cfg_attr(feature = "cfi", cfi_impl_fn)]
    #[inline(never)]
    pub(crate) fn execute(drivers: &mut Drivers, cmd_args: &[u8]) -> CaliptraResult<MboxStatusE> {
        let cmd = GetAttestedMldsaCsrReq::ref_from_bytes(cmd_args)
            .map_err(|_| CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;

        let nonce = cmd.nonce;

        let mut env_csr_eat = [0u8; MAX_CSR_EAT_CLAIMS_SIZE];

        let (csr_eat_len, rt_pub_key, rt_subj_sn) =
            Self::prepare(drivers, &nonce, cmd.key_id, &mut env_csr_eat)?;

        let csr_slice = env_csr_eat
            .get(..csr_eat_len)
            .ok_or(CaliptraError::RUNTIME_ATTESTED_CSR_EAT_ENCODING_ERROR)?;
        Self::sign_and_finalize(drivers, csr_slice, &rt_subj_sn, &rt_pub_key)
    }
}
