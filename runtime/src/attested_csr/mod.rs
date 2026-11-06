// Licensed under the Apache-2.0 license

use crate::Drivers;
use caliptra_common::x509;
use caliptra_drivers::sha2_512_384::Sha2DigestOpTrait;
use caliptra_drivers::{
    Array4x12, Ecc384Scalar, Ecc384Signature, KeyReadArgs, Mldsa87Seed, Mldsa87SignRnd,
};
use caliptra_error::{CaliptraError, CaliptraResult};
use caliptra_x509::MlDsa87Signature;
use core::mem::size_of;
use zerocopy::IntoBytes;

mod fmc_alias;
mod ldevid;
mod rt_alias;

use fmc_alias::{generate_fmc_alias_ecc_csr, generate_fmc_alias_mldsa_csr};
use ldevid::{generate_ldevid_ecc_csr, generate_ldevid_mldsa_csr};
use rt_alias::{generate_rt_alias_ecc_csr, generate_rt_alias_mldsa_csr};

include!(concat!(env!("OUT_DIR"), "/attested_csr_template.rs"));

const KEY_ID_LEN: usize = 20;
const ECC384_COORD_LEN: usize = size_of::<Ecc384Scalar>();
const ECC384_SIG_LEN: usize = size_of::<Ecc384Signature>();
const MLDSA87_SIG_LEN: usize = size_of::<MlDsa87Signature>();

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

fn encode_cbor_bstr_deferred<F>(buf: &mut [u8], f: F) -> CaliptraResult<usize>
where
    F: FnOnce(&mut [u8]) -> CaliptraResult<usize>,
{
    caliptra_ocp_eat::encode_bstr_deferred(buf, |_| CaliptraError::RUNTIME_INSUFFICIENT_MEMORY, f)
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
        if eat_buffer.len() < prefix_len {
            return Err(CaliptraError::RUNTIME_INSUFFICIENT_MEMORY);
        }

        // Write prefix before CSR
        eat_buffer[..CSR_EAT_PREFIX.len()].copy_from_slice(&CSR_EAT_PREFIX);
        let mut offset = CSR_EAT_PREFIX.len();
        eat_buffer[offset..offset + nonce.len()].copy_from_slice(nonce);
        offset += nonce.len();
        eat_buffer[offset..offset + CSR_EAT_CLAIM_KEY_CSR.len()]
            .copy_from_slice(&CSR_EAT_CLAIM_KEY_CSR);
        offset += CSR_EAT_CLAIM_KEY_CSR.len();

        // Encode CSR as a CBOR byte string
        let csr_bstr_len = encode_cbor_bstr_deferred(&mut eat_buffer[offset..], |csr_buf| {
            self.generate_csr(drivers, crypto, csr_buf)
        })?;

        let csr_end = offset + csr_bstr_len;
        let total_len = csr_end + suffix.len();
        let suffix_dest = eat_buffer
            .get_mut(csr_end..total_len)
            .ok_or(CaliptraError::RUNTIME_INSUFFICIENT_MEMORY)?;
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

fn generate_eat_payload(
    drivers: &mut Drivers,
    key_id: u32,
    nonce: &[u8; 32],
    crypto: CryptoType,
    eat_buffer: &mut [u8],
) -> CaliptraResult<usize> {
    if key_id == 0 {
        generate_keypair_inventory_eat_claims(nonce, eat_buffer)
    } else {
        let key_type = DevIdKeyType::try_from(key_id)?;
        key_type.generate_csr_eat_claims(drivers, nonce, eat_buffer, crypto)
    }
}

#[inline(never)]
fn sign_attested_ecc_csr(
    drivers: &mut Drivers,
    payload_bstr_len: usize,
    signed_eat_buffer: &mut [u8],
) -> CaliptraResult<usize> {
    let cose_prefix_len = COSE_PREAMBLE_ECC_BEFORE_KID.len()
        + KEY_ID_LEN
        + COSE_ECC_AFTER_KID_BEFORE_PAYLOAD_LEN.len();
    let payload_end = cose_prefix_len
        .checked_add(payload_bstr_len)
        .ok_or(CaliptraError::RUNTIME_INSUFFICIENT_MEMORY)?;
    let total_len = payload_end
        .checked_add(COSE_ECC_SIG_BSTR_HEADER.len() + ECC384_SIG_LEN)
        .ok_or(CaliptraError::RUNTIME_INSUFFICIENT_MEMORY)?;
    if signed_eat_buffer.len() < total_len {
        return Err(CaliptraError::RUNTIME_INSUFFICIENT_MEMORY);
    }

    // Compute RT Alias subject key identifier for COSE header kid
    let rt_pub_key = drivers.persistent_data.get().rom.fht.rt_dice_ecc_pub_key;
    let rt_key_id = x509::subj_key_id(
        &mut drivers.sha256,
        &caliptra_common::crypto::PubKey::Ecc(&rt_pub_key),
    )?;

    // Hash Sig_structure with SHA384
    let mut op = drivers.sha2_512_384.sha384_digest_init()?;
    op.update(&SIG_PREAMBLE_ECC_BEFORE_KID)?;
    op.update(&rt_key_id)?;
    op.update(&SIG_ECC_AFTER_KID_BEFORE_PAYLOAD_LEN)?;
    op.update(&signed_eat_buffer[cose_prefix_len..payload_end])?;
    let mut digest = Array4x12::default();
    op.finalize(&mut digest)?;

    // Get RT Alias private key and sign digest
    let key_id_rt_priv_key = Drivers::get_key_id_rt_ecc_priv_key(drivers)?;
    let priv_key_args = KeyReadArgs::new(key_id_rt_priv_key);
    let priv_key = caliptra_drivers::Ecc384PrivKeyIn::Key(priv_key_args);
    let signature = drivers
        .ecc384
        .sign(priv_key, &rt_pub_key, &digest, &mut drivers.trng)?;

    // Write COSE Sign1 prefix
    let mut offset = 0;
    signed_eat_buffer[offset..offset + COSE_PREAMBLE_ECC_BEFORE_KID.len()]
        .copy_from_slice(&COSE_PREAMBLE_ECC_BEFORE_KID);
    offset += COSE_PREAMBLE_ECC_BEFORE_KID.len();
    signed_eat_buffer[offset..offset + KEY_ID_LEN].copy_from_slice(&rt_key_id);
    offset += KEY_ID_LEN;
    signed_eat_buffer[offset..offset + COSE_ECC_AFTER_KID_BEFORE_PAYLOAD_LEN.len()]
        .copy_from_slice(&COSE_ECC_AFTER_KID_BEFORE_PAYLOAD_LEN);

    // Append COSE Sign1 signature
    let mut offset = payload_end;
    signed_eat_buffer
        .get_mut(offset..offset + COSE_ECC_SIG_BSTR_HEADER.len())
        .ok_or(CaliptraError::RUNTIME_INSUFFICIENT_MEMORY)?
        .copy_from_slice(&COSE_ECC_SIG_BSTR_HEADER);
    offset += COSE_ECC_SIG_BSTR_HEADER.len();
    let r_bytes: [u8; ECC384_COORD_LEN] = signature.r.into();
    let s_bytes: [u8; ECC384_COORD_LEN] = signature.s.into();
    signed_eat_buffer
        .get_mut(offset..offset + ECC384_COORD_LEN)
        .ok_or(CaliptraError::RUNTIME_INSUFFICIENT_MEMORY)?
        .copy_from_slice(&r_bytes);
    offset += ECC384_COORD_LEN;
    signed_eat_buffer
        .get_mut(offset..offset + ECC384_COORD_LEN)
        .ok_or(CaliptraError::RUNTIME_INSUFFICIENT_MEMORY)?
        .copy_from_slice(&s_bytes);
    offset += ECC384_COORD_LEN;

    Ok(offset)
}

#[inline(never)]
fn sign_attested_mldsa_csr(
    drivers: &mut Drivers,
    payload_bstr_len: usize,
    signed_eat_buffer: &mut [u8],
) -> CaliptraResult<usize> {
    let sig_prefix_len = SIG_PREAMBLE_MLDSA_BEFORE_KID.len()
        + KEY_ID_LEN
        + SIG_MLDSA_AFTER_KID_BEFORE_PAYLOAD_LEN.len();
    let cose_prefix_len = COSE_PREAMBLE_MLDSA_BEFORE_KID.len()
        + KEY_ID_LEN
        + COSE_MLDSA_AFTER_KID_BEFORE_PAYLOAD_LEN.len();

    let sig_ctx_len = sig_prefix_len
        .checked_add(payload_bstr_len)
        .ok_or(CaliptraError::RUNTIME_INSUFFICIENT_MEMORY)?;
    let payload_cose_end = cose_prefix_len
        .checked_add(payload_bstr_len)
        .ok_or(CaliptraError::RUNTIME_INSUFFICIENT_MEMORY)?;
    let total_len = payload_cose_end
        .checked_add(COSE_MLDSA_SIG_BSTR_HEADER.len() + MLDSA87_SIG_LEN)
        .ok_or(CaliptraError::RUNTIME_INSUFFICIENT_MEMORY)?;

    if signed_eat_buffer.len() < sig_ctx_len || signed_eat_buffer.len() < total_len {
        return Err(CaliptraError::RUNTIME_INSUFFICIENT_MEMORY);
    }

    // Compute RT Alias public key and subject key identifier for COSE header kid
    let rt_pub_key = Drivers::get_key_id_rt_mldsa_pub_key(drivers)?;
    let rt_key_id = x509::subj_key_id(
        &mut drivers.sha256,
        &caliptra_common::crypto::PubKey::Mldsa(&rt_pub_key),
    )?;

    // Write Sig_structure prefix (pure ML-DSA-87 per RFC 9964)
    let mut offset = 0;
    signed_eat_buffer[offset..offset + SIG_PREAMBLE_MLDSA_BEFORE_KID.len()]
        .copy_from_slice(&SIG_PREAMBLE_MLDSA_BEFORE_KID);
    offset += SIG_PREAMBLE_MLDSA_BEFORE_KID.len();
    signed_eat_buffer[offset..offset + KEY_ID_LEN].copy_from_slice(&rt_key_id);
    offset += KEY_ID_LEN;
    signed_eat_buffer[offset..offset + SIG_MLDSA_AFTER_KID_BEFORE_PAYLOAD_LEN.len()]
        .copy_from_slice(&SIG_MLDSA_AFTER_KID_BEFORE_PAYLOAD_LEN);

    let rt_seed = Drivers::get_key_id_rt_mldsa_keypair_seed(drivers)?;
    let key_args = KeyReadArgs::new(rt_seed);

    let mut mldsa87 = caliptra_drivers::Mldsa87::new(drivers.abr.abr_reg());
    let signature = mldsa87.sign_var(
        Mldsa87Seed::Key(key_args),
        &rt_pub_key,
        &signed_eat_buffer[..sig_ctx_len],
        &Mldsa87SignRnd::default(),
        &mut drivers.trng,
    )?;

    // Assemble final COSE Sign1 envelope in place into signed_eat_buffer
    let sig_bytes = signature
        .as_bytes()
        .get(..MLDSA87_SIG_LEN)
        .ok_or(CaliptraError::RUNTIME_INTERNAL)?;

    // Shift payload bstr from Sig_structure offset to COSE_Sign1 offset and write COSE prefix + signature
    for i in 0..payload_bstr_len {
        if let (Some(b), Some(dst)) = (
            signed_eat_buffer.get(sig_prefix_len + i).copied(),
            signed_eat_buffer.get_mut(cose_prefix_len + i),
        ) {
            *dst = b;
        }
    }

    let mut offset = 0;
    signed_eat_buffer[offset..offset + COSE_PREAMBLE_MLDSA_BEFORE_KID.len()]
        .copy_from_slice(&COSE_PREAMBLE_MLDSA_BEFORE_KID);
    offset += COSE_PREAMBLE_MLDSA_BEFORE_KID.len();
    signed_eat_buffer[offset..offset + KEY_ID_LEN].copy_from_slice(&rt_key_id);
    offset += KEY_ID_LEN;
    signed_eat_buffer[offset..offset + COSE_MLDSA_AFTER_KID_BEFORE_PAYLOAD_LEN.len()]
        .copy_from_slice(&COSE_MLDSA_AFTER_KID_BEFORE_PAYLOAD_LEN);

    let mut offset = payload_cose_end;
    signed_eat_buffer
        .get_mut(offset..offset + COSE_MLDSA_SIG_BSTR_HEADER.len())
        .ok_or(CaliptraError::RUNTIME_INSUFFICIENT_MEMORY)?
        .copy_from_slice(&COSE_MLDSA_SIG_BSTR_HEADER);
    offset += COSE_MLDSA_SIG_BSTR_HEADER.len();
    signed_eat_buffer
        .get_mut(offset..offset + MLDSA87_SIG_LEN)
        .ok_or(CaliptraError::RUNTIME_INSUFFICIENT_MEMORY)?
        .copy_from_slice(sig_bytes);
    offset += MLDSA87_SIG_LEN;

    Ok(offset)
}

// --- Mailbox command handlers ---

use crate::mutrefbytes;
use caliptra_api::mailbox::{GetAttestedEccCsrReq, GetAttestedMldsaCsrReq};
use caliptra_cfi_derive::cfi_impl_fn;
use caliptra_common::mailbox_api::{AttestedCsrResp, ResponseVarSize};
use zerocopy::FromBytes;

pub struct AttestedEccCsrCmd;

impl AttestedEccCsrCmd {
    #[cfg_attr(feature = "cfi", cfi_impl_fn)]
    #[inline(never)]
    pub(crate) fn execute(
        drivers: &mut Drivers,
        cmd_args: &[u8],
        mbox_resp: &mut [u8],
    ) -> CaliptraResult<usize> {
        let cmd = GetAttestedEccCsrReq::ref_from_bytes(cmd_args)
            .map_err(|_| CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;
        let key_id = cmd.key_id;
        let nonce = cmd.nonce;

        let resp = mutrefbytes::<AttestedCsrResp>(mbox_resp)?;
        let signed_eat_buffer = resp.data.as_mut();
        let cose_prefix_len = COSE_PREAMBLE_ECC_BEFORE_KID.len()
            + KEY_ID_LEN
            + COSE_ECC_AFTER_KID_BEFORE_PAYLOAD_LEN.len();
        let payload_buf = signed_eat_buffer
            .get_mut(cose_prefix_len..)
            .ok_or(CaliptraError::RUNTIME_INSUFFICIENT_MEMORY)?;

        let payload_bstr_len = encode_cbor_bstr_deferred(payload_buf, |buf| {
            generate_eat_payload(drivers, key_id, &nonce, CryptoType::ECC384, buf)
        })?;
        let signed_eat_len = sign_attested_ecc_csr(drivers, payload_bstr_len, signed_eat_buffer)?;

        resp.data_size = signed_eat_len as u32;
        resp.partial_len()
    }
}

pub struct AttestedMldsaCsrCmd;

impl AttestedMldsaCsrCmd {
    #[cfg_attr(feature = "cfi", cfi_impl_fn)]
    #[inline(never)]
    pub(crate) fn execute(
        drivers: &mut Drivers,
        cmd_args: &[u8],
        mbox_resp: &mut [u8],
    ) -> CaliptraResult<usize> {
        let cmd = GetAttestedMldsaCsrReq::ref_from_bytes(cmd_args)
            .map_err(|_| CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;
        let key_id = cmd.key_id;
        let nonce = cmd.nonce;

        let resp = mutrefbytes::<AttestedCsrResp>(mbox_resp)?;
        let signed_eat_buffer = resp.data.as_mut();
        let sig_prefix_len = SIG_PREAMBLE_MLDSA_BEFORE_KID.len()
            + KEY_ID_LEN
            + SIG_MLDSA_AFTER_KID_BEFORE_PAYLOAD_LEN.len();
        let payload_buf = signed_eat_buffer
            .get_mut(sig_prefix_len..)
            .ok_or(CaliptraError::RUNTIME_INSUFFICIENT_MEMORY)?;

        let payload_bstr_len = encode_cbor_bstr_deferred(payload_buf, |buf| {
            generate_eat_payload(drivers, key_id, &nonce, CryptoType::MLDSA87, buf)
        })?;
        let signed_eat_len = sign_attested_mldsa_csr(drivers, payload_bstr_len, signed_eat_buffer)?;

        resp.data_size = signed_eat_len as u32;
        resp.partial_len()
    }
}
