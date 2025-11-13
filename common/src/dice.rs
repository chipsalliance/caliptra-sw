/*++

Licensed under the Apache-2.0 license.

File Name:

    dice.rs

Abstract:

    DICE-related

--*/

use caliptra_api::mailbox::{AlgorithmType, GetLdevCertResp, MailboxRespHeader, ResponseVarSize};
use caliptra_drivers::{
    CaliptraError, CaliptraResult, Ecc384Signature, Lifecycle, Mldsa87Signature, PersistentData,
};
use caliptra_x509::{Ecdsa384CertBuilder, Ecdsa384Signature, MlDsa87CertBuilder};

use crate::hmac_cm::mutrefbytes;

pub const FLAG_BIT_NOT_CONFIGURED: u32 = 1 << 0;
pub const FLAG_BIT_NOT_SECURE: u32 = 1 << 1;
pub const FLAG_BIT_DEBUG: u32 = 1 << 3;
pub const FLAG_BIT_FIXED_WIDTH: u32 = 1 << 31;

/// Return the LDevId ECC cert signature
///
/// # Arguments
///
/// * `persistent_data` - PersistentData
///
/// # Returns
///
/// * `Ecc384Signature` - The formed signature
pub fn ldevid_dice_sign(persistent_data: &PersistentData) -> Ecc384Signature {
    persistent_data.data_vault.ldev_dice_ecc_signature()
}

/// Return the LDevId MLDSA87 cert signature
///
/// # Arguments
///
/// * `persistent_data` - PersistentData
///
/// # Returns
///
/// * `Mldsa87Signature` - The formed signature
pub fn ldevid_dice_mldsa87_sign(persistent_data: &PersistentData) -> Mldsa87Signature {
    persistent_data.data_vault.ldev_dice_mldsa_signature()
}

pub struct GetLdevCertCmd;
impl GetLdevCertCmd {
    #[inline(never)]
    pub fn execute(
        persistent_data: &PersistentData,
        alg_type: AlgorithmType,
        resp: &mut [u8],
    ) -> CaliptraResult<usize> {
        let resp = mutrefbytes::<GetLdevCertResp>(resp)?;
        resp.hdr = MailboxRespHeader::default();

        match alg_type {
            AlgorithmType::Ecc384 => {
                resp.data_size = copy_ldevid_ecc384_cert(persistent_data, &mut resp.data)? as u32;
            }
            AlgorithmType::Mldsa87 => {
                resp.data_size = copy_ldevid_mldsa87_cert(persistent_data, &mut resp.data)? as u32;
            }
        }
        resp.partial_len()
    }
}

/// Create a certificate from a tbs and a signature and write the output to `cert`
///
/// # Arguments
///
/// * `tbs` - ToBeSigned portion
/// * `sig` - Ecc384Signature
/// * `cert` - Buffer to copy LDevID certificate to
///
/// # Returns
/// * `usize` - The number of bytes written to `cert`
pub fn ecc384_cert_from_tbs_and_sig(
    tbs: Option<&[u8]>,
    sig: &Ecc384Signature,
    cert: &mut [u8],
) -> CaliptraResult<usize> {
    let Some(tbs) = tbs else {
        return Err(CaliptraError::CALIPTRA_INTERNAL);
    };

    // Convert from Ecc384Signature to Ecdsa384Signature
    let bldr_sig = Ecdsa384Signature {
        r: sig.r.into(),
        s: sig.s.into(),
    };
    let Some(builder) = Ecdsa384CertBuilder::new(tbs, &bldr_sig) else {
        return Err(CaliptraError::CALIPTRA_INTERNAL);
    };

    let Some(size) = builder.build(cert) else {
        return Err(CaliptraError::CALIPTRA_INTERNAL);
    };

    Ok(size)
}

/// Create a certificate from a tbs and a signature and write the output to `cert`
///
/// # Arguments
///
/// * `tbs` - ToBeSigned portion
/// * `sig` - MlDsa87Signature
/// * `cert` - Buffer to copy LDevID certificate to
///
/// # Returns
/// * `usize` - The number of bytes written to `cert`
pub fn mldsa87_cert_from_tbs_and_sig(
    tbs: Option<&[u8]>,
    sig: &Mldsa87Signature,
    cert: &mut [u8],
) -> CaliptraResult<usize> {
    let Some(tbs) = tbs else {
        return Err(CaliptraError::CALIPTRA_INTERNAL);
    };

    let sig_bytes = <[u8; 4628]>::from(sig)[..4627].try_into().unwrap();
    let signature = caliptra_x509::MlDsa87Signature { sig: sig_bytes };

    let Some(builder) = MlDsa87CertBuilder::new(tbs, &signature) else {
        return Err(CaliptraError::CALIPTRA_INTERNAL);
    };

    let Some(size) = builder.build(cert) else {
        return Err(CaliptraError::CALIPTRA_INTERNAL);
    };

    Ok(size)
}

/// Copy ECC LDevID certificate produced by ROM to `cert` buffer
///
/// # Arguments
///
/// * `persistent_data` - PersistentData
/// * `cert` - Buffer to copy LDevID certificate to
///
/// # Returns
///
/// * `usize` - The number of bytes written to `cert`
#[inline(never)]
pub fn copy_ldevid_ecc384_cert(
    persistent_data: &PersistentData,
    cert: &mut [u8],
) -> CaliptraResult<usize> {
    let tbs = persistent_data
        .ecc_ldevid_tbs
        .get(..persistent_data.fht.ecc_ldevid_tbs_size.into());
    let sig = ldevid_dice_sign(persistent_data);
    ecc384_cert_from_tbs_and_sig(tbs, &sig, cert).map_err(|_| CaliptraError::GET_LDEVID_CERT_FAILED)
}

/// Copy MLDSA LDevID certificate produced by ROM to `cert` buffer
///
/// # Arguments
///
/// * `persistent_data` - PersistentData
/// * `cert` - Buffer to copy LDevID certificate to
///
/// # Returns
///
/// * `usize` - The number of bytes written to `cert`
#[inline(never)]
pub fn copy_ldevid_mldsa87_cert(
    persistent_data: &PersistentData,
    cert: &mut [u8],
) -> CaliptraResult<usize> {
    let tbs = persistent_data
        .mldsa_ldevid_tbs
        .get(..persistent_data.fht.mldsa_ldevid_tbs_size.into());
    let sig = ldevid_dice_mldsa87_sign(persistent_data);
    mldsa87_cert_from_tbs_and_sig(tbs, &sig, cert)
        .map_err(|_| CaliptraError::GET_LDEVID_CERT_FAILED)
}

/// Generate flags for DICE evidence
///
/// # Arguments
///
/// * `device_lifecycle` - Device lifecycle
/// * `debug_locked`     - Debug locked
pub fn make_flags(device_lifecycle: Lifecycle, debug_locked: bool) -> [u8; 4] {
    let mut flags: u32 = FLAG_BIT_FIXED_WIDTH;

    flags |= match device_lifecycle {
        Lifecycle::Unprovisioned => FLAG_BIT_NOT_CONFIGURED,
        Lifecycle::Manufacturing => FLAG_BIT_NOT_SECURE,
        _ => 0,
    };

    if !debug_locked {
        flags |= FLAG_BIT_DEBUG;
    }

    flags.reverse_bits().to_be_bytes()
}
