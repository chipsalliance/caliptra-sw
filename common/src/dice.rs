/*++

Licensed under the Apache-2.0 license.

File Name:

    dice.rs

Abstract:

    DICE-related

--*/

use caliptra_api::mailbox::{AlgorithmType, GetLdevCertResp, MailboxRespHeader, ResponseVarSize};
use caliptra_drivers::{
    sha2_512_384::Sha2DigestOpTrait, Array4x12, CaliptraError, CaliptraResult, DataVault,
    Ecc384Signature, Mldsa87Signature, PersistentData, Sha2_512_384, SocIfc,
};
use caliptra_x509::{Ecdsa384CertBuilder, Ecdsa384Signature, MlDsa87CertBuilder};

use crate::hmac_cm::mutrefbytes;

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
    persistent_data.rom.data_vault.ldev_dice_ecc_signature()
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
    persistent_data.rom.data_vault.ldev_dice_mldsa_signature()
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
        .rom
        .ecc_ldevid_tbs
        .get(..persistent_data.rom.fht.ecc_ldevid_tbs_size.into());
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
        .rom
        .mldsa_ldevid_tbs
        .get(..persistent_data.rom.fht.mldsa_ldevid_tbs_size.into());
    let sig = ldevid_dice_mldsa87_sign(persistent_data);
    mldsa87_cert_from_tbs_and_sig(tbs, &sig, cert)
        .map_err(|_| CaliptraError::GET_LDEVID_CERT_FAILED)
}

/// Hash owner device info for FMC Alias Cert and CSR
///
/// # Arguments
///
/// * `soc_ifc` - SocIfc Driver
/// * `sha2_512_384` - Sha2 512/384 Driver
///
/// # Returns
///
/// * `[u8; 48]` - SHA384 hash of the owner device info
pub fn gen_fmc_alias_owner_device_info_hash(
    soc_ifc: &SocIfc,
    data_vault: &DataVault,
    sha2_512_384: &mut Sha2_512_384,
) -> CaliptraResult<[u8; 48]> {
    // NOTE: The contents of this TCB info and FMC PCR info must stay in sync.
    //       Ordering and grouping is irrelevant but both must contain the same info

    // Owner Public Key Hash (sha-384)
    // Owner public key Hash in fuses flag (u8) // Flag to indicate whether Owner Pub Key Hash is Fused
    // Anti-rollback disable Fuse (u8)
    // ECC Key Revoke Fuse (u8)
    // LMS Key Revoke Fuse (u32)
    // ML-DSA Key Revoke Fuse (u8)
    // Image Bundle FW min SVN Fuse - min SVN value (u8)
    // Auth Manifest SoC min SVN Fuse - min SVN value (u8)
    // Auth Manifest SoC max SVN Fuse - max SVN value (u8)

    let mut fuse_owner_info_digest = Array4x12::default();
    let mut hasher = sha2_512_384.sha384_digest_init()?;
    let owner_pub_keys_digest_in_fuses: bool =
        soc_ifc.fuse_bank().owner_pub_key_hash() != Array4x12::default();

    hasher.update(&<[u8; 48]>::from(data_vault.owner_pk_hash()))?;
    hasher.update(&[
        owner_pub_keys_digest_in_fuses as u8,
        soc_ifc.fuse_bank().anti_rollback_disable() as u8,
        soc_ifc.fuse_bank().vendor_ecc_pub_key_revocation().bits() as u8,
    ])?;
    hasher.update(
        &soc_ifc
            .fuse_bank()
            .vendor_lms_pub_key_revocation()
            .to_le_bytes(),
    )?;
    hasher.update(&[
        soc_ifc.fuse_bank().vendor_mldsa_pub_key_revocation() as u8,
        soc_ifc.fuse_bank().fw_fuse_svn() as u8,
        soc_ifc.fuse_bank().soc_manifest_fuse_svn() as u8,
        soc_ifc.fuse_bank().max_soc_manifest_fuse_svn() as u8,
    ])?;
    hasher.finalize(&mut fuse_owner_info_digest)?;

    Ok(fuse_owner_info_digest.into())
}

/// Hash vendor device info for FMC Alias Cert and CSR
///
/// # Arguments
///
/// * `soc_ifc` - SocIfc Driver
/// * `sha2_512_384` - Sha2 512/384 Driver
///
/// # Returns
///
/// * `[u8; 48]` - SHA384 hash of the vendor device info
pub fn gen_fmc_alias_vendor_device_info_hash(
    soc_ifc: &SocIfc,
    data_vault: &DataVault,
    sha2_512_384: &mut Sha2_512_384,
) -> CaliptraResult<[u8; 48]> {
    // NOTE: The contents of this TCB info and FMC PCR info must stay in sync.
    //       Ordering and grouping is irrelevant but both must contain the same info

    // Vendor Public Key Hash Fuse (sha-384)
    // PQC Type Fuse (u8)
    // Lifecycle State (u8)
    // Debug Locked (u8)
    // Image Bundle FW SVN from cold boot (u8)
    // PK Index ECC (u8)
    // PK Index PQC (u8)
    let mut fuse_vendor_info_digest = Array4x12::default();
    let mut hasher = sha2_512_384.sha384_digest_init()?;

    hasher.update(&<[u8; 48]>::from(
        soc_ifc.fuse_bank().vendor_pub_key_info_hash(),
    ))?;
    hasher.update(&[
        soc_ifc.fuse_bank().pqc_key_type() as u8,
        soc_ifc.lifecycle() as u8,
        soc_ifc.debug_locked() as u8,
        data_vault.cold_boot_fw_svn() as u8,
        data_vault.vendor_ecc_pk_index() as u8,
        data_vault.vendor_pqc_pk_index() as u8,
    ])?;
    hasher.finalize(&mut fuse_vendor_info_digest)?;

    Ok(fuse_vendor_info_digest.into())
}
