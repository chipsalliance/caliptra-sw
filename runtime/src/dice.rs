/*++

Licensed under the Apache-2.0 license.

File Name:

    dice.rs

Abstract:

    File contains mailbox commands related to DICE certificates.

--*/

use caliptra_common::mailbox_api::{
    AlgorithmType, GetFmcAliasEcc384CertResp, GetFmcAliasMlDsa87CertResp, GetIdevCertResp,
    GetIdevEcc384CertReq, GetLdevCertResp, GetRtAliasCertResp, MailboxResp, MailboxRespHeader,
};

use crate::Drivers;

use caliptra_drivers::{
    CaliptraError, CaliptraResult, Ecc384Signature, Mldsa87Signature, PersistentData,
};
use caliptra_x509::{Ecdsa384CertBuilder, Ecdsa384Signature, MlDsa87CertBuilder};
use zerocopy::IntoBytes;

pub struct IDevIdCertCmd;
impl IDevIdCertCmd {
    #[inline(never)]
    pub(crate) fn execute(cmd_args: &[u8], alg_type: AlgorithmType) -> CaliptraResult<MailboxResp> {
        match alg_type {
            AlgorithmType::Ecc384 => {
                if cmd_args.len() <= core::mem::size_of::<GetIdevEcc384CertReq>() {
                    let mut cmd = GetIdevEcc384CertReq::default();
                    cmd.as_mut_bytes()[..cmd_args.len()].copy_from_slice(cmd_args);

                    // Validate tbs
                    if cmd.tbs_size as usize > cmd.tbs.len() {
                        return Err(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS);
                    }

                    let sig = Ecdsa384Signature {
                        r: cmd.signature_r,
                        s: cmd.signature_s,
                    };

                    let Some(builder) =
                        Ecdsa384CertBuilder::new(&cmd.tbs[..cmd.tbs_size as usize], &sig)
                    else {
                        return Err(CaliptraError::RUNTIME_GET_IDEVID_CERT_FAILED);
                    };

                    let mut cert = [0; GetIdevCertResp::DATA_MAX_SIZE];
                    let Some(cert_size) = builder.build(&mut cert) else {
                        return Err(CaliptraError::RUNTIME_GET_IDEVID_CERT_FAILED);
                    };

                    Ok(MailboxResp::GetIdevCert(GetIdevCertResp {
                        hdr: MailboxRespHeader::default(),
                        data_size: cert_size as u32,
                        data: cert,
                    }))
                } else {
                    Err(CaliptraError::RUNTIME_INSUFFICIENT_MEMORY)
                }
            }
            AlgorithmType::Mldsa87 => {
                // MLDSA87 implementation would go here
                // This is just a placeholder - actual implementation would depend on MLDSA87 specifics
                Err(CaliptraError::RUNTIME_UNIMPLEMENTED_COMMAND)
            }
        }
    }
}

pub struct GetLdevCertCmd;
impl GetLdevCertCmd {
    #[inline(never)]
    pub(crate) fn execute(
        drivers: &mut Drivers,
        alg_type: AlgorithmType,
    ) -> CaliptraResult<MailboxResp> {
        match alg_type {
            AlgorithmType::Ecc384 => {
                let mut resp = GetLdevCertResp::default();
                resp.data_size =
                    copy_ldevid_cert(drivers.persistent_data.get(), &mut resp.data)? as u32;
                Ok(MailboxResp::GetLdevCert(resp))
            }
            AlgorithmType::Mldsa87 => {
                let mut resp = GetLdevCertResp::default();
                resp.data_size =
                    copy_ldevid_mldsa87_cert(drivers.persistent_data.get(), &mut resp.data)? as u32;
                Ok(MailboxResp::GetLdevCert(resp))
            }
        }
    }
}

pub struct GetFmcAliasCertCmd;
impl GetFmcAliasCertCmd {
    #[inline(never)]
    pub(crate) fn execute(
        drivers: &mut Drivers,
        alg_type: AlgorithmType,
    ) -> CaliptraResult<MailboxResp> {
        match alg_type {
            AlgorithmType::Ecc384 => {
                let mut resp = GetFmcAliasEcc384CertResp::default();
                resp.data_size =
                    copy_fmc_alias_ecc384_cert(drivers.persistent_data.get(), &mut resp.data)?
                        as u32;
                Ok(MailboxResp::GetFmcAliasEcc384Cert(resp))
            }
            AlgorithmType::Mldsa87 => {
                let mut resp = GetFmcAliasMlDsa87CertResp::default();
                resp.data_size =
                    copy_fmc_alias_mldsa87_cert(drivers.persistent_data.get(), &mut resp.data)?
                        as u32;
                Ok(MailboxResp::GetFmcAliasMlDsa87Cert(resp))
            }
        }
    }
}

pub struct GetRtAliasCertCmd;
impl GetRtAliasCertCmd {
    #[inline(never)]
    pub(crate) fn execute(
        drivers: &mut Drivers,
        alg_type: AlgorithmType,
    ) -> CaliptraResult<MailboxResp> {
        match alg_type {
            AlgorithmType::Ecc384 => {
                let mut resp = GetRtAliasCertResp::default();
                resp.data_size =
                    copy_rt_alias_cert(drivers.persistent_data.get(), &mut resp.data)? as u32;
                Ok(MailboxResp::GetRtAliasCert(resp))
            }
            AlgorithmType::Mldsa87 => {
                // MLDSA87 implementation would go here
                // This is just a placeholder - actual implementation would depend on MLDSA87 specifics
                Err(CaliptraError::RUNTIME_UNIMPLEMENTED_COMMAND)
            }
        }
    }
}

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

/// Copy LDevID certificate produced by ROM to `cert` buffer
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
pub fn copy_ldevid_cert(
    persistent_data: &PersistentData,
    cert: &mut [u8],
) -> CaliptraResult<usize> {
    let tbs = persistent_data
        .ecc_ldevid_tbs
        .get(..persistent_data.fht.ecc_ldevid_tbs_size.into());
    let sig = ldevid_dice_sign(persistent_data);
    ecc384_cert_from_tbs_and_sig(tbs, &sig, cert)
        .map_err(|_| CaliptraError::RUNTIME_GET_LDEVID_CERT_FAILED)
}

/// Copy LDevID certificate produced by ROM to `cert` buffer
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
        .map_err(|_| CaliptraError::RUNTIME_GET_LDEVID_CERT_FAILED)
}

/// Piece together the r and s portions of the FMC alias cert signature
///
/// # Arguments
///
/// * `persistent_data` - PersistentData
///
/// # Returns
///
/// * `Ecc384Signature` - The formed signature
pub fn fmc_dice_sign(persistent_data: &PersistentData) -> Ecc384Signature {
    persistent_data.data_vault.fmc_dice_ecc_signature()
}

/// Retrieve the MLDSA87 signature for the FMC alias cert
///
/// # Arguments
///
/// * `persistent_data` - PersistentData
///
/// # Returns
///
/// * `Mldsa87Signature` - The formed signature
pub fn fmc_dice_sign_mldsa87(persistent_data: &PersistentData) -> Mldsa87Signature {
    persistent_data.data_vault.fmc_dice_mldsa_signature()
}

/// Copy FMC alias certificate produced by ROM to `cert` buffer
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
pub fn copy_fmc_alias_ecc384_cert(
    persistent_data: &PersistentData,
    cert: &mut [u8],
) -> CaliptraResult<usize> {
    let tbs = persistent_data
        .ecc_fmcalias_tbs
        .get(..persistent_data.fht.ecc_fmcalias_tbs_size.into());
    let sig = fmc_dice_sign(persistent_data);
    ecc384_cert_from_tbs_and_sig(tbs, &sig, cert)
        .map_err(|_| CaliptraError::RUNTIME_GET_FMC_ALIAS_CERT_FAILED)
}

/// Copy FMC alias MLDSA87 certificate produced by ROM to `cert` buffer
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
pub fn copy_fmc_alias_mldsa87_cert(
    persistent_data: &PersistentData,
    cert: &mut [u8],
) -> CaliptraResult<usize> {
    let tbs = persistent_data
        .mldsa_fmcalias_tbs
        .get(..persistent_data.fht.mldsa_fmcalias_tbs_size.into());
    let sig = fmc_dice_sign_mldsa87(persistent_data);
    mldsa87_cert_from_tbs_and_sig(tbs, &sig, cert)
        .map_err(|_| CaliptraError::RUNTIME_GET_FMC_ALIAS_CERT_FAILED)
}

/// Copy RT Alias certificate produced by FMC to `cert` buffer
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
pub fn copy_rt_alias_cert(
    persistent_data: &PersistentData,
    cert: &mut [u8],
) -> CaliptraResult<usize> {
    let tbs = persistent_data
        .ecc_rtalias_tbs
        .get(..persistent_data.fht.rtalias_tbs_size.into());
    ecc384_cert_from_tbs_and_sig(tbs, &persistent_data.fht.rt_dice_sign, cert)
        .map_err(|_| CaliptraError::RUNTIME_GET_RT_ALIAS_CERT_FAILED)
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
///
/// * `usize` - The number of bytes written to `cert`
fn ecc384_cert_from_tbs_and_sig(
    tbs: Option<&[u8]>,
    sig: &Ecc384Signature,
    cert: &mut [u8],
) -> CaliptraResult<usize> {
    let Some(tbs) = tbs else {
        return Err(CaliptraError::RUNTIME_INTERNAL);
    };

    // Convert from Ecc384Signature to Ecdsa384Signature
    let bldr_sig = Ecdsa384Signature {
        r: sig.r.into(),
        s: sig.s.into(),
    };
    let Some(builder) = Ecdsa384CertBuilder::new(tbs, &bldr_sig) else {
        return Err(CaliptraError::RUNTIME_INTERNAL);
    };

    let Some(size) = builder.build(cert) else {
        return Err(CaliptraError::RUNTIME_INTERNAL);
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
///
/// * `usize` - The number of bytes written to `cert`
fn mldsa87_cert_from_tbs_and_sig(
    tbs: Option<&[u8]>,
    sig: &Mldsa87Signature,
    cert: &mut [u8],
) -> CaliptraResult<usize> {
    let Some(tbs) = tbs else {
        return Err(CaliptraError::RUNTIME_INTERNAL);
    };

    let sig_bytes = <[u8; 4628]>::from(sig)[..4627].try_into().unwrap();
    let signature = caliptra_x509::Mldsa87Signature { sig: sig_bytes };

    let Some(builder) = MlDsa87CertBuilder::new(tbs, &signature) else {
        return Err(CaliptraError::RUNTIME_INTERNAL);
    };

    let Some(size) = builder.build(cert) else {
        return Err(CaliptraError::RUNTIME_INTERNAL);
    };

    Ok(size)
}
