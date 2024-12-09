/*++

Licensed under the Apache-2.0 license.

File Name:

    dice.rs

Abstract:

    File contains mailbox commands related to DICE certificates.

--*/

use caliptra_common::mailbox_api::{
    GetFmcAliasCertResp, GetIdevCertReq, GetIdevCertResp, GetLdevCertResp, GetRtAliasCertResp,
    MailboxResp, MailboxRespHeader,
};

use crate::Drivers;

use caliptra_drivers::{
    hand_off::DataStore, CaliptraError, CaliptraResult, DataVault, Ecc384Scalar, Ecc384Signature,
    PersistentData,
};
use caliptra_x509::{Ecdsa384CertBuilder, Ecdsa384Signature};
use zerocopy::AsBytes;

pub struct IDevIdCertCmd;
impl IDevIdCertCmd {
    #[inline(never)]
    pub(crate) fn execute(cmd_args: &[u8]) -> CaliptraResult<MailboxResp> {
        if cmd_args.len() <= core::mem::size_of::<GetIdevCertReq>() {
            let mut cmd = GetIdevCertReq::default();
            cmd.as_bytes_mut()[..cmd_args.len()].copy_from_slice(cmd_args);

            // Validate tbs
            if cmd.tbs_size as usize > cmd.tbs.len() {
                return Err(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS);
            }

            let sig = Ecdsa384Signature {
                r: cmd.signature_r,
                s: cmd.signature_s,
            };

            let Some(builder) = Ecdsa384CertBuilder::new(&cmd.tbs[..cmd.tbs_size as usize], &sig) else {
                return Err(CaliptraError::RUNTIME_GET_IDEVID_CERT_FAILED);
            };

            let mut cert = [0; GetIdevCertResp::DATA_MAX_SIZE];
            let Some(cert_size) = builder.build(&mut cert) else {
                return Err(CaliptraError::RUNTIME_GET_IDEVID_CERT_FAILED);
            };

            Ok(MailboxResp::GetIdevCert(GetIdevCertResp {
                hdr: MailboxRespHeader::default(),
                cert_size: cert_size as u32,
                cert,
            }))
        } else {
            Err(CaliptraError::RUNTIME_INSUFFICIENT_MEMORY)
        }
    }
}

pub struct GetLdevCertCmd;
impl GetLdevCertCmd {
    #[inline(never)]
    pub(crate) fn execute(drivers: &mut Drivers) -> CaliptraResult<MailboxResp> {
        let mut resp = GetLdevCertResp::default();

        resp.data_size = copy_ldevid_cert(drivers.persistent_data.get(), &mut resp.data)? as u32;

        Ok(MailboxResp::GetLdevCert(resp))
    }
}

pub struct GetFmcAliasCertCmd;
impl GetFmcAliasCertCmd {
    #[inline(never)]
    pub(crate) fn execute(drivers: &mut Drivers) -> CaliptraResult<MailboxResp> {
        let mut resp = GetFmcAliasCertResp::default();

        resp.data_size = copy_fmc_alias_cert(drivers.persistent_data.get(), &mut resp.data)? as u32;

        Ok(MailboxResp::GetFmcAliasCert(resp))
    }
}

pub struct GetRtAliasCertCmd;
impl GetRtAliasCertCmd {
    #[inline(never)]
    pub(crate) fn execute(drivers: &mut Drivers) -> CaliptraResult<MailboxResp> {
        let mut resp = GetRtAliasCertResp::default();

        resp.data_size = copy_rt_alias_cert(drivers.persistent_data.get(), &mut resp.data)? as u32;

        Ok(MailboxResp::GetRtAliasCert(resp))
    }
}

/// Piece together the r and s portions of the LDevId cert signature
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
        .ldevid_tbs
        .get(..persistent_data.fht.ldevid_tbs_size.into());
    let sig = ldevid_dice_sign(persistent_data);
    cert_from_tbs_and_sig(tbs, &sig, cert)
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
pub fn copy_fmc_alias_cert(
    persistent_data: &PersistentData,
    cert: &mut [u8],
) -> CaliptraResult<usize> {
    let tbs = persistent_data
        .fmcalias_tbs
        .get(..persistent_data.fht.fmcalias_tbs_size.into());
    let sig = fmc_dice_sign(persistent_data);
    cert_from_tbs_and_sig(tbs, &sig, cert)
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
        .rtalias_tbs
        .get(..persistent_data.fht.rtalias_tbs_size.into());
    cert_from_tbs_and_sig(tbs, &persistent_data.fht.rt_dice_sign, cert)
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
fn cert_from_tbs_and_sig(
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
