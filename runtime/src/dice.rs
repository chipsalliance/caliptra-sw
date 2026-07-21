/*++

Licensed under the Apache-2.0 license.

File Name:

    dice.rs

Abstract:

    File contains mailbox commands related to DICE certificates.

--*/

use caliptra_common::mailbox_api::{
    GetFmcAliasCertResp, GetIdevCertReq, GetIdevCertResp, GetLdevCertResp, GetRtAliasCertResp,
};
#[cfg(feature = "mldsa_attestation")]
use caliptra_common::mailbox_api::{GetPqCertReq, GetPqCertResp};

use crate::Drivers;

#[cfg(feature = "mldsa_attestation")]
use caliptra_drivers::Mldsa87Signature;
use caliptra_drivers::{
    hand_off::DataStore, CaliptraError, CaliptraResult, DataVault, Ecc384Scalar, Ecc384Signature,
    PersistentData,
};
#[cfg(feature = "mldsa_attestation")]
use caliptra_x509::MlDsa87CertBuilder;
use caliptra_x509::{Ecdsa384CertBuilder, Ecdsa384Signature};
use zerocopy::{FromZeros, IntoBytes};
#[cfg(feature = "mldsa_attestation")]
use {
    caliptra_drivers::{
        hmac384_kdf, Array4x12, Hmac384, Mldsa87Seed, Trng, MLDSA87_PRIVATE_SEED_BYTES,
    },
    zeroize::Zeroizing,
};

pub struct IDevIdCertCmd;
impl IDevIdCertCmd {
    #[inline(never)]
    pub(crate) fn execute(drivers: &mut Drivers) -> CaliptraResult<()> {
        let mut cmd = GetIdevCertReq::new_zeroed();
        crate::packet::copy_from_mbox(drivers, cmd.as_mut_bytes())?;

        // Validate tbs
        if cmd.tbs_size as usize > cmd.tbs.len() {
            return Err(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS);
        }

        let sig = Ecdsa384Signature {
            r: cmd.signature_r,
            s: cmd.signature_s,
        };

        let Some(builder) = Ecdsa384CertBuilder::new(&cmd.tbs[..cmd.tbs_size as usize], &sig)
        else {
            return Err(CaliptraError::RUNTIME_GET_IDEVID_CERT_FAILED);
        };

        let mut resp = GetIdevCertResp::default();
        let Some(cert_size) = builder.build(&mut resp.cert) else {
            return Err(CaliptraError::RUNTIME_GET_IDEVID_CERT_FAILED);
        };

        resp.cert_size = cert_size as u32;
        crate::packet::copy_to_mbox(drivers, resp.as_mut_bytes())
    }
}

#[cfg(feature = "mldsa_attestation")]
pub struct PqCertCmd;
#[cfg(feature = "mldsa_attestation")]
impl PqCertCmd {
    #[inline(never)]
    pub(crate) fn execute(drivers: &mut Drivers) -> CaliptraResult<()> {
        let mut cmd = GetPqCertReq::new_zeroed();
        crate::packet::copy_from_mbox(drivers, cmd.as_mut_bytes())?;

        // Validate tbs
        if cmd.tbs_size as usize > cmd.tbs.len() {
            return Err(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS);
        }

        let sig = Mldsa87Signature::new(cmd.signature);

        let Some(builder) = MlDsa87CertBuilder::new(&cmd.tbs[..cmd.tbs_size as usize], &sig) else {
            return Err(CaliptraError::RUNTIME_GET_PQ_CERT_FAILED);
        };

        let mut resp = GetPqCertResp::default();
        let Some(cert_size) = builder.build(&mut resp.cert) else {
            return Err(CaliptraError::RUNTIME_GET_PQ_CERT_FAILED);
        };

        resp.cert_size = cert_size as u32;
        crate::packet::copy_to_mbox(drivers, resp.as_mut_bytes())
    }
}

pub struct GetLdevCertCmd;
impl GetLdevCertCmd {
    #[inline(never)]
    pub(crate) fn execute(drivers: &mut Drivers) -> CaliptraResult<()> {
        let mut resp = GetLdevCertResp::default();

        resp.data_size = copy_ldevid_cert(
            &drivers.data_vault,
            drivers.persistent_data.get(),
            &mut resp.data,
        )? as u32;

        crate::packet::copy_to_mbox(drivers, resp.as_mut_bytes())
    }
}

pub struct GetFmcAliasCertCmd;
impl GetFmcAliasCertCmd {
    #[inline(never)]
    pub(crate) fn execute(drivers: &mut Drivers) -> CaliptraResult<()> {
        let mut resp = GetFmcAliasCertResp::default();

        resp.data_size = copy_fmc_alias_cert(
            &drivers.data_vault,
            drivers.persistent_data.get(),
            &mut resp.data,
        )? as u32;

        crate::packet::copy_to_mbox(drivers, resp.as_mut_bytes())
    }
}

pub struct GetRtAliasCertCmd;
impl GetRtAliasCertCmd {
    #[inline(never)]
    pub(crate) fn execute(drivers: &mut Drivers) -> CaliptraResult<()> {
        let mut resp = GetRtAliasCertResp::default();

        resp.data_size = copy_rt_alias_cert(drivers.persistent_data.get(), &mut resp.data)? as u32;

        crate::packet::copy_to_mbox(drivers, resp.as_mut_bytes())
    }
}

/// Retrieve the r portion of the LDevId cert signature
///
/// # Arguments
///
/// * `persistent_data` - PersistentData
/// * `dv` - DataVault
///
/// # Returns
///
/// * `Ecc384Scalar` - The r portion of the LDevId cert signature
fn ldevid_dice_sign_r(
    persistent_data: &PersistentData,
    dv: &DataVault,
) -> CaliptraResult<Ecc384Scalar> {
    let ds: DataStore = persistent_data
        .fht
        .ldevid_cert_sig_r_dv_hdl
        .try_into()
        .map_err(|_| CaliptraError::RUNTIME_LDEVID_CERT_HANDOFF_FAILED)?;

    // The data store is either a warm reset entry or a cold reset entry.
    match ds {
        DataStore::DataVaultNonSticky48(dv_entry) => Ok(dv.read_warm_reset_entry48(dv_entry)),
        DataStore::DataVaultSticky48(dv_entry) => Ok(dv.read_cold_reset_entry48(dv_entry)),
        _ => Err(CaliptraError::RUNTIME_LDEVID_CERT_HANDOFF_FAILED),
    }
}

/// Retrieve the s portion of the LDevId cert signature
///
/// # Arguments
///
/// * `persistent_data` - PersistentData
/// * `dv` - DataVault
///
/// # Returns
///
/// * `Ecc384Scalar` - The s portion of the LDevId cert signature
fn ldevid_dice_sign_s(
    persistent_data: &PersistentData,
    dv: &DataVault,
) -> CaliptraResult<Ecc384Scalar> {
    let ds: DataStore = persistent_data
        .fht
        .ldevid_cert_sig_s_dv_hdl
        .try_into()
        .map_err(|_| CaliptraError::RUNTIME_LDEVID_CERT_HANDOFF_FAILED)?;

    // The data store is either a warm reset entry or a cold reset entry.
    match ds {
        DataStore::DataVaultNonSticky48(dv_entry) => Ok(dv.read_warm_reset_entry48(dv_entry)),
        DataStore::DataVaultSticky48(dv_entry) => Ok(dv.read_cold_reset_entry48(dv_entry)),
        _ => Err(CaliptraError::RUNTIME_LDEVID_CERT_HANDOFF_FAILED),
    }
}

/// Piece together the r and s portions of the LDevId cert signature
///
/// # Arguments
///
/// * `persistent_data` - PersistentData
/// * `dv` - DataVault
///
/// # Returns
///
/// * `Ecc384Signature` - The formed signature
pub fn ldevid_dice_sign(
    persistent_data: &PersistentData,
    dv: &DataVault,
) -> CaliptraResult<Ecc384Signature> {
    Ok(Ecc384Signature {
        r: ldevid_dice_sign_r(persistent_data, dv)?,
        s: ldevid_dice_sign_s(persistent_data, dv)?,
    })
}

/// Copy LDevID certificate produced by ROM to `cert` buffer
///
/// # Arguments
///
/// * `dv` - DataVault
/// * `persistent_data` - PersistentData
/// * `cert` - Buffer to copy LDevID certificate to
///
/// # Returns
///
/// * `usize` - The number of bytes written to `cert`
#[inline(never)]
pub fn copy_ldevid_cert(
    dv: &DataVault,
    persistent_data: &PersistentData,
    cert: &mut [u8],
) -> CaliptraResult<usize> {
    let tbs = persistent_data
        .ldevid_tbs
        .get(..persistent_data.fht.ldevid_tbs_size.into());
    let sig = ldevid_dice_sign(persistent_data, dv)?;
    cert_from_tbs_and_sig(tbs, &sig, cert)
        .map_err(|_| CaliptraError::RUNTIME_GET_LDEVID_CERT_FAILED)
}

/// Retrieve the r portion of the FMC alias cert signature
///
/// # Arguments
///
/// * `persistent_data` - PersistentData
/// * `dv` - DataVault
///
/// # Returns
///
/// * `Ecc384Scalar` - The r portion of the FMC alias cert signature
fn fmc_dice_sign_r(
    persistent_data: &PersistentData,
    dv: &DataVault,
) -> CaliptraResult<Ecc384Scalar> {
    let ds: DataStore = persistent_data
        .fht
        .fmc_cert_sig_r_dv_hdl
        .try_into()
        .map_err(|_| CaliptraError::RUNTIME_FMC_CERT_HANDOFF_FAILED)?;

    // The data store is either a warm reset entry or a cold reset entry.
    match ds {
        DataStore::DataVaultNonSticky48(dv_entry) => Ok(dv.read_warm_reset_entry48(dv_entry)),
        DataStore::DataVaultSticky48(dv_entry) => Ok(dv.read_cold_reset_entry48(dv_entry)),
        _ => Err(CaliptraError::RUNTIME_FMC_CERT_HANDOFF_FAILED),
    }
}

/// Retrieve the s portion of the FMC alias cert signature
///
/// # Arguments
///
/// * `persistent_data` - PersistentData
/// * `dv` - DataVault
///
/// # Returns
///
/// * `Ecc384Scalar` - The s portion of the FMC alias cert signature
fn fmc_dice_sign_s(
    persistent_data: &PersistentData,
    dv: &DataVault,
) -> CaliptraResult<Ecc384Scalar> {
    let ds: DataStore = persistent_data
        .fht
        .fmc_cert_sig_s_dv_hdl
        .try_into()
        .map_err(|_| CaliptraError::RUNTIME_FMC_CERT_HANDOFF_FAILED)?;

    // The data store is either a warm reset entry or a cold reset entry.
    match ds {
        DataStore::DataVaultNonSticky48(dv_entry) => Ok(dv.read_warm_reset_entry48(dv_entry)),
        DataStore::DataVaultSticky48(dv_entry) => Ok(dv.read_cold_reset_entry48(dv_entry)),
        _ => Err(CaliptraError::RUNTIME_FMC_CERT_HANDOFF_FAILED),
    }
}

/// Piece together the r and s portions of the FMC alias cert signature
///
/// # Arguments
///
/// * `persistent_data` - PersistentData
/// * `dv` - DataVault
///
/// # Returns
///
/// * `Ecc384Signature` - The formed signature
pub fn fmc_dice_sign(
    persistent_data: &PersistentData,
    dv: &DataVault,
) -> CaliptraResult<Ecc384Signature> {
    Ok(Ecc384Signature {
        r: fmc_dice_sign_r(persistent_data, dv)?,
        s: fmc_dice_sign_s(persistent_data, dv)?,
    })
}

/// Copy FMC alias certificate produced by ROM to `cert` buffer
///
/// # Arguments
///
/// * `dv` - DataVault
/// * `persistent_data` - PersistentData
/// * `cert` - Buffer to copy LDevID certificate to
///
/// # Returns
///
/// * `usize` - The number of bytes written to `cert`
#[inline(never)]
pub fn copy_fmc_alias_cert(
    dv: &DataVault,
    persistent_data: &PersistentData,
    cert: &mut [u8],
) -> CaliptraResult<usize> {
    let tbs = persistent_data
        .fmcalias_tbs
        .get(..persistent_data.fht.fmcalias_tbs_size.into());
    let sig = fmc_dice_sign(persistent_data, dv)?;
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

/// Derive the PQ.DevID ML-DSA-87 seed from the PQ.DevID CDI stored in
/// persistent data.
///
/// This mirrors the ROM DICE convention of deriving the DevID key pair from
/// the DevID CDI, so the CSR here matches the PQ.DevID identity used
/// elsewhere in the runtime. The CDI is provisioned by SET_PQ_SEED and lives
/// in persistent data.
#[cfg(feature = "mldsa_attestation")]
pub fn derive_devid_seed(
    cdi: &Array4x12,
    seed: &mut Mldsa87Seed,
    hmac384: &mut Hmac384,
    trng: &mut Trng,
) -> CaliptraResult<()> {
    let mut output = Zeroizing::new(Array4x12::default());
    hmac384_kdf(
        hmac384,
        cdi.into(),
        b"pq_devid_keygen",
        None,
        trng,
        (&mut *output).into(),
    )?;

    let bytes = Zeroizing::new(<[u8; core::mem::size_of::<Array4x12>()]>::from(*output));
    seed.copy_from_slice(&bytes[..MLDSA87_PRIVATE_SEED_BYTES]);
    Ok(())
}
