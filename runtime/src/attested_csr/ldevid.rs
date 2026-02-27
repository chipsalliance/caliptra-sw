// Licensed under the Apache-2.0 license

use super::MAX_CSR_SIZE;
use crate::Drivers;
use caliptra_common::x509;
use caliptra_error::{CaliptraError, CaliptraResult};
use caliptra_x509::{
    Ecdsa384CsrBuilder, Ecdsa384Signature, LocalDevIdCsrTbsEcc384, LocalDevIdCsrTbsEcc384Params,
    LocalDevIdCsrTbsMlDsa87, LocalDevIdCsrTbsMlDsa87Params, MlDsa87CsrBuilder, MlDsa87Signature,
};

/// Build a null-signed LDevID ECC384 CSR.
/// Null CSR is encapsulated in COSE Sign1 structure, signed by
/// RT alias key.
pub fn generate_ldevid_ecc_csr(
    drivers: &mut Drivers,
    csr_buf: &mut [u8; MAX_CSR_SIZE],
) -> CaliptraResult<usize> {
    let pub_key = drivers
        .persistent_data
        .get()
        .rom
        .data_vault
        .ldev_dice_ecc_pub_key();
    let subject_sn = x509::subj_sn(
        &mut drivers.sha256,
        &caliptra_common::crypto::PubKey::Ecc(&pub_key),
    )?;
    let ueid = x509::ueid(&drivers.soc_ifc)?;
    let params = LocalDevIdCsrTbsEcc384Params {
        public_key: &pub_key.to_der(),
        subject_sn: &subject_sn,
        ueid: &ueid,
    };

    let csr_tbs = LocalDevIdCsrTbsEcc384::new(&params);
    let null_sig = Ecdsa384Signature::default();
    let csr_builder = Ecdsa384CsrBuilder::new(csr_tbs.tbs(), &null_sig)
        .ok_or(CaliptraError::RUNTIME_ATTESTED_CSR_EAT_ENCODING_ERROR)?;
    csr_builder
        .build(csr_buf)
        .ok_or(CaliptraError::RUNTIME_ATTESTED_CSR_EAT_ENCODING_ERROR)
}

/// Build a null-signed LDevID ML-DSA87 CSR.
pub fn generate_ldevid_mldsa_csr(
    drivers: &mut Drivers,
    csr_buf: &mut [u8; MAX_CSR_SIZE],
) -> CaliptraResult<usize> {
    let pub_key = drivers
        .persistent_data
        .get()
        .rom
        .data_vault
        .ldev_dice_mldsa_pub_key();
    let subject_sn = x509::subj_sn(
        &mut drivers.sha256,
        &caliptra_common::crypto::PubKey::Mldsa(&pub_key),
    )?;
    let ueid = x509::ueid(&drivers.soc_ifc)?;
    let params = LocalDevIdCsrTbsMlDsa87Params {
        public_key: &pub_key.into(),
        subject_sn: &subject_sn,
        ueid: &ueid,
    };

    let csr_tbs = LocalDevIdCsrTbsMlDsa87::new(&params);
    let null_sig = MlDsa87Signature::default();
    let csr_builder = MlDsa87CsrBuilder::new(csr_tbs.tbs(), &null_sig)
        .ok_or(CaliptraError::RUNTIME_ATTESTED_CSR_EAT_ENCODING_ERROR)?;
    csr_builder
        .build(csr_buf)
        .ok_or(CaliptraError::RUNTIME_ATTESTED_CSR_EAT_ENCODING_ERROR)
}
