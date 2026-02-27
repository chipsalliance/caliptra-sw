// Licensed under the Apache-2.0 license

use super::MAX_CSR_SIZE;
use crate::Drivers;
use caliptra_common::{crypto::PubKey, x509};
use caliptra_drivers::{KeyReadArgs, Mldsa87Seed, Mldsa87SignRnd};
use caliptra_error::{CaliptraError, CaliptraResult};
use caliptra_x509::{
    Ecdsa384CsrBuilder, Ecdsa384Signature, MlDsa87CsrBuilder, MlDsa87Signature,
    RtAliasCsrTbsEcc384, RtAliasCsrTbsEcc384Params, RtAliasCsrTbsMlDsa87,
    RtAliasCsrTbsMlDsa87Params,
};
use zerocopy::IntoBytes;

/// Generate an RT Alias ECC384 CSR, signed with the RT Alias ECC private key.
pub fn generate_rt_alias_ecc_csr(
    drivers: &mut Drivers,
    csr_buf: &mut [u8; MAX_CSR_SIZE],
) -> CaliptraResult<usize> {
    let pub_key = drivers.persistent_data.get().rom.fht.rt_dice_ecc_pub_key;
    let subject_sn = x509::subj_sn(&mut drivers.sha256, &PubKey::Ecc(&pub_key))?;
    let ueid = x509::ueid(&drivers.soc_ifc)?;

    let data_vault = &drivers.persistent_data.get().rom.data_vault;
    let rt_tci: [u8; 48] = data_vault.rt_tci().into();
    let fw_svn = data_vault.fw_svn() as u8;

    let params = RtAliasCsrTbsEcc384Params {
        public_key: &pub_key.to_der(),
        subject_sn: &subject_sn,
        ueid: &ueid,
        tcb_info_rt_tci: &rt_tci,
        tcb_info_fw_svn: &fw_svn.to_be_bytes(),
    };

    let tbs = RtAliasCsrTbsEcc384::new(&params);

    // Sign the TBS with RT Alias ECC private key
    let key_id_rt_priv_key = Drivers::get_key_id_rt_ecc_priv_key(drivers)?;
    let priv_key_args = KeyReadArgs::new(key_id_rt_priv_key);
    let priv_key = caliptra_drivers::Ecc384PrivKeyIn::Key(priv_key_args);
    let digest = drivers.sha2_512_384.sha384_digest(tbs.tbs());
    let digest = caliptra_drivers::okref(&digest)?;

    let signature = drivers
        .ecc384
        .sign(priv_key, &pub_key, digest, &mut drivers.trng)?;

    let ecdsa_sig = Ecdsa384Signature {
        r: (&signature.r).into(),
        s: (&signature.s).into(),
    };

    let csr_builder = Ecdsa384CsrBuilder::new(tbs.tbs(), &ecdsa_sig)
        .ok_or(CaliptraError::RUNTIME_ATTESTED_CSR_EAT_ENCODING_ERROR)?;
    csr_builder
        .build(csr_buf)
        .ok_or(CaliptraError::RUNTIME_ATTESTED_CSR_EAT_ENCODING_ERROR)
}

/// Generate an RT Alias ML-DSA-87 CSR, signed with the RT Alias ML-DSA private key.
pub fn generate_rt_alias_mldsa_csr(
    drivers: &mut Drivers,
    csr_buf: &mut [u8; MAX_CSR_SIZE],
) -> CaliptraResult<usize> {
    let pub_key = Drivers::get_key_id_rt_mldsa_pub_key(drivers)?;
    let subject_sn = x509::subj_sn(&mut drivers.sha256, &PubKey::Mldsa(&pub_key))?;
    let ueid = x509::ueid(&drivers.soc_ifc)?;

    let data_vault = &drivers.persistent_data.get().rom.data_vault;
    let rt_tci: [u8; 48] = data_vault.rt_tci().into();
    let fw_svn = data_vault.fw_svn() as u8;

    let params = RtAliasCsrTbsMlDsa87Params {
        public_key: &pub_key.into(),
        subject_sn: &subject_sn,
        ueid: &ueid,
        tcb_info_rt_tci: &rt_tci,
        tcb_info_fw_svn: &fw_svn.to_be_bytes(),
    };

    let tbs = RtAliasCsrTbsMlDsa87::new(&params);

    // Sign the TBS with RT Alias ML-DSA private key
    // ML-DSA handles its own internal hashing, so pass raw TBS data
    let rt_seed = Drivers::get_key_id_rt_mldsa_keypair_seed(drivers)?;
    let key_args = KeyReadArgs::new(rt_seed);

    let signature = drivers.mldsa87.sign_var(
        Mldsa87Seed::Key(key_args),
        &pub_key,
        tbs.tbs(),
        &Mldsa87SignRnd::default(),
        &mut drivers.trng,
    )?;

    let mldsa_sig = MlDsa87Signature {
        sig: signature.as_bytes()[..4627].try_into().unwrap(),
    };

    let csr_builder = MlDsa87CsrBuilder::new(tbs.tbs(), &mldsa_sig)
        .ok_or(CaliptraError::RUNTIME_ATTESTED_CSR_EAT_ENCODING_ERROR)?;
    csr_builder
        .build(csr_buf)
        .ok_or(CaliptraError::RUNTIME_ATTESTED_CSR_EAT_ENCODING_ERROR)
}
