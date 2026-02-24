// Licensed under the Apache-2.0 license

use crate::{mutrefbytes, Drivers};

use caliptra_api::mailbox::{
    EndorsementAlgorithms, MailboxRespHeader, OcpLockEndorseHpkePubKeyReq,
    OcpLockEndorseHpkePubKeyResp,
};
use caliptra_cfi_derive_git::cfi_impl_fn;

use caliptra_common::{
    crypto::{Crypto, PubKey},
    dice::{ecc384_cert_from_tbs_and_sig, mldsa87_cert_from_tbs_and_sig},
    x509,
};
use caliptra_drivers::{
    hpke::{
        kem::{HybridEncapsulationKey, MlKemEncapsulationKey, P384EncapsulationKey},
        suites::{HpkeCipherSuite, KemId},
        HpkeHandle,
    },
    Ecc384PubKey,
};
use caliptra_error::{CaliptraError, CaliptraResult};

use caliptra_x509::{
    OcpLockEcdh384CertTbsEcc384, OcpLockEcdh384CertTbsEcc384Params, OcpLockEcdh384CertTbsMlDsa87,
    OcpLockEcdh384CertTbsMlDsa87Params, OcpLockHybridCertTbsEcc384,
    OcpLockHybridCertTbsEcc384Params, OcpLockMlKemCertTbsEcc384, OcpLockMlKemCertTbsEcc384Params,
    OcpLockMlKemCertTbsMlDsa87, OcpLockMlKemCertTbsMlDsa87Params,
};
use zerocopy::FromBytes;

pub struct EndorseHpkePubkeyCmd;
impl EndorseHpkePubkeyCmd {
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    #[inline(never)]
    pub(crate) fn execute(
        drivers: &mut Drivers,
        cmd_args: &[u8],
        resp: &mut [u8],
    ) -> CaliptraResult<usize> {
        let ref_from_bytes = OcpLockEndorseHpkePubKeyReq::ref_from_bytes(cmd_args);
        let cmd = ref_from_bytes.map_err(|_| CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;
        let hpke_handle = HpkeHandle::from(cmd.hpke_handle);

        let resp = mutrefbytes::<OcpLockEndorseHpkePubKeyResp>(resp)?;
        resp.hdr = MailboxRespHeader::default();
        resp.pub_key_len = drivers.ocp_lock_context.get_hpke_public_key(
            &mut drivers.sha3,
            &mut drivers.ml_kem,
            &mut drivers.ecc384,
            &mut drivers.trng,
            &mut drivers.hmac,
            &hpke_handle,
            &mut resp.pub_key,
        )? as u32;

        let HpkeCipherSuite { kem, .. } = drivers
            .ocp_lock_context
            .get_hpke_cipher_suite(&hpke_handle)?;

        resp.endorsement_len = Self::create_endorsement_certificate(
            drivers,
            &resp.pub_key,
            &kem,
            cmd.endorsement_algorithm.clone(),
            &mut resp.endorsement,
        )? as u32;

        Ok(core::mem::size_of::<OcpLockEndorseHpkePubKeyResp>())
    }

    /// Creates a certificate that endorses `pub_key` based on the `EndorsementAlgorithms`
    fn create_endorsement_certificate(
        drivers: &mut Drivers,
        pub_key: &[u8],
        kem_id: &KemId,
        endorsement_algorithm: EndorsementAlgorithms,
        cert_buf: &mut [u8],
    ) -> CaliptraResult<usize> {
        match endorsement_algorithm {
            EndorsementAlgorithms::ECDSA_P384_SHA384 => {
                Self::create_ecdsa_endorsed_certificate(drivers, pub_key, kem_id, cert_buf)
            }
            // TODO(clundin): Renable after code space optimizations
            // https://github.com/chipsalliance/caliptra-sw/issues/3355
            // EndorsementAlgorithms::ML_DSA_87 => {
            //     Self::create_mldsa_endorsed_certificate(drivers, pub_key, kem_id, cert_buf)
            // }
            _ => Err(CaliptraError::RUNTIME_OCP_LOCK_UNKNOWN_ENDORSEMENT_ALGORITHM)?,
        }
    }

    fn create_ecdsa_endorsed_certificate(
        drivers: &mut Drivers,
        pub_key: &[u8],
        kem_id: &KemId,
        cert_buf: &mut [u8],
    ) -> CaliptraResult<usize> {
        let (not_before, not_after) =
            Drivers::get_cert_validity_info(&drivers.persistent_data.get().rom.manifest1);
        let rt_ecc_key = Drivers::get_key_id_rt_ecc_priv_key(drivers)?;
        let rt_ecc_pub_key = &drivers.persistent_data.get().rom.fht.rt_dice_ecc_pub_key;
        let issuer_sn: [u8; 64] = x509::subj_sn(&mut drivers.sha256, &PubKey::Ecc(rt_ecc_pub_key))?;
        let authority_key_id: [u8; 20] =
            x509::subj_key_id(&mut drivers.sha256, &PubKey::Ecc(rt_ecc_pub_key))?;

        match *kem_id {
            KemId::ML_KEM_1024 => {
                let public_key = pub_key
                    .get(..OcpLockMlKemCertTbsEcc384Params::PUBLIC_KEY_LEN)
                    .and_then(|pub_key| <MlKemEncapsulationKey>::ref_from_bytes(pub_key).ok())
                    .ok_or(CaliptraError::RUNTIME_OCP_LOCK_ENDORSEMENT_CERT_ENCODING_ERROR)?;
                let subject_sn: [u8; 64] =
                    x509::subj_sn(&mut drivers.sha256, &PubKey::MlKem(public_key))?;
                let subject_key_id: [u8; 20] =
                    x509::subj_key_id(&mut drivers.sha256, &PubKey::MlKem(public_key))?;

                let params = OcpLockMlKemCertTbsEcc384Params {
                    public_key: public_key.as_ref(),
                    subject_sn: &subject_sn,
                    issuer_sn: &issuer_sn,
                    serial_number: subject_sn
                        .get(..20)
                        .and_then(|sn| <[u8; 20]>::ref_from_bytes(sn).ok())
                        .ok_or(CaliptraError::RUNTIME_OCP_LOCK_ENDORSEMENT_CERT_ENCODING_ERROR)?,
                    subject_key_id: &subject_key_id,
                    authority_key_id: &authority_key_id,
                    not_before: &not_before.value,
                    not_after: &not_after.value,
                };

                let tbs = OcpLockMlKemCertTbsEcc384::new(&params);
                let signature = Crypto::ecdsa384_sign(
                    &mut drivers.sha2_512_384,
                    &mut drivers.ecc384,
                    &mut drivers.trng,
                    rt_ecc_key,
                    rt_ecc_pub_key,
                    tbs.tbs(),
                )?;
                ecc384_cert_from_tbs_and_sig(Some(tbs.tbs()), &signature, cert_buf)
            }
            KemId::P_384 => {
                let public_key = pub_key
                    .get(..OcpLockEcdh384CertTbsEcc384Params::PUBLIC_KEY_LEN)
                    .and_then(|pub_key| <P384EncapsulationKey>::ref_from_bytes(pub_key).ok())
                    .ok_or(CaliptraError::RUNTIME_OCP_LOCK_ENDORSEMENT_CERT_ENCODING_ERROR)?;
                let public_key_serialized = Ecc384PubKey::try_from(public_key)
                    .map_err(|_| CaliptraError::RUNTIME_OCP_LOCK_ENDORSEMENT_CERT_ENCODING_ERROR)?;
                let subject_sn: [u8; 64] =
                    x509::subj_sn(&mut drivers.sha256, &PubKey::Ecc(&public_key_serialized))?;
                let subject_key_id: [u8; 20] =
                    x509::subj_key_id(&mut drivers.sha256, &PubKey::Ecc(&public_key_serialized))?;

                let params = OcpLockEcdh384CertTbsEcc384Params {
                    public_key: public_key.as_ref(),
                    subject_sn: &subject_sn,
                    issuer_sn: &issuer_sn,
                    serial_number: subject_sn
                        .get(..20)
                        .and_then(|sn| <[u8; 20]>::ref_from_bytes(sn).ok())
                        .ok_or(CaliptraError::RUNTIME_OCP_LOCK_ENDORSEMENT_CERT_ENCODING_ERROR)?,
                    subject_key_id: &subject_key_id,
                    authority_key_id: &authority_key_id,
                    not_before: &not_before.value,
                    not_after: &not_after.value,
                };

                let tbs = OcpLockEcdh384CertTbsEcc384::new(&params);
                let signature = Crypto::ecdsa384_sign(
                    &mut drivers.sha2_512_384,
                    &mut drivers.ecc384,
                    &mut drivers.trng,
                    rt_ecc_key,
                    rt_ecc_pub_key,
                    tbs.tbs(),
                )?;
                ecc384_cert_from_tbs_and_sig(Some(tbs.tbs()), &signature, cert_buf)
            }
            KemId::ML_KEM_1024_P384 => {
                let public_key = pub_key
                    .get(..OcpLockHybridCertTbsEcc384Params::PUBLIC_KEY_LEN)
                    .and_then(|pub_key| <HybridEncapsulationKey>::ref_from_bytes(pub_key).ok())
                    .ok_or(CaliptraError::RUNTIME_OCP_LOCK_ENDORSEMENT_CERT_ENCODING_ERROR)?;
                let subject_sn: [u8; 64] =
                    x509::subj_sn(&mut drivers.sha256, &PubKey::HybridMlkemP384(public_key))?;
                let subject_key_id: [u8; 20] =
                    x509::subj_key_id(&mut drivers.sha256, &PubKey::HybridMlkemP384(public_key))?;

                let params = OcpLockHybridCertTbsEcc384Params {
                    public_key: public_key.as_ref(),
                    subject_sn: &subject_sn,
                    issuer_sn: &issuer_sn,
                    serial_number: subject_sn
                        .get(..20)
                        .and_then(|sn| <[u8; 20]>::ref_from_bytes(sn).ok())
                        .ok_or(CaliptraError::RUNTIME_OCP_LOCK_ENDORSEMENT_CERT_ENCODING_ERROR)?,
                    subject_key_id: &subject_key_id,
                    authority_key_id: &authority_key_id,
                    not_before: &not_before.value,
                    not_after: &not_after.value,
                };

                let tbs = OcpLockHybridCertTbsEcc384::new(&params);
                let signature = Crypto::ecdsa384_sign(
                    &mut drivers.sha2_512_384,
                    &mut drivers.ecc384,
                    &mut drivers.trng,
                    rt_ecc_key,
                    rt_ecc_pub_key,
                    tbs.tbs(),
                )?;
                ecc384_cert_from_tbs_and_sig(Some(tbs.tbs()), &signature, cert_buf)
            }
            _ => Err(CaliptraError::RUNTIME_OCP_LOCK_UNKNOWN_KEM_ALGORITHM)?,
        }
    }

    // TODO(clundin): Renable after code space optimizations
    // https://github.com/chipsalliance/caliptra-sw/issues/3355
    #[allow(dead_code)]
    fn create_mldsa_endorsed_certificate(
        drivers: &mut Drivers,
        pub_key: &[u8],
        kem_id: &KemId,
        cert_buf: &mut [u8],
    ) -> CaliptraResult<usize> {
        let (not_before, not_after) =
            Drivers::get_cert_validity_info(&drivers.persistent_data.get().rom.manifest1);
        let rt_mldsa_key = Drivers::get_key_id_rt_mldsa_keypair_seed(drivers)?;
        let rt_mldsa_pub_key = Drivers::get_key_id_rt_mldsa_pub_key(drivers)?;

        let issuer_sn: [u8; 64] =
            x509::subj_sn(&mut drivers.sha256, &PubKey::Mldsa(&rt_mldsa_pub_key))?;
        let authority_key_id: [u8; 20] =
            x509::subj_key_id(&mut drivers.sha256, &PubKey::Mldsa(&rt_mldsa_pub_key))?;

        match *kem_id {
            KemId::ML_KEM_1024 => {
                let public_key = pub_key
                    .get(..OcpLockMlKemCertTbsMlDsa87Params::PUBLIC_KEY_LEN)
                    .and_then(|pub_key| <MlKemEncapsulationKey>::ref_from_bytes(pub_key).ok())
                    .ok_or(CaliptraError::RUNTIME_OCP_LOCK_ENDORSEMENT_CERT_ENCODING_ERROR)?;
                let subject_sn: [u8; 64] =
                    x509::subj_sn(&mut drivers.sha256, &PubKey::MlKem(public_key))?;
                let subject_key_id: [u8; 20] =
                    x509::subj_key_id(&mut drivers.sha256, &PubKey::MlKem(public_key))?;

                let params = OcpLockMlKemCertTbsMlDsa87Params {
                    public_key: public_key.as_ref(),
                    subject_sn: &subject_sn,
                    issuer_sn: &issuer_sn,
                    serial_number: subject_sn
                        .get(..20)
                        .and_then(|sn| <[u8; 20]>::ref_from_bytes(sn).ok())
                        .ok_or(CaliptraError::RUNTIME_OCP_LOCK_ENDORSEMENT_CERT_ENCODING_ERROR)?,
                    subject_key_id: &subject_key_id,
                    authority_key_id: &authority_key_id,
                    not_before: &not_before.value,
                    not_after: &not_after.value,
                };

                let tbs = OcpLockMlKemCertTbsMlDsa87::new(&params);
                let signature = Crypto::mldsa87_sign(
                    &mut drivers.mldsa87,
                    &mut drivers.trng,
                    rt_mldsa_key,
                    &rt_mldsa_pub_key,
                    tbs.tbs(),
                )?;
                mldsa87_cert_from_tbs_and_sig(Some(tbs.tbs()), &signature, cert_buf)
            }
            KemId::P_384 => {
                let public_key = pub_key
                    .get(..OcpLockEcdh384CertTbsMlDsa87Params::PUBLIC_KEY_LEN)
                    .and_then(|pub_key| <P384EncapsulationKey>::ref_from_bytes(pub_key).ok())
                    .ok_or(CaliptraError::RUNTIME_OCP_LOCK_ENDORSEMENT_CERT_ENCODING_ERROR)?;
                let public_key_serialized = Ecc384PubKey::try_from(public_key)
                    .map_err(|_| CaliptraError::RUNTIME_OCP_LOCK_ENDORSEMENT_CERT_ENCODING_ERROR)?;
                let subject_sn: [u8; 64] =
                    x509::subj_sn(&mut drivers.sha256, &PubKey::Ecc(&public_key_serialized))?;
                let subject_key_id: [u8; 20] =
                    x509::subj_key_id(&mut drivers.sha256, &PubKey::Ecc(&public_key_serialized))?;

                let params = OcpLockEcdh384CertTbsMlDsa87Params {
                    public_key: public_key.as_ref(),
                    subject_sn: &subject_sn,
                    issuer_sn: &issuer_sn,
                    serial_number: subject_sn
                        .get(..20)
                        .and_then(|sn| <[u8; 20]>::ref_from_bytes(sn).ok())
                        .ok_or(CaliptraError::RUNTIME_OCP_LOCK_ENDORSEMENT_CERT_ENCODING_ERROR)?,
                    subject_key_id: &subject_key_id,
                    authority_key_id: &authority_key_id,
                    not_before: &not_before.value,
                    not_after: &not_after.value,
                };

                let tbs = OcpLockEcdh384CertTbsMlDsa87::new(&params);
                let signature = Crypto::mldsa87_sign(
                    &mut drivers.mldsa87,
                    &mut drivers.trng,
                    rt_mldsa_key,
                    &rt_mldsa_pub_key,
                    tbs.tbs(),
                )?;
                mldsa87_cert_from_tbs_and_sig(Some(tbs.tbs()), &signature, cert_buf)
            }
            _ => Err(CaliptraError::RUNTIME_OCP_LOCK_UNKNOWN_KEM_ALGORITHM)?,
        }
    }
}
