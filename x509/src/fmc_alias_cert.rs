/*++

Licensed under the Apache-2.0 license.

File Name:

    fmc_alias_cert.rs

Abstract:

    FMC Alias Certificate related code.

--*/

// Note: All the necessary code is auto generated
include!(concat!(env!("OUT_DIR"), "/fmc_alias_cert_tbs.rs"));

#[cfg(all(test, target_family = "unix"))]
mod tests {
    use super::*;
    use crate::test_util::tests::*;
    use crate::{NotAfter, NotBefore};
    use openssl::ecdsa::EcdsaSig;
    use openssl::sha::Sha384;
    use openssl::x509::X509;

    #[test]
    fn test_cert_signing() {
        let subject_key = Ecc384AsymKey::default();
        let issuer_key = Ecc384AsymKey::default();
        let ec_key = issuer_key.priv_key().ec_key().unwrap();

        let params = FmcAliasCertTbsParams {
            serial_number: &[0xABu8; FmcAliasCertTbsParams::SERIAL_NUMBER_LEN],
            public_key: TryInto::<&[u8; FmcAliasCertTbsParams::PUBLIC_KEY_LEN]>::try_into(
                subject_key.pub_key(),
            )
            .unwrap(),
            subject_sn: &TryInto::<[u8; FmcAliasCertTbsParams::SUBJECT_SN_LEN]>::try_into(
                subject_key.hex_str().into_bytes(),
            )
            .unwrap(),
            issuer_sn: &TryInto::<[u8; FmcAliasCertTbsParams::ISSUER_SN_LEN]>::try_into(
                issuer_key.hex_str().into_bytes(),
            )
            .unwrap(),
            ueid: &[0xAB; FmcAliasCertTbsParams::UEID_LEN],
            subject_key_id: &TryInto::<[u8; FmcAliasCertTbsParams::SUBJECT_KEY_ID_LEN]>::try_into(
                subject_key.sha1(),
            )
            .unwrap(),
            authority_key_id:
                &TryInto::<[u8; FmcAliasCertTbsParams::SUBJECT_KEY_ID_LEN]>::try_into(
                    issuer_key.sha1(),
                )
                .unwrap(),
            tcb_info_flags: &[0xB0, 0xB1, 0xB2, 0xB3],
            tcb_info_owner_pk_hash: &[0xB5u8; FmcAliasCertTbsParams::TCB_INFO_OWNER_PK_HASH_LEN],
            tcb_info_fmc_tci: &[0xB6u8; FmcAliasCertTbsParams::TCB_INFO_FMC_TCI_LEN],
            tcb_info_svn: &[0xB7],
            tcb_info_min_svn: &[0xB8],
            not_before: &NotBefore::default().not_before,
            not_after: &NotAfter::default().not_after,
        };

        let cert = FmcAliasCertTbs::new(&params);

        let sig = cert
            .sign(|b| {
                let mut sha = Sha384::new();
                sha.update(b);
                EcdsaSig::sign(&sha.finish(), &ec_key)
            })
            .unwrap();

        assert_ne!(cert.tbs(), FmcAliasCertTbs::TBS_TEMPLATE);
        assert_eq!(
            &cert.tbs()[FmcAliasCertTbs::PUBLIC_KEY_OFFSET
                ..FmcAliasCertTbs::PUBLIC_KEY_OFFSET + FmcAliasCertTbs::PUBLIC_KEY_LEN],
            params.public_key,
        );
        assert_eq!(
            &cert.tbs()[FmcAliasCertTbs::SUBJECT_SN_OFFSET
                ..FmcAliasCertTbs::SUBJECT_SN_OFFSET + FmcAliasCertTbs::SUBJECT_SN_LEN],
            params.subject_sn,
        );
        assert_eq!(
            &cert.tbs()[FmcAliasCertTbs::ISSUER_SN_OFFSET
                ..FmcAliasCertTbs::ISSUER_SN_OFFSET + FmcAliasCertTbs::ISSUER_SN_LEN],
            params.issuer_sn,
        );
        assert_eq!(
            &cert.tbs()[FmcAliasCertTbs::UEID_OFFSET
                ..FmcAliasCertTbs::UEID_OFFSET + FmcAliasCertTbs::UEID_LEN],
            params.ueid,
        );
        assert_eq!(
            &cert.tbs()[FmcAliasCertTbs::SUBJECT_KEY_ID_OFFSET
                ..FmcAliasCertTbs::SUBJECT_KEY_ID_OFFSET + FmcAliasCertTbs::SUBJECT_KEY_ID_LEN],
            params.subject_key_id,
        );
        assert_eq!(
            &cert.tbs()[FmcAliasCertTbs::AUTHORITY_KEY_ID_OFFSET
                ..FmcAliasCertTbs::AUTHORITY_KEY_ID_OFFSET + FmcAliasCertTbs::AUTHORITY_KEY_ID_LEN],
            params.authority_key_id,
        );
        assert_eq!(
            &cert.tbs()[FmcAliasCertTbs::TCB_INFO_FLAGS_OFFSET
                ..FmcAliasCertTbs::TCB_INFO_FLAGS_OFFSET + FmcAliasCertTbs::TCB_INFO_FLAGS_LEN],
            params.tcb_info_flags,
        );
        assert_eq!(
            &cert.tbs()[FmcAliasCertTbs::TCB_INFO_OWNER_PK_HASH_OFFSET
                ..FmcAliasCertTbs::TCB_INFO_OWNER_PK_HASH_OFFSET
                    + FmcAliasCertTbs::TCB_INFO_OWNER_PK_HASH_LEN],
            params.tcb_info_owner_pk_hash,
        );
        assert_eq!(
            &cert.tbs()[FmcAliasCertTbs::TCB_INFO_FMC_TCI_OFFSET
                ..FmcAliasCertTbs::TCB_INFO_FMC_TCI_OFFSET + FmcAliasCertTbs::TCB_INFO_FMC_TCI_LEN],
            params.tcb_info_fmc_tci,
        );
        assert_eq!(
            &cert.tbs()[FmcAliasCertTbs::TCB_INFO_SVN_OFFSET
                ..FmcAliasCertTbs::TCB_INFO_SVN_OFFSET + FmcAliasCertTbs::TCB_INFO_SVN_LEN],
            params.tcb_info_svn,
        );
        assert_eq!(
            &cert.tbs()[FmcAliasCertTbs::TCB_INFO_MIN_SVN_OFFSET
                ..FmcAliasCertTbs::TCB_INFO_MIN_SVN_OFFSET + FmcAliasCertTbs::TCB_INFO_MIN_SVN_LEN],
            params.tcb_info_min_svn,
        );

        let ecdsa_sig = crate::Ecdsa384Signature {
            r: TryInto::<[u8; 48]>::try_into(sig.r().to_vec_padded(48).unwrap()).unwrap(),
            s: TryInto::<[u8; 48]>::try_into(sig.s().to_vec_padded(48).unwrap()).unwrap(),
        };

        let builder = crate::Ecdsa384CertBuilder::new(cert.tbs(), &ecdsa_sig).unwrap();
        let mut buf = vec![0u8; builder.len()];
        builder.build(&mut buf).unwrap();

        let cert: X509 = X509::from_der(&buf).unwrap();
        assert!(cert.verify(issuer_key.priv_key()).unwrap());
    }
}
