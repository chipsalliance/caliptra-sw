/*++

Licensed under the Apache-2.0 license.

File Name:

    rt_alias_cert.rs

Abstract:

    ECC384 RT Alias Certificate related code.

--*/

// Note: All the necessary code is auto generated
#[cfg(feature = "generate_templates")]
include!(concat!(env!("OUT_DIR"), "/rt_alias_cert_tbs_ecc_384.rs"));
#[cfg(not(feature = "generate_templates"))]
include! {"../build/rt_alias_cert_tbs_ecc_384.rs"}

#[cfg(all(test, target_family = "unix"))]
mod tests {
    use openssl::ecdsa::EcdsaSig;
    use openssl::sha::Sha384;
    use openssl::x509::X509;

    use super::*;
    use crate::test_util::tests::*;
    use crate::{NotAfter, NotBefore};

    #[test]
    fn test_cert_signing() {
        let subject_key = Ecc384AsymKey::default();
        let issuer_key = Ecc384AsymKey::default();
        let ec_key = issuer_key.priv_key().ec_key().unwrap();

        let params = RtAliasCertTbsEcc384Params {
            serial_number: &[0xABu8; RtAliasCertTbsEcc384Params::SERIAL_NUMBER_LEN],
            public_key: TryInto::<&[u8; RtAliasCertTbsEcc384Params::PUBLIC_KEY_LEN]>::try_into(
                subject_key.pub_key(),
            )
            .unwrap(),
            subject_sn: &TryInto::<[u8; RtAliasCertTbsEcc384Params::SUBJECT_SN_LEN]>::try_into(
                subject_key.hex_str().into_bytes(),
            )
            .unwrap(),
            issuer_sn: &TryInto::<[u8; RtAliasCertTbsEcc384Params::ISSUER_SN_LEN]>::try_into(
                issuer_key.hex_str().into_bytes(),
            )
            .unwrap(),
            ueid: &[0xAB; RtAliasCertTbsEcc384Params::UEID_LEN],
            subject_key_id:
                &TryInto::<[u8; RtAliasCertTbsEcc384Params::SUBJECT_KEY_ID_LEN]>::try_into(
                    subject_key.sha1(),
                )
                .unwrap(),
            authority_key_id:
                &TryInto::<[u8; RtAliasCertTbsEcc384Params::SUBJECT_KEY_ID_LEN]>::try_into(
                    issuer_key.sha1(),
                )
                .unwrap(),
            tcb_info_rt_svn: &[0xE3],
            tcb_info_rt_tci: &[0xEFu8; RtAliasCertTbsEcc384Params::TCB_INFO_RT_TCI_LEN],
            not_before: &NotBefore::default().value,
            not_after: &NotAfter::default().value,
        };

        let cert = RtAliasCertTbsEcc384::new(&params);

        let sig = cert
            .sign(|b| {
                let mut sha = Sha384::new();
                sha.update(b);
                EcdsaSig::sign(&sha.finish(), &ec_key)
            })
            .unwrap();

        assert_ne!(cert.tbs(), RtAliasCertTbsEcc384::TBS_TEMPLATE);
        assert_eq!(
            &cert.tbs()[RtAliasCertTbsEcc384::PUBLIC_KEY_OFFSET
                ..RtAliasCertTbsEcc384::PUBLIC_KEY_OFFSET + RtAliasCertTbsEcc384::PUBLIC_KEY_LEN],
            params.public_key,
        );
        assert_eq!(
            &cert.tbs()[RtAliasCertTbsEcc384::SUBJECT_SN_OFFSET
                ..RtAliasCertTbsEcc384::SUBJECT_SN_OFFSET + RtAliasCertTbsEcc384::SUBJECT_SN_LEN],
            params.subject_sn,
        );
        assert_eq!(
            &cert.tbs()[RtAliasCertTbsEcc384::ISSUER_SN_OFFSET
                ..RtAliasCertTbsEcc384::ISSUER_SN_OFFSET + RtAliasCertTbsEcc384::ISSUER_SN_LEN],
            params.issuer_sn,
        );
        assert_eq!(
            &cert.tbs()[RtAliasCertTbsEcc384::UEID_OFFSET
                ..RtAliasCertTbsEcc384::UEID_OFFSET + RtAliasCertTbsEcc384::UEID_LEN],
            params.ueid,
        );
        assert_eq!(
            &cert.tbs()[RtAliasCertTbsEcc384::SUBJECT_KEY_ID_OFFSET
                ..RtAliasCertTbsEcc384::SUBJECT_KEY_ID_OFFSET
                    + RtAliasCertTbsEcc384::SUBJECT_KEY_ID_LEN],
            params.subject_key_id,
        );
        assert_eq!(
            &cert.tbs()[RtAliasCertTbsEcc384::AUTHORITY_KEY_ID_OFFSET
                ..RtAliasCertTbsEcc384::AUTHORITY_KEY_ID_OFFSET
                    + RtAliasCertTbsEcc384::AUTHORITY_KEY_ID_LEN],
            params.authority_key_id,
        );
        assert_eq!(
            &cert.tbs()[RtAliasCertTbsEcc384::TCB_INFO_RT_SVN_OFFSET
                ..RtAliasCertTbsEcc384::TCB_INFO_RT_SVN_OFFSET
                    + RtAliasCertTbsEcc384::TCB_INFO_RT_SVN_LEN],
            params.tcb_info_rt_svn,
        );
        assert_eq!(
            &cert.tbs()[RtAliasCertTbsEcc384::TCB_INFO_RT_TCI_OFFSET
                ..RtAliasCertTbsEcc384::TCB_INFO_RT_TCI_OFFSET
                    + RtAliasCertTbsEcc384::TCB_INFO_RT_TCI_LEN],
            params.tcb_info_rt_tci,
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

    #[test]
    #[cfg(feature = "generate_templates")]
    fn test_rt_alias_template() {
        let manual_template =
            std::fs::read(std::path::Path::new("./build/rt_alias_cert_tbs_ecc_384.rs")).unwrap();
        let auto_generated_template = std::fs::read(std::path::Path::new(concat!(
            env!("OUT_DIR"),
            "/rt_alias_cert_tbs_ecc_384.rs"
        )))
        .unwrap();
        if auto_generated_template != manual_template {
            panic!(
                "Auto-generated RT Alias Certificate template is not equal to the manual template."
            )
        }
    }
}
