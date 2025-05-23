/*++

Licensed under the Apache-2.0 license.

File Name:

    rt_alias_cert.rs

Abstract:

    ML-DSA87 RT Alias Certificate related code.

--*/

// Note: All the necessary code is auto generated
#[cfg(feature = "generate_templates")]
include!(concat!(env!("OUT_DIR"), "/rt_alias_cert_tbs_ml_dsa_87.rs"));
#[cfg(not(feature = "generate_templates"))]
include! {"../build/rt_alias_cert_tbs_ml_dsa_87.rs"}

#[cfg(all(test, target_family = "unix"))]
mod tests {
    use openssl::pkey_ctx::PkeyCtx;
    use openssl::pkey_ml_dsa::Variant;
    use openssl::signature::Signature;
    use openssl::x509::X509;

    use super::*;
    use crate::test_util::tests::*;
    use crate::{NotAfter, NotBefore};

    #[test]
    fn test_cert_signing() {
        let subject_key = MlDsa87AsymKey::default();
        let issuer_key = MlDsa87AsymKey::default();
        let mldsa_key = issuer_key.priv_key();

        let params = RtAliasCertTbsMlDsa87Params {
            serial_number: &[0xABu8; RtAliasCertTbsMlDsa87Params::SERIAL_NUMBER_LEN],
            public_key: TryInto::<&[u8; RtAliasCertTbsMlDsa87Params::PUBLIC_KEY_LEN]>::try_into(
                subject_key.pub_key(),
            )
            .unwrap(),
            subject_sn: &TryInto::<[u8; RtAliasCertTbsMlDsa87Params::SUBJECT_SN_LEN]>::try_into(
                subject_key.hex_str().into_bytes(),
            )
            .unwrap(),
            issuer_sn: &TryInto::<[u8; RtAliasCertTbsMlDsa87Params::ISSUER_SN_LEN]>::try_into(
                issuer_key.hex_str().into_bytes(),
            )
            .unwrap(),
            ueid: &[0xAB; RtAliasCertTbsMlDsa87Params::UEID_LEN],
            subject_key_id:
                &TryInto::<[u8; RtAliasCertTbsMlDsa87Params::SUBJECT_KEY_ID_LEN]>::try_into(
                    subject_key.sha1(),
                )
                .unwrap(),
            authority_key_id:
                &TryInto::<[u8; RtAliasCertTbsMlDsa87Params::SUBJECT_KEY_ID_LEN]>::try_into(
                    issuer_key.sha1(),
                )
                .unwrap(),
            tcb_info_fw_svn: &[0xE3],
            tcb_info_rt_tci: &[0xEFu8; RtAliasCertTbsMlDsa87Params::TCB_INFO_RT_TCI_LEN],
            not_before: &NotBefore::default().value,
            not_after: &NotAfter::default().value,
        };

        let cert = RtAliasCertTbsMlDsa87::new(&params);

        let sig = cert
            .sign(|b| {
                let mut signature = vec![];
                let mut ctx = PkeyCtx::new(mldsa_key)?;
                let mut algo = Signature::for_ml_dsa(Variant::MlDsa87)?;
                ctx.sign_message_init(&mut algo)?;
                ctx.sign_to_vec(b, &mut signature)?;
                Ok::<Vec<u8>, openssl::error::ErrorStack>(signature)
            })
            .unwrap();

        assert_ne!(cert.tbs(), RtAliasCertTbsMlDsa87::TBS_TEMPLATE);
        assert_eq!(
            &cert.tbs()[RtAliasCertTbsMlDsa87::PUBLIC_KEY_OFFSET
                ..RtAliasCertTbsMlDsa87::PUBLIC_KEY_OFFSET + RtAliasCertTbsMlDsa87::PUBLIC_KEY_LEN],
            params.public_key,
        );
        assert_eq!(
            &cert.tbs()[RtAliasCertTbsMlDsa87::SUBJECT_SN_OFFSET
                ..RtAliasCertTbsMlDsa87::SUBJECT_SN_OFFSET + RtAliasCertTbsMlDsa87::SUBJECT_SN_LEN],
            params.subject_sn,
        );
        assert_eq!(
            &cert.tbs()[RtAliasCertTbsMlDsa87::ISSUER_SN_OFFSET
                ..RtAliasCertTbsMlDsa87::ISSUER_SN_OFFSET + RtAliasCertTbsMlDsa87::ISSUER_SN_LEN],
            params.issuer_sn,
        );
        assert_eq!(
            &cert.tbs()[RtAliasCertTbsMlDsa87::UEID_OFFSET
                ..RtAliasCertTbsMlDsa87::UEID_OFFSET + RtAliasCertTbsMlDsa87::UEID_LEN],
            params.ueid,
        );
        assert_eq!(
            &cert.tbs()[RtAliasCertTbsMlDsa87::SUBJECT_KEY_ID_OFFSET
                ..RtAliasCertTbsMlDsa87::SUBJECT_KEY_ID_OFFSET
                    + RtAliasCertTbsMlDsa87::SUBJECT_KEY_ID_LEN],
            params.subject_key_id,
        );
        assert_eq!(
            &cert.tbs()[RtAliasCertTbsMlDsa87::AUTHORITY_KEY_ID_OFFSET
                ..RtAliasCertTbsMlDsa87::AUTHORITY_KEY_ID_OFFSET
                    + RtAliasCertTbsMlDsa87::AUTHORITY_KEY_ID_LEN],
            params.authority_key_id,
        );
        assert_eq!(
            &cert.tbs()[RtAliasCertTbsMlDsa87::TCB_INFO_FW_SVN_OFFSET
                ..RtAliasCertTbsMlDsa87::TCB_INFO_FW_SVN_OFFSET
                    + RtAliasCertTbsMlDsa87::TCB_INFO_FW_SVN_LEN],
            params.tcb_info_fw_svn,
        );
        assert_eq!(
            &cert.tbs()[RtAliasCertTbsMlDsa87::TCB_INFO_RT_TCI_OFFSET
                ..RtAliasCertTbsMlDsa87::TCB_INFO_RT_TCI_OFFSET
                    + RtAliasCertTbsMlDsa87::TCB_INFO_RT_TCI_LEN],
            params.tcb_info_rt_tci,
        );

        let mldsa_sig = crate::MlDsa87Signature {
            sig: sig.try_into().unwrap(),
        };

        let builder = crate::MlDsa87CertBuilder::new(cert.tbs(), &mldsa_sig).unwrap();
        let mut buf = vec![0u8; builder.len()];
        builder.build(&mut buf).unwrap();

        let cert: X509 = X509::from_der(&buf).unwrap();
        assert!(cert.verify(issuer_key.priv_key()).unwrap());
    }

    #[test]
    #[cfg(feature = "generate_templates")]
    fn test_rt_alias_template() {
        let manual_template = std::fs::read(std::path::Path::new(
            "./build/rt_alias_cert_tbs_ml_dsa_87.rs",
        ))
        .unwrap();
        let auto_generated_template = std::fs::read(std::path::Path::new(concat!(
            env!("OUT_DIR"),
            "/rt_alias_cert_tbs_ml_dsa_87.rs"
        )))
        .unwrap();
        if auto_generated_template != manual_template {
            panic!(
                "Auto-generated RT Alias Certificate template is not equal to the manual template."
            )
        }
    }
}
