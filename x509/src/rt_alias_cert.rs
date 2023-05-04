/*++

Licensed under the Apache-2.0 license.

File Name:

    Rt_alias_cert.rs

Abstract:

    RT Alias Certificate related code.

--*/

// Note: All the necessary code is auto generated
include!(concat!(env!("OUT_DIR"), "/rt_alias_cert_tbs.rs"));

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

        let params = RtAliasCertTbsParams {
            serial_number: &[0xABu8; RtAliasCertTbsParams::SERIAL_NUMBER_LEN],
            public_key: TryInto::<&[u8; RtAliasCertTbsParams::PUBLIC_KEY_LEN]>::try_into(
                subject_key.pub_key(),
            )
            .unwrap(),
            subject_sn: &TryInto::<[u8; RtAliasCertTbsParams::SUBJECT_SN_LEN]>::try_into(
                subject_key.hex_str().into_bytes(),
            )
            .unwrap(),
            issuer_sn: &TryInto::<[u8; RtAliasCertTbsParams::ISSUER_SN_LEN]>::try_into(
                issuer_key.hex_str().into_bytes(),
            )
            .unwrap(),
            ueid: &[0xAB; RtAliasCertTbsParams::UEID_LEN],
            subject_key_id: &TryInto::<[u8; RtAliasCertTbsParams::SUBJECT_KEY_ID_LEN]>::try_into(
                subject_key.sha1(),
            )
            .unwrap(),
            authority_key_id: &TryInto::<[u8; RtAliasCertTbsParams::SUBJECT_KEY_ID_LEN]>::try_into(
                issuer_key.sha1(),
            )
            .unwrap(),
            tcb_info_rt_svn: &[0xE3],
            tcb_info_rt_tci: &[0xEFu8; RtAliasCertTbsParams::TCB_INFO_RT_TCI_LEN],
            not_before: &NotBefore::default().not_before,
            not_after: &NotAfter::default().not_after,
        };

        let cert = RtAliasCertTbs::new(&params);

        let sig = cert
            .sign(|b| {
                let mut sha = Sha384::new();
                sha.update(b);
                EcdsaSig::sign(&sha.finish(), &ec_key)
            })
            .unwrap();

        assert_ne!(cert.tbs(), RtAliasCertTbs::TBS_TEMPLATE);
        assert_eq!(
            &cert.tbs()[RtAliasCertTbs::PUBLIC_KEY_OFFSET
                ..RtAliasCertTbs::PUBLIC_KEY_OFFSET + RtAliasCertTbs::PUBLIC_KEY_LEN],
            params.public_key,
        );
        assert_eq!(
            &cert.tbs()[RtAliasCertTbs::SUBJECT_SN_OFFSET
                ..RtAliasCertTbs::SUBJECT_SN_OFFSET + RtAliasCertTbs::SUBJECT_SN_LEN],
            params.subject_sn,
        );
        assert_eq!(
            &cert.tbs()[RtAliasCertTbs::ISSUER_SN_OFFSET
                ..RtAliasCertTbs::ISSUER_SN_OFFSET + RtAliasCertTbs::ISSUER_SN_LEN],
            params.issuer_sn,
        );
        assert_eq!(
            &cert.tbs()[RtAliasCertTbs::UEID_OFFSET
                ..RtAliasCertTbs::UEID_OFFSET + RtAliasCertTbs::UEID_LEN],
            params.ueid,
        );
        assert_eq!(
            &cert.tbs()[RtAliasCertTbs::SUBJECT_KEY_ID_OFFSET
                ..RtAliasCertTbs::SUBJECT_KEY_ID_OFFSET + RtAliasCertTbs::SUBJECT_KEY_ID_LEN],
            params.subject_key_id,
        );
        assert_eq!(
            &cert.tbs()[RtAliasCertTbs::AUTHORITY_KEY_ID_OFFSET
                ..RtAliasCertTbs::AUTHORITY_KEY_ID_OFFSET + RtAliasCertTbs::AUTHORITY_KEY_ID_LEN],
            params.authority_key_id,
        );
        assert_eq!(
            &cert.tbs()[RtAliasCertTbs::TCB_INFO_RT_SVN_OFFSET
                ..RtAliasCertTbs::TCB_INFO_RT_SVN_OFFSET + RtAliasCertTbs::TCB_INFO_RT_SVN_LEN],
            params.tcb_info_rt_svn,
        );
        assert_eq!(
            &cert.tbs()[RtAliasCertTbs::TCB_INFO_RT_TCI_OFFSET
                ..RtAliasCertTbs::TCB_INFO_RT_TCI_OFFSET + RtAliasCertTbs::TCB_INFO_RT_TCI_LEN],
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
}
