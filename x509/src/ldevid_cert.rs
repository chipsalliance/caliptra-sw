/*++

Licensed under the Apache-2.0 license.

File Name:

    ldevid_cert.rs

Abstract:

    Local Device ID Certificate related code.

--*/

// Note: All the necessary code is auto generated
include!(concat!(env!("OUT_DIR"), "/local_dev_id_cert_tbs.rs"));

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

        let params = LocalDevIdCertTbsParams {
            serial_number: &[0xABu8; LocalDevIdCertTbsParams::SERIAL_NUMBER_LEN],
            public_key: TryInto::<&[u8; LocalDevIdCertTbsParams::PUBLIC_KEY_LEN]>::try_into(
                subject_key.pub_key(),
            )
            .unwrap(),
            subject_sn: &TryInto::<[u8; LocalDevIdCertTbsParams::SUBJECT_SN_LEN]>::try_into(
                subject_key.hex_str().into_bytes(),
            )
            .unwrap(),
            issuer_sn: &TryInto::<[u8; LocalDevIdCertTbsParams::ISSUER_SN_LEN]>::try_into(
                issuer_key.hex_str().into_bytes(),
            )
            .unwrap(),
            ueid: &[0xAB; LocalDevIdCertTbsParams::UEID_LEN],
            subject_key_id:
                &TryInto::<[u8; LocalDevIdCertTbsParams::SUBJECT_KEY_ID_LEN]>::try_into(
                    subject_key.sha1(),
                )
                .unwrap(),
            authority_key_id:
                &TryInto::<[u8; LocalDevIdCertTbsParams::SUBJECT_KEY_ID_LEN]>::try_into(
                    issuer_key.sha1(),
                )
                .unwrap(),
            not_before: &NotBefore::default().not_before,
            not_after: &NotAfter::default().not_after,
        };

        let cert = LocalDevIdCertTbs::new(&params);

        let sig = cert
            .sign(|b| {
                let mut sha = Sha384::new();
                sha.update(b);
                EcdsaSig::sign(&sha.finish(), &ec_key)
            })
            .unwrap();

        assert_ne!(cert.tbs(), LocalDevIdCertTbs::TBS_TEMPLATE);
        assert_eq!(
            &cert.tbs()[LocalDevIdCertTbs::PUBLIC_KEY_OFFSET
                ..LocalDevIdCertTbs::PUBLIC_KEY_OFFSET + LocalDevIdCertTbs::PUBLIC_KEY_LEN],
            params.public_key,
        );
        assert_eq!(
            &cert.tbs()[LocalDevIdCertTbs::SUBJECT_SN_OFFSET
                ..LocalDevIdCertTbs::SUBJECT_SN_OFFSET + LocalDevIdCertTbs::SUBJECT_SN_LEN],
            params.subject_sn,
        );
        assert_eq!(
            &cert.tbs()[LocalDevIdCertTbs::ISSUER_SN_OFFSET
                ..LocalDevIdCertTbs::ISSUER_SN_OFFSET + LocalDevIdCertTbs::ISSUER_SN_LEN],
            params.issuer_sn,
        );
        assert_eq!(
            &cert.tbs()[LocalDevIdCertTbs::UEID_OFFSET
                ..LocalDevIdCertTbs::UEID_OFFSET + LocalDevIdCertTbs::UEID_LEN],
            params.ueid,
        );
        assert_eq!(
            &cert.tbs()[LocalDevIdCertTbs::SUBJECT_KEY_ID_OFFSET
                ..LocalDevIdCertTbs::SUBJECT_KEY_ID_OFFSET + LocalDevIdCertTbs::SUBJECT_KEY_ID_LEN],
            params.subject_key_id,
        );
        assert_eq!(
            &cert.tbs()[LocalDevIdCertTbs::AUTHORITY_KEY_ID_OFFSET
                ..LocalDevIdCertTbs::AUTHORITY_KEY_ID_OFFSET
                    + LocalDevIdCertTbs::AUTHORITY_KEY_ID_LEN],
            params.authority_key_id,
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
