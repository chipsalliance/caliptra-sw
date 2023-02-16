/*++

Licensed under the Apache-2.0 license.

File Name:

    ldevid_cert.rs

Abstract:

    Local Device ID Certificate related code.

--*/

// Note: All the necessary code is auto generated
include!(concat!(env!("OUT_DIR"), "/local_dev_id_cert.rs"));

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use openssl::ecdsa::EcdsaSig;
    use openssl::sha::Sha384;
    use openssl::x509::X509;

    use super::*;
    use crate::test_util::tests::*;

    #[test]
    fn test_cert_signing() {
        let subject_key = Ecc384AsymKey::default();
        let issuer_key = Ecc384AsymKey::default();
        let ec_key = issuer_key.priv_key().ec_key().unwrap();

        let params = LocalDevIdCertParams {
            serial_number: [0xABu8; LocalDevIdCertParams::SERIAL_NUMBER_LEN],
            public_key: *TryInto::<&[u8; LocalDevIdCertParams::PUBLIC_KEY_LEN]>::try_into(
                subject_key.pub_key(),
            )
            .unwrap(),
            subject_name: TryInto::<[u8; LocalDevIdCertParams::SUBJECT_NAME_LEN]>::try_into(
                subject_key.hex_str().into_bytes(),
            )
            .unwrap(),
            issuer_name: TryInto::<[u8; LocalDevIdCertParams::SUBJECT_NAME_LEN]>::try_into(
                issuer_key.hex_str().into_bytes(),
            )
            .unwrap(),
            device_serial_number: [0xAB; LocalDevIdCertParams::DEVICE_SERIAL_NUMBER_LEN],
            subject_key_id: TryInto::<[u8; LocalDevIdCertParams::SUBJECT_KEY_ID_LEN]>::try_into(
                subject_key.sha1(),
            )
            .unwrap(),
            authority_key_id: TryInto::<[u8; LocalDevIdCertParams::SUBJECT_KEY_ID_LEN]>::try_into(
                issuer_key.sha1(),
            )
            .unwrap(),
        };

        let cert = LocalDevIdCert::new(&params);

        let sig = cert
            .sign(|b| {
                let mut sha = Sha384::new();
                sha.update(b);
                EcdsaSig::sign(&sha.finish(), &ec_key)
            })
            .unwrap();
        assert_eq!(sig.r().to_hex_str().unwrap().len(), 96);
        assert_eq!(sig.s().to_hex_str().unwrap().len(), 96);

        assert_ne!(cert.tbs(), LocalDevIdCert::TBS_TEMPLATE);
        assert_eq!(
            &cert.tbs()[LocalDevIdCert::PUBLIC_KEY_OFFSET
                ..LocalDevIdCert::PUBLIC_KEY_OFFSET + LocalDevIdCert::PUBLIC_KEY_LEN],
            &params.public_key,
        );
        assert_eq!(
            &cert.tbs()[LocalDevIdCert::SUBJECT_NAME_OFFSET
                ..LocalDevIdCert::SUBJECT_NAME_OFFSET + LocalDevIdCert::SUBJECT_NAME_LEN],
            &params.subject_name,
        );
        assert_eq!(
            &cert.tbs()[LocalDevIdCert::ISSUER_NAME_OFFSET
                ..LocalDevIdCert::ISSUER_NAME_OFFSET + LocalDevIdCert::ISSUER_NAME_LEN],
            &params.issuer_name,
        );
        assert_eq!(
            &cert.tbs()[LocalDevIdCert::DEVICE_SERIAL_NUMBER_OFFSET
                ..LocalDevIdCert::DEVICE_SERIAL_NUMBER_OFFSET
                    + LocalDevIdCert::DEVICE_SERIAL_NUMBER_LEN],
            &params.device_serial_number,
        );
        assert_eq!(
            &cert.tbs()[LocalDevIdCert::SUBJECT_KEY_ID_OFFSET
                ..LocalDevIdCert::SUBJECT_KEY_ID_OFFSET + LocalDevIdCert::SUBJECT_KEY_ID_LEN],
            &params.subject_key_id,
        );
        assert_eq!(
            &cert.tbs()[LocalDevIdCert::AUTHORITY_KEY_ID_OFFSET
                ..LocalDevIdCert::AUTHORITY_KEY_ID_OFFSET + LocalDevIdCert::AUTHORITY_KEY_ID_LEN],
            &params.authority_key_id,
        );

        let ecdsa_sig = crate::Ecdsa384Signature {
            r: TryInto::<[u8; 48]>::try_into(sig.r().to_vec()).unwrap(),
            s: TryInto::<[u8; 48]>::try_into(sig.s().to_vec()).unwrap(),
        };

        let builder = crate::Ecdsa384CertBuilder::new(cert.tbs(), &ecdsa_sig).unwrap();
        let mut buf = vec![0u8; builder.len()];
        builder.build(&mut buf).unwrap();

        let cert: X509 = X509::from_der(&buf).unwrap();
        assert!(cert.verify(issuer_key.priv_key()).unwrap());
    }
}
