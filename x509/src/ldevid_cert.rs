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

    use super::*;
    use crate::test_util::tests::*;

    #[test]
    fn test_cert_signing() {
        let subject_key = Ecc384AsymKey::default();
        let issuer_key = Ecc384AsymKey::default();
        let ec_key = subject_key.priv_key().ec_key().unwrap();

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

        let csr = LocalDevIdCert::new(&params);

        let x = csr.sign(|b| EcdsaSig::sign(b, &ec_key)).unwrap();
        assert_eq!(x.r().to_hex_str().unwrap().len(), 96);
        assert_eq!(x.s().to_hex_str().unwrap().len(), 96);

        assert_ne!(csr.tbs(), LocalDevIdCert::TBS_TEMPLATE);
        assert_eq!(
            &csr.tbs()[LocalDevIdCert::PUBLIC_KEY_OFFSET
                ..LocalDevIdCert::PUBLIC_KEY_OFFSET + LocalDevIdCert::PUBLIC_KEY_LEN],
            &params.public_key,
        );
        assert_eq!(
            &csr.tbs()[LocalDevIdCert::SUBJECT_NAME_OFFSET
                ..LocalDevIdCert::SUBJECT_NAME_OFFSET + LocalDevIdCert::SUBJECT_NAME_LEN],
            &params.subject_name,
        );
        assert_eq!(
            &csr.tbs()[LocalDevIdCert::ISSUER_NAME_OFFSET
                ..LocalDevIdCert::ISSUER_NAME_OFFSET + LocalDevIdCert::ISSUER_NAME_LEN],
            &params.issuer_name,
        );
        assert_eq!(
            &csr.tbs()[LocalDevIdCert::DEVICE_SERIAL_NUMBER_OFFSET
                ..LocalDevIdCert::DEVICE_SERIAL_NUMBER_OFFSET
                    + LocalDevIdCert::DEVICE_SERIAL_NUMBER_LEN],
            &params.device_serial_number,
        );
        assert_eq!(
            &csr.tbs()[LocalDevIdCert::SUBJECT_KEY_ID_OFFSET
                ..LocalDevIdCert::SUBJECT_KEY_ID_OFFSET + LocalDevIdCert::SUBJECT_KEY_ID_LEN],
            &params.subject_key_id,
        );
        assert_eq!(
            &csr.tbs()[LocalDevIdCert::AUTHORITY_KEY_ID_OFFSET
                ..LocalDevIdCert::AUTHORITY_KEY_ID_OFFSET + LocalDevIdCert::AUTHORITY_KEY_ID_LEN],
            &params.authority_key_id,
        );
        assert_eq!(x.verify(csr.tbs(), &ec_key).unwrap(), true);
    }
}
