/*++

Licensed under the Apache-2.0 license.

File Name:

    idevid_csr.rs

Abstract:

    Initial Device ID Certificate Signing Request related code.

--*/

// Note: All the necessary code is auto generated
include!(concat!(env!("OUT_DIR"), "/init_dev_id_csr.rs"));

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use openssl::sha::Sha384;
    use openssl::{ecdsa::EcdsaSig, x509::X509Req};

    use super::*;
    use crate::test_util::tests::*;

    #[test]
    fn test_csr_signing() {
        let key = Ecc384AsymKey::default();
        let ec_key = key.priv_key().ec_key().unwrap();

        let params = InitDevIdCsrParams {
            public_key: *TryInto::<&[u8; InitDevIdCsr::PUBLIC_KEY_LEN]>::try_into(key.pub_key())
                .unwrap(),
            subject_name: TryInto::<[u8; InitDevIdCsr::SUBJECT_NAME_LEN]>::try_into(
                key.hex_str().into_bytes(),
            )
            .unwrap(),
            device_serial_number: [0xAB; InitDevIdCsr::DEVICE_SERIAL_NUMBER_LEN],
        };

        let csr = InitDevIdCsr::new(&params);

        let sig: EcdsaSig = csr
            .sign(|b| {
                let mut sha = Sha384::new();
                sha.update(b);
                EcdsaSig::sign(&sha.finish(), &ec_key)
            })
            .unwrap();

        assert_ne!(csr.tbs(), InitDevIdCsr::TBS_TEMPLATE);
        assert_eq!(
            &csr.tbs()[InitDevIdCsr::PUBLIC_KEY_OFFSET
                ..InitDevIdCsr::PUBLIC_KEY_OFFSET + InitDevIdCsr::PUBLIC_KEY_LEN],
            &params.public_key,
        );
        assert_eq!(
            &csr.tbs()[InitDevIdCsr::SUBJECT_NAME_OFFSET
                ..InitDevIdCsr::SUBJECT_NAME_OFFSET + InitDevIdCsr::SUBJECT_NAME_LEN],
            &params.subject_name,
        );
        assert_eq!(
            &csr.tbs()[InitDevIdCsr::DEVICE_SERIAL_NUMBER_OFFSET
                ..InitDevIdCsr::DEVICE_SERIAL_NUMBER_OFFSET
                    + InitDevIdCsr::DEVICE_SERIAL_NUMBER_LEN],
            &params.device_serial_number,
        );

        let ecdsa_sig = crate::Ecdsa384Signature {
            r: TryInto::<[u8; 48]>::try_into(sig.r().to_vec_padded(48).unwrap()).unwrap(),
            s: TryInto::<[u8; 48]>::try_into(sig.s().to_vec_padded(48).unwrap()).unwrap(),
        };

        let builder = crate::Ecdsa384CsrBuilder::new(csr.tbs(), &ecdsa_sig).unwrap();
        let mut buf = vec![0u8; builder.len()];
        builder.build(&mut buf).unwrap();

        let req: X509Req = X509Req::from_der(&buf).unwrap();
        assert!(req.verify(&req.public_key().unwrap()).unwrap());
        assert!(req.verify(key.priv_key()).unwrap());
    }
}
