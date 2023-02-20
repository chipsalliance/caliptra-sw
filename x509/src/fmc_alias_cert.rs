/*++

Licensed under the Apache-2.0 license.

File Name:

    fmc_alias_cert.rs

Abstract:

    FMC Alias Certificate related code.

--*/

// Note: All the necessary code is auto generated
include!(concat!(env!("OUT_DIR"), "/fmc_alias_cert.rs"));

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

        let params = FmcAliasCertParams {
            serial_number: [0xABu8; FmcAliasCertParams::SERIAL_NUMBER_LEN],
            public_key: *TryInto::<&[u8; FmcAliasCertParams::PUBLIC_KEY_LEN]>::try_into(
                subject_key.pub_key(),
            )
            .unwrap(),
            subject_sn: TryInto::<[u8; FmcAliasCertParams::SUBJECT_SN_LEN]>::try_into(
                subject_key.hex_str().into_bytes(),
            )
            .unwrap(),
            issuer_sn: TryInto::<[u8; FmcAliasCertParams::ISSUER_SN_LEN]>::try_into(
                issuer_key.hex_str().into_bytes(),
            )
            .unwrap(),
            device_serial_number: [0xAB; FmcAliasCertParams::DEVICE_SERIAL_NUMBER_LEN],
            subject_key_id: TryInto::<[u8; FmcAliasCertParams::SUBJECT_KEY_ID_LEN]>::try_into(
                subject_key.sha1(),
            )
            .unwrap(),
            authority_key_id: TryInto::<[u8; FmcAliasCertParams::SUBJECT_KEY_ID_LEN]>::try_into(
                issuer_key.sha1(),
            )
            .unwrap(),
            tcb_info_fmc_config: [0xCDu8; FmcAliasCertParams::TCB_INFO_FMC_CONFIG_LEN],
            tcb_info_fmc_hash: [0xEFu8; FmcAliasCertParams::TCB_INFO_FMC_CONFIG_LEN],
        };

        let cert = FmcAliasCert::new(&params);

        let sig = cert
            .sign(|b| {
                let mut sha = Sha384::new();
                sha.update(b);
                EcdsaSig::sign(&sha.finish(), &ec_key)
            })
            .unwrap();

        assert_ne!(cert.tbs(), FmcAliasCert::TBS_TEMPLATE);
        assert_eq!(
            &cert.tbs()[FmcAliasCert::PUBLIC_KEY_OFFSET
                ..FmcAliasCert::PUBLIC_KEY_OFFSET + FmcAliasCert::PUBLIC_KEY_LEN],
            &params.public_key,
        );
        assert_eq!(
            &cert.tbs()[FmcAliasCert::SUBJECT_SN_OFFSET
                ..FmcAliasCert::SUBJECT_SN_OFFSET + FmcAliasCert::SUBJECT_SN_LEN],
            &params.subject_sn,
        );
        assert_eq!(
            &cert.tbs()[FmcAliasCert::ISSUER_SN_OFFSET
                ..FmcAliasCert::ISSUER_SN_OFFSET + FmcAliasCert::ISSUER_SN_LEN],
            &params.issuer_sn,
        );
        assert_eq!(
            &cert.tbs()[FmcAliasCert::DEVICE_SERIAL_NUMBER_OFFSET
                ..FmcAliasCert::DEVICE_SERIAL_NUMBER_OFFSET
                    + FmcAliasCert::DEVICE_SERIAL_NUMBER_LEN],
            &params.device_serial_number,
        );
        assert_eq!(
            &cert.tbs()[FmcAliasCert::SUBJECT_KEY_ID_OFFSET
                ..FmcAliasCert::SUBJECT_KEY_ID_OFFSET + FmcAliasCert::SUBJECT_KEY_ID_LEN],
            &params.subject_key_id,
        );
        assert_eq!(
            &cert.tbs()[FmcAliasCert::AUTHORITY_KEY_ID_OFFSET
                ..FmcAliasCert::AUTHORITY_KEY_ID_OFFSET + FmcAliasCert::AUTHORITY_KEY_ID_LEN],
            &params.authority_key_id,
        );
        assert_eq!(
            &cert.tbs()[FmcAliasCert::TCB_INFO_FMC_CONFIG_OFFSET
                ..FmcAliasCert::TCB_INFO_FMC_CONFIG_OFFSET + FmcAliasCert::TCB_INFO_FMC_CONFIG_LEN],
            &params.tcb_info_fmc_config,
        );
        assert_eq!(
            &cert.tbs()[FmcAliasCert::TCB_INFO_FMC_HASH_OFFSET
                ..FmcAliasCert::TCB_INFO_FMC_HASH_OFFSET + FmcAliasCert::TCB_INFO_FMC_HASH_LEN],
            &params.tcb_info_fmc_hash,
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
