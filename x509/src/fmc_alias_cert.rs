/*++

Licensed under the Apache-2.0 license.

File Name:

    fmc_alias_cert.rs

Abstract:

    FMC Alias Certificate related code.

--*/

// Note: All the necessary code is auto generated
#[cfg(feature = "generate_templates")]
include!(concat!(env!("OUT_DIR"), "/fmc_alias_cert_tbs.rs"));
#[cfg(not(feature = "generate_templates"))]
include! {"../build/fmc_alias_cert_tbs.rs"}

#[cfg(all(test, target_family = "unix"))]
mod tests {
    use super::*;
    use crate::test_util::tests::*;
    use crate::{Ecdsa384CertBuilder, Ecdsa384Signature, NotAfter, NotBefore};

    use openssl::ecdsa::EcdsaSig;
    use openssl::sha::Sha384;
    use openssl::x509::X509;

    use x509_parser::nom::Parser;
    use x509_parser::oid_registry::asn1_rs::oid;
    use x509_parser::oid_registry::Oid;
    use x509_parser::prelude::X509CertificateParser;
    use x509_parser::x509::X509Version;

    const TEST_DEVICE_INFO_HASH: &[u8] =
        &[0xCDu8; FmcAliasCertTbsParams::TCB_INFO_DEVICE_INFO_HASH_LEN];
    const TEST_FMC_HASH: &[u8] = &[0xEFu8; FmcAliasCertTbsParams::TCB_INFO_FMC_TCI_LEN];
    const TEST_UEID: &[u8] = &[0xABu8; FmcAliasCertTbsParams::UEID_LEN];
    const TEST_TCB_INFO_FLAGS: &[u8] = &[0xB0, 0xB1, 0xB2, 0xB3];
    const TEST_TCB_INFO_FW_SVN: &[u8] = &[0xB7];
    const TEST_TCB_INFO_FW_SVN_FUSES: &[u8] = &[0xB8];

    fn make_test_cert(subject_key: &Ecc384AsymKey, issuer_key: &Ecc384AsymKey) -> FmcAliasCertTbs {
        let params = FmcAliasCertTbsParams {
            serial_number: &[0xABu8; FmcAliasCertTbsParams::SERIAL_NUMBER_LEN],
            public_key: &subject_key.pub_key().try_into().unwrap(),
            subject_sn: &subject_key
                .hex_str()
                .into_bytes()
                .as_slice()
                .try_into()
                .unwrap(),
            issuer_sn: &issuer_key
                .hex_str()
                .into_bytes()
                .as_slice()
                .try_into()
                .unwrap(),
            ueid: TEST_UEID.try_into().unwrap(),
            subject_key_id: &subject_key.sha1(),
            authority_key_id: &issuer_key.sha1(),
            tcb_info_flags: TEST_TCB_INFO_FLAGS.try_into().unwrap(),
            tcb_info_device_info_hash: &TEST_DEVICE_INFO_HASH.try_into().unwrap(),
            tcb_info_fmc_tci: &TEST_FMC_HASH.try_into().unwrap(),
            tcb_info_fw_svn: &TEST_TCB_INFO_FW_SVN.try_into().unwrap(),
            tcb_info_fw_svn_fuses: &TEST_TCB_INFO_FW_SVN_FUSES.try_into().unwrap(),
            not_before: &NotBefore::default().value,
            not_after: &NotAfter::default().value,
        };

        FmcAliasCertTbs::new(&params)
    }

    #[test]
    fn test_cert_signing() {
        let subject_key = Ecc384AsymKey::default();
        let issuer_key = Ecc384AsymKey::default();
        let cert = make_test_cert(&subject_key, &issuer_key);

        let ec_key = issuer_key.priv_key().ec_key().unwrap();
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
            subject_key.pub_key(),
        );
        assert_eq!(
            &cert.tbs()[FmcAliasCertTbs::SUBJECT_SN_OFFSET
                ..FmcAliasCertTbs::SUBJECT_SN_OFFSET + FmcAliasCertTbs::SUBJECT_SN_LEN],
            subject_key.hex_str().into_bytes(),
        );
        assert_eq!(
            &cert.tbs()[FmcAliasCertTbs::ISSUER_SN_OFFSET
                ..FmcAliasCertTbs::ISSUER_SN_OFFSET + FmcAliasCertTbs::ISSUER_SN_LEN],
            issuer_key.hex_str().into_bytes(),
        );
        assert_eq!(
            &cert.tbs()[FmcAliasCertTbs::UEID_OFFSET
                ..FmcAliasCertTbs::UEID_OFFSET + FmcAliasCertTbs::UEID_LEN],
            TEST_UEID,
        );
        assert_eq!(
            &cert.tbs()[FmcAliasCertTbs::SUBJECT_KEY_ID_OFFSET
                ..FmcAliasCertTbs::SUBJECT_KEY_ID_OFFSET + FmcAliasCertTbs::SUBJECT_KEY_ID_LEN],
            subject_key.sha1(),
        );
        assert_eq!(
            &cert.tbs()[FmcAliasCertTbs::AUTHORITY_KEY_ID_OFFSET
                ..FmcAliasCertTbs::AUTHORITY_KEY_ID_OFFSET + FmcAliasCertTbs::AUTHORITY_KEY_ID_LEN],
            issuer_key.sha1(),
        );
        assert_eq!(
            &cert.tbs()[FmcAliasCertTbs::TCB_INFO_FLAGS_OFFSET
                ..FmcAliasCertTbs::TCB_INFO_FLAGS_OFFSET + FmcAliasCertTbs::TCB_INFO_FLAGS_LEN],
            TEST_TCB_INFO_FLAGS,
        );
        assert_eq!(
            &cert.tbs()[FmcAliasCertTbs::TCB_INFO_DEVICE_INFO_HASH_OFFSET
                ..FmcAliasCertTbs::TCB_INFO_DEVICE_INFO_HASH_OFFSET
                    + FmcAliasCertTbs::TCB_INFO_DEVICE_INFO_HASH_LEN],
            TEST_DEVICE_INFO_HASH,
        );
        assert_eq!(
            &cert.tbs()[FmcAliasCertTbs::TCB_INFO_FMC_TCI_OFFSET
                ..FmcAliasCertTbs::TCB_INFO_FMC_TCI_OFFSET + FmcAliasCertTbs::TCB_INFO_FMC_TCI_LEN],
            TEST_FMC_HASH,
        );
        assert_eq!(
            &cert.tbs()[FmcAliasCertTbs::TCB_INFO_FW_SVN_OFFSET
                ..FmcAliasCertTbs::TCB_INFO_FW_SVN_OFFSET + FmcAliasCertTbs::TCB_INFO_FW_SVN_LEN],
            TEST_TCB_INFO_FW_SVN,
        );
        assert_eq!(
            &cert.tbs()[FmcAliasCertTbs::TCB_INFO_FW_SVN_FUSES_OFFSET
                ..FmcAliasCertTbs::TCB_INFO_FW_SVN_FUSES_OFFSET
                    + FmcAliasCertTbs::TCB_INFO_FW_SVN_FUSES_LEN],
            TEST_TCB_INFO_FW_SVN_FUSES,
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
    fn test_extensions() {
        let subject_key = Ecc384AsymKey::default();
        let issuer_key = Ecc384AsymKey::default();
        let cert = make_test_cert(&subject_key, &issuer_key);

        let ec_key = issuer_key.priv_key().ec_key().unwrap();
        let sig = cert
            .sign(|b| {
                let mut sha = Sha384::new();
                sha.update(b);
                EcdsaSig::sign(&sha.finish(), &ec_key)
            })
            .unwrap();

        let ecdsa_sig = Ecdsa384Signature {
            r: sig.r().to_vec_padded(48).unwrap().try_into().unwrap(),
            s: sig.s().to_vec_padded(48).unwrap().try_into().unwrap(),
        };

        let builder = Ecdsa384CertBuilder::new(cert.tbs(), &ecdsa_sig).unwrap();
        let mut buf = vec![0u8; builder.len()];
        builder.build(&mut buf).unwrap();

        let mut parser = X509CertificateParser::new().with_deep_parse_extensions(true);
        let parsed_cert = match parser.parse(&buf) {
            Ok((_, parsed_cert)) => parsed_cert,
            Err(e) => panic!("x509 parsing failed: {:?}", e),
        };

        assert_eq!(parsed_cert.version(), X509Version::V3);

        // Basic checks on standard extensions
        let basic_constraints = parsed_cert.basic_constraints().unwrap().unwrap();
        assert!(basic_constraints.critical);
        assert!(basic_constraints.value.ca);

        let key_usage = parsed_cert.key_usage().unwrap().unwrap();
        assert!(key_usage.critical);

        // Check that TCG extensions are present
        let ext_map = parsed_cert.extensions_map().unwrap();

        const UEID_OID: Oid = oid!(2.23.133 .5 .4 .4);
        assert!(!ext_map[&UEID_OID].critical);

        const MULTI_TCB_INFO_OID: Oid = oid!(2.23.133 .5 .4 .5);
        assert!(!ext_map[&MULTI_TCB_INFO_OID].critical);
    }

    #[test]
    #[cfg(feature = "generate_templates")]
    fn test_fmc_alias_template() {
        let manual_template =
            std::fs::read(std::path::Path::new("./build/fmc_alias_cert_tbs.rs")).unwrap();
        let auto_generated_template = std::fs::read(std::path::Path::new(concat!(
            env!("OUT_DIR"),
            "/fmc_alias_cert_tbs.rs"
        )))
        .unwrap();
        if auto_generated_template != manual_template {
            panic!(
                "Auto-generated FMC Alias Certificate template is not equal to the manual template."
            )
        }
    }
}
