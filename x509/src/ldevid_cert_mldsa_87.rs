/*++

Licensed under the Apache-2.0 license.

File Name:

    ldevid_cert.rs

Abstract:

    Local Device ID Certificate related code.

--*/

// Note: All the necessary code is auto generated
#[cfg(feature = "generate_templates")]
include!(concat!(
    env!("OUT_DIR"),
    "/local_dev_id_cert_tbs_ml_dsa_87.rs"
));
#[cfg(not(feature = "generate_templates"))]
include! {"../build/local_dev_id_cert_tbs_ml_dsa_87.rs"}

#[cfg(all(test, target_family = "unix"))]
mod tests {
    use openssl::pkey_ctx::PkeyCtx;
    use openssl::pkey_ml_dsa::Variant;
    use openssl::signature::Signature;
    use openssl::x509::X509;

    use x509_parser::nom::Parser;
    use x509_parser::oid_registry::asn1_rs::oid;
    use x509_parser::oid_registry::Oid;
    use x509_parser::prelude::X509CertificateParser;
    use x509_parser::x509::X509Version;

    use super::*;
    use crate::test_util::tests::*;
    use crate::{NotAfter, NotBefore};

    const TEST_UEID: &[u8] = &[0xAB; LocalDevIdCertTbsMlDsa87Params::UEID_LEN];

    fn make_test_cert(
        subject_key: &MlDsa87AsymKey,
        issuer_key: &MlDsa87AsymKey,
    ) -> LocalDevIdCertTbsMlDsa87 {
        let params = LocalDevIdCertTbsMlDsa87Params {
            serial_number: &[0xABu8; LocalDevIdCertTbsMlDsa87Params::SERIAL_NUMBER_LEN],
            public_key: &subject_key.pub_key().try_into().unwrap(),
            subject_sn: &subject_key
                .hex_str()
                .into_bytes()
                .as_slice()
                .try_into()
                .unwrap(),
            issuer_sn: &issuer_key.hex_str().into_bytes().try_into().unwrap(),
            ueid: &TEST_UEID.try_into().unwrap(),
            subject_key_id: &subject_key.sha1(),
            authority_key_id: &issuer_key.sha1(),
            not_before: &NotBefore::default().value,
            not_after: &NotAfter::default().value,
        };

        LocalDevIdCertTbsMlDsa87::new(&params)
    }

    #[test]
    fn test_cert_signing() {
        let subject_key = MlDsa87AsymKey::default();
        let issuer_key = MlDsa87AsymKey::default();
        let mldsa_key = issuer_key.priv_key();
        let cert = make_test_cert(&subject_key, &issuer_key);

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

        assert_ne!(cert.tbs(), LocalDevIdCertTbsMlDsa87::TBS_TEMPLATE);
        assert_eq!(
            &cert.tbs()[LocalDevIdCertTbsMlDsa87::PUBLIC_KEY_OFFSET
                ..LocalDevIdCertTbsMlDsa87::PUBLIC_KEY_OFFSET
                    + LocalDevIdCertTbsMlDsa87::PUBLIC_KEY_LEN],
            subject_key.pub_key(),
        );
        assert_eq!(
            &cert.tbs()[LocalDevIdCertTbsMlDsa87::SUBJECT_SN_OFFSET
                ..LocalDevIdCertTbsMlDsa87::SUBJECT_SN_OFFSET
                    + LocalDevIdCertTbsMlDsa87::SUBJECT_SN_LEN],
            subject_key.hex_str().into_bytes(),
        );
        assert_eq!(
            &cert.tbs()[LocalDevIdCertTbsMlDsa87::ISSUER_SN_OFFSET
                ..LocalDevIdCertTbsMlDsa87::ISSUER_SN_OFFSET
                    + LocalDevIdCertTbsMlDsa87::ISSUER_SN_LEN],
            issuer_key.hex_str().into_bytes(),
        );
        assert_eq!(
            &cert.tbs()[LocalDevIdCertTbsMlDsa87::UEID_OFFSET
                ..LocalDevIdCertTbsMlDsa87::UEID_OFFSET + LocalDevIdCertTbsMlDsa87::UEID_LEN],
            TEST_UEID,
        );
        assert_eq!(
            &cert.tbs()[LocalDevIdCertTbsMlDsa87::SUBJECT_KEY_ID_OFFSET
                ..LocalDevIdCertTbsMlDsa87::SUBJECT_KEY_ID_OFFSET
                    + LocalDevIdCertTbsMlDsa87::SUBJECT_KEY_ID_LEN],
            subject_key.sha1(),
        );
        assert_eq!(
            &cert.tbs()[LocalDevIdCertTbsMlDsa87::AUTHORITY_KEY_ID_OFFSET
                ..LocalDevIdCertTbsMlDsa87::AUTHORITY_KEY_ID_OFFSET
                    + LocalDevIdCertTbsMlDsa87::AUTHORITY_KEY_ID_LEN],
            issuer_key.sha1(),
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
    fn test_extensions() {
        let subject_key = MlDsa87AsymKey::default();
        let issuer_key = MlDsa87AsymKey::default();
        let mldsa_key = issuer_key.priv_key();
        let cert = make_test_cert(&subject_key, &issuer_key);

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

        let mldsa_sig = crate::MlDsa87Signature {
            sig: sig.try_into().unwrap(),
        };

        let builder = crate::MlDsa87CertBuilder::new(cert.tbs(), &mldsa_sig).unwrap();
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

        // Check that TCG extensions are marked critical
        let ext_map = parsed_cert.extensions_map().unwrap();

        const UEID_OID: Oid = oid!(2.23.133 .5 .4 .4);
        assert!(!ext_map[&UEID_OID].critical);
    }

    #[test]
    #[cfg(feature = "generate_templates")]
    fn test_ldevid_template() {
        let manual_template = std::fs::read(std::path::Path::new(
            "./build/local_dev_id_cert_tbs_ml_dsa_87.rs",
        ))
        .unwrap();
        let auto_generated_template = std::fs::read(std::path::Path::new(concat!(
            env!("OUT_DIR"),
            "/local_dev_id_cert_tbs_ml_dsa_87.rs"
        )))
        .unwrap();
        if auto_generated_template != manual_template {
            panic!(
                "Auto-generated LDevID Certificate template is not equal to the manual template."
            )
        }
    }
}
