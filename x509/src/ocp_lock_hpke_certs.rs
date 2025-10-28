// Licensed under the Apache-2.0 license

pub mod ml_kem_ecc_348 {

    #[cfg(feature = "generate_templates")]
    include!(concat!(
        env!("OUT_DIR"),
        "/ocp_lock_ml_kem_cert_tbs_ecc_384.rs"
    ));
    #[cfg(not(feature = "generate_templates"))]
    include! {"../build/ocp_lock_ml_kem_cert_tbs_ecc_384.rs"}

    #[cfg(all(test, target_family = "unix"))]
    mod tests {
        use openssl::ecdsa::EcdsaSig;
        use openssl::sha::Sha384;
        use openssl::x509::X509;
        use x509_parser::nom::Parser;
        use x509_parser::oid_registry::asn1_rs::oid;
        use x509_parser::oid_registry::Oid;
        use x509_parser::prelude::X509CertificateParser;
        use x509_parser::x509::X509Version;

        use super::*;
        use crate::test_util::tests::*;
        use crate::{NotAfter, NotBefore};

        #[test]
        fn test_cert() {
            let subject_key = MlKem1024AsymKey::default();
            let issuer_key = Ecc384AsymKey::default();
            let ec_key = issuer_key.priv_key().ec_key().unwrap();
            let params = OcpLockMlKemCertTbsEcc384Params {
                serial_number: &[0xABu8; OcpLockMlKemCertTbsEcc384Params::SERIAL_NUMBER_LEN],
                public_key:
                    TryInto::<&[u8; OcpLockMlKemCertTbsEcc384Params::PUBLIC_KEY_LEN]>::try_into(
                        subject_key.pub_key(),
                    )
                    .unwrap(),
                subject_sn:
                    &TryInto::<[u8; OcpLockMlKemCertTbsEcc384Params::SUBJECT_SN_LEN]>::try_into(
                        subject_key.hex_str().into_bytes(),
                    )
                    .unwrap(),
                issuer_sn:
                    &TryInto::<[u8; OcpLockMlKemCertTbsEcc384Params::ISSUER_SN_LEN]>::try_into(
                        issuer_key.hex_str().into_bytes(),
                    )
                    .unwrap(),
                subject_key_id:
                    &TryInto::<[u8; OcpLockMlKemCertTbsEcc384Params::SUBJECT_KEY_ID_LEN]>::try_into(
                        subject_key.sha1(),
                    )
                    .unwrap(),
                authority_key_id: &TryInto::<
                    [u8; OcpLockMlKemCertTbsEcc384Params::AUTHORITY_KEY_ID_LEN],
                >::try_into(issuer_key.sha1())
                .unwrap(),
                not_before: &NotBefore::default().value,
                not_after: &NotAfter::default().value,
            };

            let cert = OcpLockMlKemCertTbsEcc384::new(&params);

            let sig = cert
                .sign(|b| {
                    let mut sha = Sha384::new();
                    sha.update(b);
                    EcdsaSig::sign(&sha.finish(), &ec_key)
                })
                .unwrap();

            assert_ne!(cert.tbs(), OcpLockMlKemCertTbsEcc384::TBS_TEMPLATE);
            assert_eq!(
                &cert.tbs()[OcpLockMlKemCertTbsEcc384::PUBLIC_KEY_OFFSET
                    ..OcpLockMlKemCertTbsEcc384::PUBLIC_KEY_OFFSET
                        + OcpLockMlKemCertTbsEcc384::PUBLIC_KEY_LEN],
                params.public_key,
            );
            assert_eq!(
                &cert.tbs()[OcpLockMlKemCertTbsEcc384::SUBJECT_SN_OFFSET
                    ..OcpLockMlKemCertTbsEcc384::SUBJECT_SN_OFFSET
                        + OcpLockMlKemCertTbsEcc384::SUBJECT_SN_LEN],
                params.subject_sn,
            );
            assert_eq!(
                &cert.tbs()[OcpLockMlKemCertTbsEcc384::ISSUER_SN_OFFSET
                    ..OcpLockMlKemCertTbsEcc384::ISSUER_SN_OFFSET
                        + OcpLockMlKemCertTbsEcc384::ISSUER_SN_LEN],
                params.issuer_sn,
            );
            assert_eq!(
                &cert.tbs()[OcpLockMlKemCertTbsEcc384::SUBJECT_KEY_ID_OFFSET
                    ..OcpLockMlKemCertTbsEcc384::SUBJECT_KEY_ID_OFFSET
                        + OcpLockMlKemCertTbsEcc384::SUBJECT_KEY_ID_LEN],
                params.subject_key_id,
            );
            assert_eq!(
                &cert.tbs()[OcpLockMlKemCertTbsEcc384::AUTHORITY_KEY_ID_OFFSET
                    ..OcpLockMlKemCertTbsEcc384::AUTHORITY_KEY_ID_OFFSET
                        + OcpLockMlKemCertTbsEcc384::AUTHORITY_KEY_ID_LEN],
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

            let mut parser = X509CertificateParser::new().with_deep_parse_extensions(true);
            let parsed_cert = match parser.parse(&buf) {
                Ok((_, parsed_cert)) => parsed_cert,
                Err(e) => panic!("x509 parsing failed: {:?}", e),
            };

            assert_eq!(parsed_cert.version(), X509Version::V3);
            let basic_constraints = parsed_cert.basic_constraints().unwrap().unwrap();
            assert!(basic_constraints.critical);
            assert!(!basic_constraints.value.ca);

            // Check key usage. OCP LOCK HPKE certs should only allow key encipherment
            let key_usage = parsed_cert.key_usage().unwrap().unwrap();
            assert!(key_usage.critical);
            assert!(key_usage.value.key_encipherment());
            assert!(!key_usage.value.key_cert_sign());
            assert!(!key_usage.value.digital_signature());

            // Check that HPKE Identifiers extension is present
            let ext_map = parsed_cert.extensions_map().unwrap();
            const HPKE_IDENTIFIERS_OID: Oid = oid!(2.23.133 .21 .1 .1);
            assert!(!ext_map[&HPKE_IDENTIFIERS_OID].critical);
        }

        #[test]
        #[cfg(feature = "generate_templates")]
        fn test_ocp_lock_mlkem_ecc384_template() {
            let manual_template = std::fs::read(std::path::Path::new(
                "./build/ocp_lock_ml_kem_cert_tbs_ecc_384.rs",
            ))
            .unwrap();
            let auto_generated_template = std::fs::read(std::path::Path::new(concat!(
                env!("OUT_DIR"),
                "/ocp_lock_ml_kem_cert_tbs_ecc_384.rs"
            )))
            .unwrap();
            if auto_generated_template != manual_template {
                panic!(
                "Auto-generated OCP LOCK ML-KEM 1024 EC Certificate template is not equal to the manual template."
            )
            }
        }
    }
}

pub mod ml_kem_mldsa_87 {

    #[cfg(feature = "generate_templates")]
    include!(concat!(
        env!("OUT_DIR"),
        "/ocp_lock_ml_kem_cert_tbs_ml_dsa_87.rs"
    ));
    #[cfg(not(feature = "generate_templates"))]
    include! {"../build/ocp_lock_ml_kem_cert_tbs_ml_dsa_87.rs"}

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

        #[test]
        fn test_cert() {
            let subject_key = MlKem1024AsymKey::default();
            let issuer_key = MlDsa87AsymKey::default();
            let mldsa_key = issuer_key.priv_key();

            let params = OcpLockMlKemCertTbsMlDsa87Params {
                serial_number: &[0xABu8; OcpLockMlKemCertTbsMlDsa87Params::SERIAL_NUMBER_LEN],
                public_key:
                    TryInto::<&[u8; OcpLockMlKemCertTbsMlDsa87Params::PUBLIC_KEY_LEN]>::try_into(
                        subject_key.pub_key(),
                    )
                    .unwrap(),
                subject_sn:
                    &TryInto::<[u8; OcpLockMlKemCertTbsMlDsa87Params::SUBJECT_SN_LEN]>::try_into(
                        subject_key.hex_str().into_bytes(),
                    )
                    .unwrap(),
                issuer_sn:
                    &TryInto::<[u8; OcpLockMlKemCertTbsMlDsa87Params::ISSUER_SN_LEN]>::try_into(
                        issuer_key.hex_str().into_bytes(),
                    )
                    .unwrap(),
                subject_key_id: &TryInto::<
                    [u8; OcpLockMlKemCertTbsMlDsa87Params::SUBJECT_KEY_ID_LEN],
                >::try_into(subject_key.sha1())
                .unwrap(),
                authority_key_id: &TryInto::<
                    [u8; OcpLockMlKemCertTbsMlDsa87Params::AUTHORITY_KEY_ID_LEN],
                >::try_into(issuer_key.sha1())
                .unwrap(),
                not_before: &NotBefore::default().value,
                not_after: &NotAfter::default().value,
            };

            let cert = OcpLockMlKemCertTbsMlDsa87::new(&params);

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

            assert_ne!(cert.tbs(), OcpLockMlKemCertTbsMlDsa87::TBS_TEMPLATE);
            assert_eq!(
                &cert.tbs()[OcpLockMlKemCertTbsMlDsa87::PUBLIC_KEY_OFFSET
                    ..OcpLockMlKemCertTbsMlDsa87::PUBLIC_KEY_OFFSET
                        + OcpLockMlKemCertTbsMlDsa87::PUBLIC_KEY_LEN],
                params.public_key,
            );
            assert_eq!(
                &cert.tbs()[OcpLockMlKemCertTbsMlDsa87::SUBJECT_SN_OFFSET
                    ..OcpLockMlKemCertTbsMlDsa87::SUBJECT_SN_OFFSET
                        + OcpLockMlKemCertTbsMlDsa87::SUBJECT_SN_LEN],
                params.subject_sn,
            );
            assert_eq!(
                &cert.tbs()[OcpLockMlKemCertTbsMlDsa87::ISSUER_SN_OFFSET
                    ..OcpLockMlKemCertTbsMlDsa87::ISSUER_SN_OFFSET
                        + OcpLockMlKemCertTbsMlDsa87::ISSUER_SN_LEN],
                params.issuer_sn,
            );
            assert_eq!(
                &cert.tbs()[OcpLockMlKemCertTbsMlDsa87::SUBJECT_KEY_ID_OFFSET
                    ..OcpLockMlKemCertTbsMlDsa87::SUBJECT_KEY_ID_OFFSET
                        + OcpLockMlKemCertTbsMlDsa87::SUBJECT_KEY_ID_LEN],
                params.subject_key_id,
            );
            assert_eq!(
                &cert.tbs()[OcpLockMlKemCertTbsMlDsa87::AUTHORITY_KEY_ID_OFFSET
                    ..OcpLockMlKemCertTbsMlDsa87::AUTHORITY_KEY_ID_OFFSET
                        + OcpLockMlKemCertTbsMlDsa87::AUTHORITY_KEY_ID_LEN],
                params.authority_key_id,
            );

            let mldsa_sig = crate::MlDsa87Signature {
                sig: sig.try_into().unwrap(),
            };

            let builder = crate::MlDsa87CertBuilder::new(cert.tbs(), &mldsa_sig).unwrap();
            let mut buf = vec![0u8; builder.len()];
            builder.build(&mut buf).unwrap();

            let cert: X509 = X509::from_der(&buf).unwrap();
            assert!(cert.verify(issuer_key.priv_key()).unwrap());

            let mut parser = X509CertificateParser::new().with_deep_parse_extensions(true);
            let parsed_cert = match parser.parse(&buf) {
                Ok((_, parsed_cert)) => parsed_cert,
                Err(e) => panic!("x509 parsing failed: {:?}", e),
            };

            assert_eq!(parsed_cert.version(), X509Version::V3);
            let basic_constraints = parsed_cert.basic_constraints().unwrap().unwrap();
            assert!(basic_constraints.critical);
            assert!(!basic_constraints.value.ca);

            // Check key usage. OCP LOCK HPKE certs should only allow key encipherment
            let key_usage = parsed_cert.key_usage().unwrap().unwrap();
            assert!(key_usage.critical);
            assert!(key_usage.value.key_encipherment());
            assert!(!key_usage.value.key_cert_sign());
            assert!(!key_usage.value.digital_signature());

            // Check that HPKE Identifiers extension is present
            let ext_map = parsed_cert.extensions_map().unwrap();
            const HPKE_IDENTIFIERS_OID: Oid = oid!(2.23.133 .21 .1 .1);
            assert!(!ext_map[&HPKE_IDENTIFIERS_OID].critical);
        }

        #[test]
        #[cfg(feature = "generate_templates")]
        fn test_ocp_lock_mlkem_mldsa87_template() {
            let manual_template = std::fs::read(std::path::Path::new(
                "./build/ocp_lock_ml_kem_cert_tbs_ml_dsa_87.rs",
            ))
            .unwrap();
            let auto_generated_template = std::fs::read(std::path::Path::new(concat!(
                env!("OUT_DIR"),
                "/ocp_lock_ml_kem_cert_tbs_ml_dsa_87.rs"
            )))
            .unwrap();
            if auto_generated_template != manual_template {
                panic!(
                "Auto-generated OCP LOCK ML-KEM 1024 ML-DSA Certificate template is not equal to the manual template."
            )
            }
        }
    }
}

pub mod ecdh_384_ecc_348 {

    #[cfg(feature = "generate_templates")]
    include!(concat!(
        env!("OUT_DIR"),
        "/ocp_lock_ecdh_384_cert_tbs_ecc_384.rs"
    ));
    #[cfg(not(feature = "generate_templates"))]
    include! {"../build/ocp_lock_ecdh_384_cert_tbs_ecc_384.rs"}

    #[cfg(all(test, target_family = "unix"))]
    mod tests {
        use openssl::ecdsa::EcdsaSig;
        use openssl::sha::Sha384;
        use openssl::x509::X509;
        use x509_parser::nom::Parser;
        use x509_parser::oid_registry::asn1_rs::oid;
        use x509_parser::oid_registry::Oid;
        use x509_parser::prelude::X509CertificateParser;
        use x509_parser::x509::X509Version;

        use super::*;
        use crate::test_util::tests::*;
        use crate::{NotAfter, NotBefore};

        #[test]
        fn test_cert() {
            let subject_key = Ecc384AsymKey::default();
            let issuer_key = Ecc384AsymKey::default();
            let ec_key = issuer_key.priv_key().ec_key().unwrap();
            let params = OcpLockEcdh384CertTbsEcc384Params {
                serial_number: &[0xABu8; OcpLockEcdh384CertTbsEcc384Params::SERIAL_NUMBER_LEN],
                public_key:
                    TryInto::<&[u8; OcpLockEcdh384CertTbsEcc384Params::PUBLIC_KEY_LEN]>::try_into(
                        subject_key.pub_key(),
                    )
                    .unwrap(),
                subject_sn:
                    &TryInto::<[u8; OcpLockEcdh384CertTbsEcc384Params::SUBJECT_SN_LEN]>::try_into(
                        subject_key.hex_str().into_bytes(),
                    )
                    .unwrap(),
                issuer_sn:
                    &TryInto::<[u8; OcpLockEcdh384CertTbsEcc384Params::ISSUER_SN_LEN]>::try_into(
                        issuer_key.hex_str().into_bytes(),
                    )
                    .unwrap(),
                subject_key_id: &TryInto::<
                    [u8; OcpLockEcdh384CertTbsEcc384Params::SUBJECT_KEY_ID_LEN],
                >::try_into(subject_key.sha1())
                .unwrap(),
                authority_key_id: &TryInto::<
                    [u8; OcpLockEcdh384CertTbsEcc384Params::AUTHORITY_KEY_ID_LEN],
                >::try_into(issuer_key.sha1())
                .unwrap(),
                not_before: &NotBefore::default().value,
                not_after: &NotAfter::default().value,
            };

            let cert = OcpLockEcdh384CertTbsEcc384::new(&params);

            let sig = cert
                .sign(|b| {
                    let mut sha = Sha384::new();
                    sha.update(b);
                    EcdsaSig::sign(&sha.finish(), &ec_key)
                })
                .unwrap();

            assert_ne!(cert.tbs(), OcpLockEcdh384CertTbsEcc384::TBS_TEMPLATE);
            assert_eq!(
                &cert.tbs()[OcpLockEcdh384CertTbsEcc384::PUBLIC_KEY_OFFSET
                    ..OcpLockEcdh384CertTbsEcc384::PUBLIC_KEY_OFFSET
                        + OcpLockEcdh384CertTbsEcc384::PUBLIC_KEY_LEN],
                params.public_key,
            );
            assert_eq!(
                &cert.tbs()[OcpLockEcdh384CertTbsEcc384::SUBJECT_SN_OFFSET
                    ..OcpLockEcdh384CertTbsEcc384::SUBJECT_SN_OFFSET
                        + OcpLockEcdh384CertTbsEcc384::SUBJECT_SN_LEN],
                params.subject_sn,
            );
            assert_eq!(
                &cert.tbs()[OcpLockEcdh384CertTbsEcc384::ISSUER_SN_OFFSET
                    ..OcpLockEcdh384CertTbsEcc384::ISSUER_SN_OFFSET
                        + OcpLockEcdh384CertTbsEcc384::ISSUER_SN_LEN],
                params.issuer_sn,
            );
            assert_eq!(
                &cert.tbs()[OcpLockEcdh384CertTbsEcc384::SUBJECT_KEY_ID_OFFSET
                    ..OcpLockEcdh384CertTbsEcc384::SUBJECT_KEY_ID_OFFSET
                        + OcpLockEcdh384CertTbsEcc384::SUBJECT_KEY_ID_LEN],
                params.subject_key_id,
            );
            assert_eq!(
                &cert.tbs()[OcpLockEcdh384CertTbsEcc384::AUTHORITY_KEY_ID_OFFSET
                    ..OcpLockEcdh384CertTbsEcc384::AUTHORITY_KEY_ID_OFFSET
                        + OcpLockEcdh384CertTbsEcc384::AUTHORITY_KEY_ID_LEN],
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

            let mut parser = X509CertificateParser::new().with_deep_parse_extensions(true);
            let parsed_cert = match parser.parse(&buf) {
                Ok((_, parsed_cert)) => parsed_cert,
                Err(e) => panic!("x509 parsing failed: {:?}", e),
            };

            assert_eq!(parsed_cert.version(), X509Version::V3);
            let basic_constraints = parsed_cert.basic_constraints().unwrap().unwrap();
            assert!(basic_constraints.critical);
            assert!(!basic_constraints.value.ca);

            // Check key usage. OCP LOCK HPKE certs should only allow key encipherment
            let key_usage = parsed_cert.key_usage().unwrap().unwrap();
            assert!(key_usage.critical);
            assert!(key_usage.value.key_encipherment());
            assert!(!key_usage.value.key_cert_sign());
            assert!(!key_usage.value.digital_signature());

            // Check that HPKE Identifiers extension is present
            let ext_map = parsed_cert.extensions_map().unwrap();
            const HPKE_IDENTIFIERS_OID: Oid = oid!(2.23.133 .21 .1 .1);
            assert!(!ext_map[&HPKE_IDENTIFIERS_OID].critical);
        }

        #[test]
        #[cfg(feature = "generate_templates")]
        fn test_ocp_lock_ecdh_ecc384_template() {
            let manual_template = std::fs::read(std::path::Path::new(
                "./build/ocp_lock_ecdh_384_cert_tbs_ecc_384.rs",
            ))
            .unwrap();
            let auto_generated_template = std::fs::read(std::path::Path::new(concat!(
                env!("OUT_DIR"),
                "/ocp_lock_ecdh_384_cert_tbs_ecc_384.rs"
            )))
            .unwrap();
            if auto_generated_template != manual_template {
                panic!(
                "Auto-generated OCP LOCK ECDH P-384 EC Certificate template is not equal to the manual template."
            )
            }
        }
    }
}

pub mod ecdh_384_mldsa_87 {

    #[cfg(feature = "generate_templates")]
    include!(concat!(
        env!("OUT_DIR"),
        "/ocp_lock_ecdh_384_cert_tbs_ml_dsa_87.rs"
    ));
    #[cfg(not(feature = "generate_templates"))]
    include! {"../build/ocp_lock_ecdh_384_cert_tbs_ml_dsa_87.rs"}

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

        #[test]
        fn test_cert() {
            let subject_key = Ecc384AsymKey::default();
            let issuer_key = MlDsa87AsymKey::default();
            let mldsa_key = issuer_key.priv_key();

            let params = OcpLockEcdh384CertTbsMlDsa87Params {
                serial_number: &[0xABu8; OcpLockEcdh384CertTbsMlDsa87Params::SERIAL_NUMBER_LEN],
                public_key:
                    TryInto::<&[u8; OcpLockEcdh384CertTbsMlDsa87Params::PUBLIC_KEY_LEN]>::try_into(
                        subject_key.pub_key(),
                    )
                    .unwrap(),
                subject_sn:
                    &TryInto::<[u8; OcpLockEcdh384CertTbsMlDsa87Params::SUBJECT_SN_LEN]>::try_into(
                        subject_key.hex_str().into_bytes(),
                    )
                    .unwrap(),
                issuer_sn:
                    &TryInto::<[u8; OcpLockEcdh384CertTbsMlDsa87Params::ISSUER_SN_LEN]>::try_into(
                        issuer_key.hex_str().into_bytes(),
                    )
                    .unwrap(),
                subject_key_id: &TryInto::<
                    [u8; OcpLockEcdh384CertTbsMlDsa87Params::SUBJECT_KEY_ID_LEN],
                >::try_into(subject_key.sha1())
                .unwrap(),
                authority_key_id: &TryInto::<
                    [u8; OcpLockEcdh384CertTbsMlDsa87Params::AUTHORITY_KEY_ID_LEN],
                >::try_into(issuer_key.sha1())
                .unwrap(),
                not_before: &NotBefore::default().value,
                not_after: &NotAfter::default().value,
            };

            let cert = OcpLockEcdh384CertTbsMlDsa87::new(&params);

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

            assert_ne!(cert.tbs(), OcpLockEcdh384CertTbsMlDsa87::TBS_TEMPLATE);
            assert_eq!(
                &cert.tbs()[OcpLockEcdh384CertTbsMlDsa87::PUBLIC_KEY_OFFSET
                    ..OcpLockEcdh384CertTbsMlDsa87::PUBLIC_KEY_OFFSET
                        + OcpLockEcdh384CertTbsMlDsa87::PUBLIC_KEY_LEN],
                params.public_key,
            );
            assert_eq!(
                &cert.tbs()[OcpLockEcdh384CertTbsMlDsa87::SUBJECT_SN_OFFSET
                    ..OcpLockEcdh384CertTbsMlDsa87::SUBJECT_SN_OFFSET
                        + OcpLockEcdh384CertTbsMlDsa87::SUBJECT_SN_LEN],
                params.subject_sn,
            );
            assert_eq!(
                &cert.tbs()[OcpLockEcdh384CertTbsMlDsa87::ISSUER_SN_OFFSET
                    ..OcpLockEcdh384CertTbsMlDsa87::ISSUER_SN_OFFSET
                        + OcpLockEcdh384CertTbsMlDsa87::ISSUER_SN_LEN],
                params.issuer_sn,
            );
            assert_eq!(
                &cert.tbs()[OcpLockEcdh384CertTbsMlDsa87::SUBJECT_KEY_ID_OFFSET
                    ..OcpLockEcdh384CertTbsMlDsa87::SUBJECT_KEY_ID_OFFSET
                        + OcpLockEcdh384CertTbsMlDsa87::SUBJECT_KEY_ID_LEN],
                params.subject_key_id,
            );
            assert_eq!(
                &cert.tbs()[OcpLockEcdh384CertTbsMlDsa87::AUTHORITY_KEY_ID_OFFSET
                    ..OcpLockEcdh384CertTbsMlDsa87::AUTHORITY_KEY_ID_OFFSET
                        + OcpLockEcdh384CertTbsMlDsa87::AUTHORITY_KEY_ID_LEN],
                params.authority_key_id,
            );

            let mldsa_sig = crate::MlDsa87Signature {
                sig: sig.try_into().unwrap(),
            };

            let builder = crate::MlDsa87CertBuilder::new(cert.tbs(), &mldsa_sig).unwrap();
            let mut buf = vec![0u8; builder.len()];
            builder.build(&mut buf).unwrap();

            let cert: X509 = X509::from_der(&buf).unwrap();
            assert!(cert.verify(issuer_key.priv_key()).unwrap());

            let mut parser = X509CertificateParser::new().with_deep_parse_extensions(true);
            let parsed_cert = match parser.parse(&buf) {
                Ok((_, parsed_cert)) => parsed_cert,
                Err(e) => panic!("x509 parsing failed: {:?}", e),
            };

            assert_eq!(parsed_cert.version(), X509Version::V3);
            let basic_constraints = parsed_cert.basic_constraints().unwrap().unwrap();
            assert!(basic_constraints.critical);
            assert!(!basic_constraints.value.ca);

            // Check key usage. OCP LOCK HPKE certs should only allow key encipherment
            let key_usage = parsed_cert.key_usage().unwrap().unwrap();
            assert!(key_usage.critical);
            assert!(key_usage.value.key_encipherment());
            assert!(!key_usage.value.key_cert_sign());
            assert!(!key_usage.value.digital_signature());

            // Check that HPKE Identifiers extension is present
            let ext_map = parsed_cert.extensions_map().unwrap();
            const HPKE_IDENTIFIERS_OID: Oid = oid!(2.23.133 .21 .1 .1);
            assert!(!ext_map[&HPKE_IDENTIFIERS_OID].critical);
        }

        #[test]
        #[cfg(feature = "generate_templates")]
        fn test_ocp_lock_ecdh_mldsa87_template() {
            let manual_template = std::fs::read(std::path::Path::new(
                "./build/ocp_lock_ecdh_384_cert_tbs_ml_dsa_87.rs",
            ))
            .unwrap();
            let auto_generated_template = std::fs::read(std::path::Path::new(concat!(
                env!("OUT_DIR"),
                "/ocp_lock_ecdh_384_cert_tbs_ml_dsa_87.rs"
            )))
            .unwrap();
            if auto_generated_template != manual_template {
                panic!(
                "Auto-generated OCP LOCK ECDH P-384 ML-DSA Certificate template is not equal to the manual template."
            )
            }
        }
    }
}
