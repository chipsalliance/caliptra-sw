/*++

Licensed under the Apache-2.0 license.

File Name:

    pq_dev_id_csr_mldsa_87.rs

Abstract:

    Post-Quantum Device ID Certificate Signing Request related code (ML-DSA-87).

--*/
// Note: All the necessary code is auto generated
#[cfg(feature = "generate_templates")]
include!(concat!(env!("OUT_DIR"), "/pq_dev_id_cert_tbs_ml_dsa_87.rs"));
#[cfg(not(feature = "generate_templates"))]
include! {"../build/pq_dev_id_cert_tbs_ml_dsa_87.rs"}

#[cfg(all(test, target_family = "unix"))]
mod tests {
    use openssl::pkey_ctx::PkeyCtx;
    use openssl::pkey_ml_dsa::Variant;
    use openssl::signature::Signature;
    use openssl::x509::X509;

    use x509_parser::nom::Parser;
    use x509_parser::oid_registry::asn1_rs::oid;
    use x509_parser::prelude::X509CertificateParser;

    use super::*;
    use crate::test_util::tests::*;
    use crate::{MlDsa87CertBuilder, NotAfter, NotBefore};
    use caliptra_drivers::Mldsa87Signature;

    const TEST_UEID: &[u8] = &[0xAB; PqDevIdCertTbsMlDsa87::UEID_LEN];

    fn make_test_cert(
        subject_key: &MlDsa87AsymKey,
        issuer_key: &MlDsa87AsymKey,
    ) -> PqDevIdCertTbsMlDsa87 {
        PqDevIdCertTbsMlDsa87::new(&PqDevIdCertTbsMlDsa87Params {
            serial_number: &[0xABu8; PqDevIdCertTbsMlDsa87Params::SERIAL_NUMBER_LEN],
            public_key: &subject_key.pub_key().try_into().unwrap(),
            subject_sn: &subject_key.hex_str().into_bytes().try_into().unwrap(),
            issuer_sn: &issuer_key.hex_str().into_bytes().try_into().unwrap(),
            ueid: &TEST_UEID.try_into().unwrap(),
            subject_key_id: &subject_key.sha1(),
            authority_key_id: &issuer_key.sha1(),
            not_before: &NotBefore::default().value,
            not_after: &NotAfter::default().value,
        })
    }

    fn build_cert(cert: &PqDevIdCertTbsMlDsa87, issuer_key: &MlDsa87AsymKey) -> Vec<u8> {
        let sig = cert
            .sign(|b| {
                let mut signature = vec![];
                let mut ctx = PkeyCtx::new(issuer_key.priv_key())?;
                let mut algo = Signature::for_ml_dsa(Variant::MlDsa87)?;
                ctx.sign_message_init(&mut algo)?;
                ctx.sign_to_vec(b, &mut signature)?;
                Ok::<Vec<u8>, openssl::error::ErrorStack>(signature)
            })
            .unwrap();

        let mldsa_sig = Mldsa87Signature::new(sig.try_into().unwrap());
        let builder = MlDsa87CertBuilder::new(cert.tbs(), &mldsa_sig).unwrap();
        let mut buf = vec![0u8; builder.len()];
        builder.build(&mut buf).unwrap();
        buf
    }

    #[test]
    fn test_cert_is_valid_der() {
        let subject_key = MlDsa87AsymKey::default();
        let issuer_key = MlDsa87AsymKey::default();
        let cert = make_test_cert(&subject_key, &issuer_key);
        let buf = build_cert(&cert, &issuer_key);
        X509::from_der(&buf).expect("cert must be valid DER");
    }

    #[test]
    fn test_cert_contains_mldsa87_oid() {
        let subject_key = MlDsa87AsymKey::default();
        let issuer_key = MlDsa87AsymKey::default();
        let cert = make_test_cert(&subject_key, &issuer_key);
        let buf = build_cert(&cert, &issuer_key);

        let mut parser = X509CertificateParser::new().with_deep_parse_extensions(true);
        let (_, parsed) = parser.parse(&buf).expect("x509 parsing failed");

        assert_eq!(
            parsed.tbs_certificate.subject_pki.algorithm.algorithm,
            oid!(2.16.840 .1 .101 .3 .4 .3 .19),
        );
    }

    #[test]
    fn test_cert_contains_expected_public_key() {
        let subject_key = MlDsa87AsymKey::default();
        let issuer_key = MlDsa87AsymKey::default();
        let cert = make_test_cert(&subject_key, &issuer_key);

        assert_ne!(cert.tbs(), PqDevIdCertTbsMlDsa87::TBS_TEMPLATE);
        assert_eq!(
            &cert.tbs()[PqDevIdCertTbsMlDsa87::PUBLIC_KEY_OFFSET
                ..PqDevIdCertTbsMlDsa87::PUBLIC_KEY_OFFSET + PqDevIdCertTbsMlDsa87::PUBLIC_KEY_LEN],
            subject_key.pub_key(),
        );
    }

    #[test]
    fn test_cert_signature_verifies() {
        let subject_key = MlDsa87AsymKey::default();
        let issuer_key = MlDsa87AsymKey::default();
        let cert = make_test_cert(&subject_key, &issuer_key);
        let buf = build_cert(&cert, &issuer_key);

        let x509 = X509::from_der(&buf).unwrap();
        assert!(x509.verify(issuer_key.priv_key()).unwrap());
    }
}
