/*++

Licensed under the Apache-2.0 license.

File Name:

    ldevid_csr_mldsa_87.rs

Abstract:

    Local Device ID Certificate Signing Request related code.

--*/

#[cfg(feature = "generate_templates")]
include!(concat!(
    env!("OUT_DIR"),
    "/local_dev_id_csr_tbs_ml_dsa_87.rs"
));
#[cfg(not(feature = "generate_templates"))]
include! {"../build/local_dev_id_csr_tbs_ml_dsa_87.rs"}

#[cfg(all(test, target_family = "unix"))]
mod tests {
    use openssl::pkey_ctx::PkeyCtx;
    use openssl::pkey_ml_dsa::Variant;
    use openssl::signature::Signature;
    use openssl::x509::X509Req;

    use x509_parser::cri_attributes::ParsedCriAttribute;
    use x509_parser::extensions::ParsedExtension;
    use x509_parser::oid_registry::asn1_rs::oid;
    use x509_parser::prelude::{FromDer, X509CertificationRequest};

    use super::*;
    use crate::test_util::tests::*;
    use crate::{MlDsa87CsrBuilder, MlDsa87Signature};

    const TEST_UEID: &[u8] = &[0xAB; LocalDevIdCsrTbsMlDsa87::UEID_LEN];

    fn make_test_csr(subject_key: &MlDsa87AsymKey) -> LocalDevIdCsrTbsMlDsa87 {
        let params = LocalDevIdCsrTbsMlDsa87Params {
            public_key: &subject_key.pub_key().try_into().unwrap(),
            subject_sn: &subject_key.hex_str().into_bytes().try_into().unwrap(),
            ueid: &TEST_UEID.try_into().unwrap(),
        };

        LocalDevIdCsrTbsMlDsa87::new(&params)
    }

    #[test]
    fn test_csr_signing() {
        let key = MlDsa87AsymKey::default();
        let mldsa_key = key.priv_key();
        let csr = make_test_csr(&key);

        let sig = csr
            .sign(|b| {
                let mut signature = vec![];
                let mut ctx = PkeyCtx::new(mldsa_key)?;
                let mut algo = Signature::for_ml_dsa(Variant::MlDsa87)?;
                ctx.sign_message_init(&mut algo)?;
                ctx.sign_to_vec(b, &mut signature)?;
                Ok::<Vec<u8>, openssl::error::ErrorStack>(signature)
            })
            .unwrap();

        assert_ne!(csr.tbs(), LocalDevIdCsrTbsMlDsa87::TBS_TEMPLATE);
        assert_eq!(
            &csr.tbs()[LocalDevIdCsrTbsMlDsa87::PUBLIC_KEY_OFFSET
                ..LocalDevIdCsrTbsMlDsa87::PUBLIC_KEY_OFFSET
                    + LocalDevIdCsrTbsMlDsa87::PUBLIC_KEY_LEN],
            key.pub_key(),
        );
        assert_eq!(
            &csr.tbs()[LocalDevIdCsrTbsMlDsa87::SUBJECT_SN_OFFSET
                ..LocalDevIdCsrTbsMlDsa87::SUBJECT_SN_OFFSET
                    + LocalDevIdCsrTbsMlDsa87::SUBJECT_SN_LEN],
            key.hex_str().into_bytes(),
        );
        assert_eq!(
            &csr.tbs()[LocalDevIdCsrTbsMlDsa87::UEID_OFFSET
                ..LocalDevIdCsrTbsMlDsa87::UEID_OFFSET + LocalDevIdCsrTbsMlDsa87::UEID_LEN],
            TEST_UEID,
        );

        let mldsa_sig = MlDsa87Signature {
            sig: sig.try_into().unwrap(),
        };

        let builder = crate::MlDsa87CsrBuilder::new(csr.tbs(), &mldsa_sig).unwrap();
        let mut buf = vec![0u8; builder.len()];
        builder.build(&mut buf).unwrap();

        let req: X509Req = X509Req::from_der(&buf).unwrap();
        assert!(req.verify(&req.public_key().unwrap()).unwrap());
        assert!(req.verify(key.priv_key()).unwrap());
    }

    #[test]
    fn test_extensions() {
        let key = MlDsa87AsymKey::default();
        let mldsa_key = key.priv_key();
        let csr = make_test_csr(&key);

        let sig = csr
            .sign(|b| {
                let mut signature = vec![];
                let mut ctx = PkeyCtx::new(mldsa_key)?;
                let mut algo = Signature::for_ml_dsa(Variant::MlDsa87)?;
                ctx.sign_message_init(&mut algo)?;
                ctx.sign_to_vec(b, &mut signature)?;
                Ok::<Vec<u8>, openssl::error::ErrorStack>(signature)
            })
            .unwrap();

        let mldsa_sig = MlDsa87Signature {
            sig: sig.try_into().unwrap(),
        };

        let builder = MlDsa87CsrBuilder::new(csr.tbs(), &mldsa_sig).unwrap();
        let mut buf = vec![0u8; builder.len()];
        builder.build(&mut buf).unwrap();

        let (_, parsed_csr) = X509CertificationRequest::from_der(&buf).unwrap();

        let requested_extensions = parsed_csr
            .certification_request_info
            .iter_attributes()
            .find_map(|attr| {
                if let ParsedCriAttribute::ExtensionRequest(requested) = attr.parsed_attribute() {
                    Some(&requested.extensions)
                } else {
                    None
                }
            })
            .unwrap();

        // BasicConstraints
        let bc_ext = requested_extensions
            .iter()
            .find(|ext| matches!(ext.parsed_extension(), ParsedExtension::BasicConstraints(_)))
            .unwrap();
        let ParsedExtension::BasicConstraints(bc) = bc_ext.parsed_extension() else {
            panic!("Extension is not BasicConstraints");
        };

        assert!(bc_ext.critical);
        assert!(bc.ca);

        // KeyUsage
        let ku_ext = requested_extensions
            .iter()
            .find(|ext| matches!(ext.parsed_extension(), ParsedExtension::KeyUsage(_)))
            .unwrap();

        assert!(ku_ext.critical);

        // ExtendedKeyUsage
        let eku_ext = requested_extensions
            .iter()
            .find(|ext| matches!(ext.parsed_extension(), ParsedExtension::ExtendedKeyUsage(_)))
            .unwrap();
        let ParsedExtension::ExtendedKeyUsage(eku) = eku_ext.parsed_extension() else {
            panic!("Extension is not ExtendedKeyUsage");
        };

        assert!(!eku_ext.critical);
        // Should contain TCG_DICE_KP_IDENTITY_LOC (2.23.133.5.4.100.7) and TCG_DICE_KP_ECA (2.23.133.5.4.100.12)
        assert!(eku.other.contains(&oid!(2.23.133 .5 .4 .100 .7)));
        assert!(eku.other.contains(&oid!(2.23.133 .5 .4 .100 .12)));

        // UEID
        let ueid_ext = requested_extensions
            .iter()
            .find(|ext| {
                if let ParsedExtension::UnsupportedExtension { oid } = ext.parsed_extension() {
                    oid == &oid!(2.23.133 .5 .4 .4)
                } else {
                    false
                }
            })
            .unwrap();
        assert!(!ueid_ext.critical);
    }

    #[test]
    #[cfg(feature = "generate_templates")]
    fn test_ldevid_template() {
        let manual_template = std::fs::read(std::path::Path::new(
            "./build/local_dev_id_csr_tbs_ml_dsa_87.rs",
        ))
        .unwrap();
        let auto_generated_template = std::fs::read(std::path::Path::new(concat!(
            env!("OUT_DIR"),
            "/local_dev_id_csr_tbs_ml_dsa_87.rs"
        )))
        .unwrap();
        if auto_generated_template != manual_template {
            panic!("Auto-generated LDevID CSR template is not equal to the manual template.")
        }
    }
}
