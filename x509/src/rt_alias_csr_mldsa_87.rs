/*++

Licensed under the Apache-2.0 license.

File Name:

    rt_alias_csr_mldsa_87.rs

Abstract:

    ML-DSA-87 Runtime Alias Certificate Signing Request related code.

--*/

// Note: All the necessary code is auto generated
include! {"../build/rt_alias_csr_tbs_ml_dsa_87.rs"}

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

    const TEST_UEID: &[u8] = &[0xAB; RtAliasCsrTbsMlDsa87::UEID_LEN];
    const TEST_RT_TCI: &[u8] = &[0xCD; RtAliasCsrTbsMlDsa87::TCB_INFO_RT_TCI_LEN];
    const TEST_FW_SVN: &[u8] = &[0x01];

    fn make_test_csr(subject_key: &MlDsa87AsymKey) -> RtAliasCsrTbsMlDsa87 {
        let params = RtAliasCsrTbsMlDsa87Params {
            public_key: &subject_key.pub_key().try_into().unwrap(),
            subject_sn: &subject_key.hex_str().into_bytes().try_into().unwrap(),
            ueid: &TEST_UEID.try_into().unwrap(),
            tcb_info_rt_tci: &TEST_RT_TCI.try_into().unwrap(),
            tcb_info_fw_svn: &TEST_FW_SVN.try_into().unwrap(),
        };

        RtAliasCsrTbsMlDsa87::new(&params)
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

        assert_ne!(csr.tbs(), RtAliasCsrTbsMlDsa87::TBS_TEMPLATE);
        assert_eq!(
            &csr.tbs()[RtAliasCsrTbsMlDsa87::PUBLIC_KEY_OFFSET
                ..RtAliasCsrTbsMlDsa87::PUBLIC_KEY_OFFSET + RtAliasCsrTbsMlDsa87::PUBLIC_KEY_LEN],
            key.pub_key(),
        );
        assert_eq!(
            &csr.tbs()[RtAliasCsrTbsMlDsa87::SUBJECT_SN_OFFSET
                ..RtAliasCsrTbsMlDsa87::SUBJECT_SN_OFFSET + RtAliasCsrTbsMlDsa87::SUBJECT_SN_LEN],
            key.hex_str().into_bytes(),
        );
        assert_eq!(
            &csr.tbs()[RtAliasCsrTbsMlDsa87::UEID_OFFSET
                ..RtAliasCsrTbsMlDsa87::UEID_OFFSET + RtAliasCsrTbsMlDsa87::UEID_LEN],
            TEST_UEID,
        );
        assert_eq!(
            &csr.tbs()[RtAliasCsrTbsMlDsa87::TCB_INFO_RT_TCI_OFFSET
                ..RtAliasCsrTbsMlDsa87::TCB_INFO_RT_TCI_OFFSET
                    + RtAliasCsrTbsMlDsa87::TCB_INFO_RT_TCI_LEN],
            TEST_RT_TCI,
        );
        assert_eq!(
            &csr.tbs()[RtAliasCsrTbsMlDsa87::TCB_INFO_FW_SVN_OFFSET
                ..RtAliasCsrTbsMlDsa87::TCB_INFO_FW_SVN_OFFSET
                    + RtAliasCsrTbsMlDsa87::TCB_INFO_FW_SVN_LEN],
            TEST_FW_SVN,
        );

        let mldsa_sig = crate::MlDsa87Signature {
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
        // Should contain TCG_DICE_KP_ECA (2.23.133.5.4.100.12)
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

        // TCB Info (OID 2.23.133.5.4.1)
        let tcb_info_ext = requested_extensions
            .iter()
            .find(|ext| {
                if let ParsedExtension::UnsupportedExtension { oid } = ext.parsed_extension() {
                    oid == &oid!(2.23.133 .5 .4 .1)
                } else {
                    false
                }
            })
            .unwrap();
        assert!(!tcb_info_ext.critical);
    }
}
