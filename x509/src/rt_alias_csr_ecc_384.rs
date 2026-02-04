/*++

Licensed under the Apache-2.0 license.

File Name:

    rt_alias_csr_ecc_384.rs

Abstract:

    ECC384 Runtime Alias Certificate Signing Request related code.

--*/

// Note: All the necessary code is auto generated
#[cfg(feature = "generate_templates")]
include!(concat!(env!("OUT_DIR"), "/rt_alias_csr_tbs_ecc_384.rs"));
#[cfg(not(feature = "generate_templates"))]
include! {"../build/rt_alias_csr_tbs_ecc_384.rs"}

#[cfg(all(test, target_family = "unix"))]
mod tests {
    use openssl::sha::Sha384;
    use openssl::{ecdsa::EcdsaSig, x509::X509Req};

    use x509_parser::cri_attributes::ParsedCriAttribute;
    use x509_parser::extensions::ParsedExtension;
    use x509_parser::oid_registry::asn1_rs::oid;
    use x509_parser::prelude::{FromDer, X509CertificationRequest};

    use super::*;
    use crate::test_util::tests::*;
    use crate::{Ecdsa384CsrBuilder, Ecdsa384Signature};

    const TEST_UEID: &[u8] = &[0xAB; RtAliasCsrTbsEcc384::UEID_LEN];
    const TEST_RT_TCI: &[u8] = &[0xCD; RtAliasCsrTbsEcc384::TCB_INFO_RT_TCI_LEN];
    const TEST_FW_SVN: &[u8] = &[0x01];

    fn make_test_csr(subject_key: &Ecc384AsymKey) -> RtAliasCsrTbsEcc384 {
        let params = RtAliasCsrTbsEcc384Params {
            public_key: &subject_key.pub_key().try_into().unwrap(),
            subject_sn: &subject_key.hex_str().into_bytes().try_into().unwrap(),
            ueid: &TEST_UEID.try_into().unwrap(),
            tcb_info_rt_tci: &TEST_RT_TCI.try_into().unwrap(),
            tcb_info_fw_svn: &TEST_FW_SVN.try_into().unwrap(),
        };

        RtAliasCsrTbsEcc384::new(&params)
    }

    #[test]
    fn test_csr_signing() {
        let key = Ecc384AsymKey::default();
        let ec_key = key.priv_key().ec_key().unwrap();
        let csr = make_test_csr(&key);

        let sig: EcdsaSig = csr
            .sign(|b| {
                let mut sha = Sha384::new();
                sha.update(b);
                EcdsaSig::sign(&sha.finish(), &ec_key)
            })
            .unwrap();

        assert_ne!(csr.tbs(), RtAliasCsrTbsEcc384::TBS_TEMPLATE);
        assert_eq!(
            &csr.tbs()[RtAliasCsrTbsEcc384::PUBLIC_KEY_OFFSET
                ..RtAliasCsrTbsEcc384::PUBLIC_KEY_OFFSET + RtAliasCsrTbsEcc384::PUBLIC_KEY_LEN],
            key.pub_key(),
        );
        assert_eq!(
            &csr.tbs()[RtAliasCsrTbsEcc384::SUBJECT_SN_OFFSET
                ..RtAliasCsrTbsEcc384::SUBJECT_SN_OFFSET + RtAliasCsrTbsEcc384::SUBJECT_SN_LEN],
            key.hex_str().into_bytes(),
        );
        assert_eq!(
            &csr.tbs()[RtAliasCsrTbsEcc384::UEID_OFFSET
                ..RtAliasCsrTbsEcc384::UEID_OFFSET + RtAliasCsrTbsEcc384::UEID_LEN],
            TEST_UEID,
        );
        assert_eq!(
            &csr.tbs()[RtAliasCsrTbsEcc384::TCB_INFO_RT_TCI_OFFSET
                ..RtAliasCsrTbsEcc384::TCB_INFO_RT_TCI_OFFSET
                    + RtAliasCsrTbsEcc384::TCB_INFO_RT_TCI_LEN],
            TEST_RT_TCI,
        );
        assert_eq!(
            &csr.tbs()[RtAliasCsrTbsEcc384::TCB_INFO_FW_SVN_OFFSET
                ..RtAliasCsrTbsEcc384::TCB_INFO_FW_SVN_OFFSET
                    + RtAliasCsrTbsEcc384::TCB_INFO_FW_SVN_LEN],
            TEST_FW_SVN,
        );

        let ecdsa_sig = crate::Ecdsa384Signature {
            r: sig.r().to_vec_padded(48).unwrap().try_into().unwrap(),
            s: sig.s().to_vec_padded(48).unwrap().try_into().unwrap(),
        };

        let builder = crate::Ecdsa384CsrBuilder::new(csr.tbs(), &ecdsa_sig).unwrap();
        let mut buf = vec![0u8; builder.len()];
        builder.build(&mut buf).unwrap();

        let req: X509Req = X509Req::from_der(&buf).unwrap();
        assert!(req.verify(&req.public_key().unwrap()).unwrap());
        assert!(req.verify(key.priv_key()).unwrap());
    }

    #[test]
    fn test_extensions() {
        let key = Ecc384AsymKey::default();
        let ec_key = key.priv_key().ec_key().unwrap();
        let csr = make_test_csr(&key);

        let sig: EcdsaSig = csr
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

        let builder = Ecdsa384CsrBuilder::new(csr.tbs(), &ecdsa_sig).unwrap();
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

    #[test]
    #[cfg(feature = "generate_templates")]
    fn test_rt_alias_template() {
        let manual_template =
            std::fs::read(std::path::Path::new("./build/rt_alias_csr_tbs_ecc_384.rs")).unwrap();
        let auto_generated_template = std::fs::read(std::path::Path::new(concat!(
            env!("OUT_DIR"),
            "/rt_alias_csr_tbs_ecc_384.rs"
        )))
        .unwrap();
        if auto_generated_template != manual_template {
            panic!("Auto-generated RT Alias CSR template is not equal to the manual template.")
        }
    }
}
