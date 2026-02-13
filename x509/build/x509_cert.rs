/*++

Licensed under the Apache-2.0 license.

File Name:

    x509_cert.rs

Abstract:

    File contains a re-implementation of "cert.rs" to workaround the limitations of the OpenSSL
    API. This is built on "x509-cert" crate.

    You should prefer to create certs from the "cert.rs".

--*/

use std::str::FromStr;

use const_oid::{
    db::{
        rfc5280::{
            ID_CE_AUTHORITY_KEY_IDENTIFIER, ID_CE_BASIC_CONSTRAINTS, ID_CE_KEY_USAGE,
            ID_CE_SUBJECT_KEY_IDENTIFIER,
        },
        rfc5912::ECDSA_WITH_SHA_384,
    },
    ObjectIdentifier,
};
use x509_cert::{
    certificate::{TbsCertificate, Version},
    der::{
        asn1::{BitString, GeneralizedTime, OctetString},
        flagset::Flags,
        DateTime, {Decode, Encode},
    },
    ext::{
        pkix::{
            AuthorityKeyIdentifier, BasicConstraints, KeyUsage as PkixKeyUsage, KeyUsages,
            SubjectKeyIdentifier,
        },
        Extension,
    },
    name::Name,
    serial_number::SerialNumber,
    spki::{AlgorithmIdentifier, SubjectPublicKeyInfo},
    time::{Time, Validity},
};

use crate::x509::{AsymKey, KeyType, KeyUsage, SigningAlgorithm, HYBRID_MLKEM_1024_ECDH_P384_OID};
use crate::{
    tbs::{init_param, sanitize, TbsParam, TbsTemplate},
    x509::MLDSA_87_OID,
};

struct CertTemplateParam {
    tbs_param: TbsParam,
    needle: Vec<u8>,
}

pub struct X509CertTemplateBuilder<AlgoIssuer: SigningAlgorithm, AlgoSubject: SigningAlgorithm> {
    issuer_algo: AlgoIssuer,
    subject_algo: AlgoSubject,
    params: Vec<CertTemplateParam>,
    extensions: Vec<Extension>,
}

impl<AlgoIssuer: SigningAlgorithm, AlgoSubject: SigningAlgorithm>
    X509CertTemplateBuilder<AlgoIssuer, AlgoSubject>
{
    pub fn new() -> Self {
        Self {
            issuer_algo: AlgoIssuer::default(),
            subject_algo: AlgoSubject::default(),
            params: vec![],
            extensions: vec![],
        }
    }

    pub fn add_basic_constraints_ext(mut self, ca: bool, path_len: u32) -> Self {
        let ext = BasicConstraints {
            ca,
            path_len_constraint: Some(path_len.try_into().unwrap()),
        };
        self.extensions.push(Extension {
            extn_id: ID_CE_BASIC_CONSTRAINTS,
            critical: true,
            extn_value: OctetString::new(ext.to_der().unwrap()).unwrap(),
        });
        self
    }

    /// NOTE: Only supports `KeyUsage::KeyEncipherment`.
    pub fn add_key_usage_ext(mut self, usage: KeyUsage) -> Self {
        let mut bits = KeyUsages::none();
        if usage.key_encipherment() {
            bits |= KeyUsages::KeyEncipherment;
        }

        let ext = PkixKeyUsage(bits);
        self.extensions.push(Extension {
            extn_id: ID_CE_KEY_USAGE,
            critical: true,
            extn_value: OctetString::new(ext.to_der().unwrap()).unwrap(),
        });
        self
    }

    pub fn add_hpke_identifiers_ext(mut self, identifier: &crate::x509::HPKEIdentifiers) -> Self {
        let oid = ObjectIdentifier::new_unwrap(crate::x509::HPKEIdentifiers::OID);
        let ext_val = asn1::write_single(identifier).unwrap();
        self.extensions.push(Extension {
            extn_id: oid,
            critical: false,
            extn_value: OctetString::new(ext_val).unwrap(),
        });
        self
    }

    pub fn tbs_template(mut self, subject_cn: &str, issuer_cn: &str) -> TbsTemplate {
        let subject_key = self.subject_algo.gen_key();
        let issuer_key = self.issuer_algo.gen_key();

        let serial_number_bytes = [0x7Fu8; 20];
        let serial_number = SerialNumber::new(&serial_number_bytes).unwrap();
        self.params.push(CertTemplateParam {
            tbs_param: TbsParam::new("SERIAL_NUMBER", 0, serial_number_bytes.len()),
            needle: serial_number_bytes.to_vec(),
        });

        let not_before = "20230101000000Z";
        let not_after = "99991231235959Z";
        let validity = Validity {
            // The Rust Crypto parser is much stricter, so we can't use the exact same date string.
            not_before: Time::GeneralTime(GeneralizedTime::from_date_time(
                DateTime::from_str("2023-01-01T00:00:00Z").unwrap(),
            )),
            not_after: Time::GeneralTime(GeneralizedTime::from_date_time(
                DateTime::from_str("9999-12-31T23:59:59Z").unwrap(),
            )),
        };

        self.params.push(CertTemplateParam {
            tbs_param: TbsParam::new("NOT_BEFORE", 0, not_before.len()),
            needle: not_before.as_bytes().to_vec(),
        });
        self.params.push(CertTemplateParam {
            tbs_param: TbsParam::new("NOT_AFTER", 0, not_after.len()),
            needle: not_after.as_bytes().to_vec(),
        });

        let subject_name = format!("CN={},serialNumber={}", subject_cn, subject_key.hex_str())
            .parse::<Name>()
            .unwrap();
        self.params.push(CertTemplateParam {
            tbs_param: TbsParam::new("SUBJECT_SN", 0, subject_key.hex_str().len()),
            needle: subject_key.hex_str().into_bytes(),
        });

        let issuer_name = format!("CN={},serialNumber={}", issuer_cn, issuer_key.hex_str())
            .parse::<Name>()
            .unwrap();
        self.params.push(CertTemplateParam {
            tbs_param: TbsParam::new("ISSUER_SN", 0, issuer_key.hex_str().len()),
            needle: issuer_key.hex_str().into_bytes(),
        });

        let subject_spki = match subject_key.key_type() {
            KeyType::MlKem1024P384 => SubjectPublicKeyInfo {
                algorithm: AlgorithmIdentifier {
                    oid: ObjectIdentifier::new_unwrap(HYBRID_MLKEM_1024_ECDH_P384_OID),
                    parameters: None,
                },
                subject_public_key: BitString::new(0, subject_key.pub_key()).unwrap(),
            },
            _ => {
                let subject_spki_der = subject_key.priv_key().public_key_to_der().unwrap();
                SubjectPublicKeyInfo::from_der(&subject_spki_der).unwrap()
            }
        };

        self.params.push(CertTemplateParam {
            tbs_param: TbsParam::new("PUBLIC_KEY", 0, subject_key.pub_key().len()),
            needle: subject_key.pub_key().to_vec(),
        });

        let ski = SubjectKeyIdentifier(OctetString::new(subject_key.sha1()).unwrap());
        self.extensions.push(Extension {
            extn_id: ID_CE_SUBJECT_KEY_IDENTIFIER,
            critical: false,
            extn_value: OctetString::new(ski.to_der().unwrap()).unwrap(),
        });
        self.params.push(CertTemplateParam {
            tbs_param: TbsParam::new("SUBJECT_KEY_ID", 0, subject_key.sha1().len()),
            needle: subject_key.sha1().to_vec(),
        });

        let aki = AuthorityKeyIdentifier {
            key_identifier: Some(OctetString::new(issuer_key.sha1()).unwrap()),
            authority_cert_issuer: None,
            authority_cert_serial_number: None,
        };
        self.extensions.push(Extension {
            extn_id: ID_CE_AUTHORITY_KEY_IDENTIFIER,
            critical: false,
            extn_value: OctetString::new(aki.to_der().unwrap()).unwrap(),
        });
        self.params.push(CertTemplateParam {
            tbs_param: TbsParam::new("AUTHORITY_KEY_ID", 0, issuer_key.sha1().len()),
            needle: issuer_key.sha1().to_vec(),
        });

        let signature_oid = match issuer_key.key_type() {
            KeyType::P384 => ECDSA_WITH_SHA_384,
            KeyType::MlDsa87 => ObjectIdentifier::new_unwrap(MLDSA_87_OID),
            _ => panic!("unsupported key type"),
        };

        let tbs_cert = TbsCertificate {
            version: Version::V3,
            serial_number,
            signature: AlgorithmIdentifier {
                oid: signature_oid,
                parameters: None,
            },
            issuer: issuer_name,
            validity,
            subject: subject_name,
            subject_public_key_info: subject_spki,
            issuer_unique_id: None,
            subject_unique_id: None,
            extensions: Some(self.extensions),
        };

        let mut tbs = tbs_cert.to_der().unwrap();

        self.params
            .sort_by_key(|p| std::cmp::Reverse(p.tbs_param.len));
        let params = self
            .params
            .iter()
            .map(|p| sanitize(init_param(&p.needle, &tbs, p.tbs_param), &mut tbs))
            .collect();
        TbsTemplate::new(tbs, params)
    }
}
