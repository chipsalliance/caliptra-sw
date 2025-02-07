/*++

Licensed under the Apache-2.0 license.

File Name:

    csr_rustcrypto.rs

Abstract:

    File contains generation of X509 Certificate Signing Request (CSR) To Be Signed (TBS)
    template using RustCrypto that can be substituted at firmware runtime.

--*/
use std::str::FromStr;

use crate::tbs::{get_tbs, init_param, sanitize, TbsParam, TbsTemplate};
use const_oid::{AssociatedOid, ObjectIdentifier};
use core::marker::PhantomData;
use der::Decode;
use der::Sequence;
use p384::NistP384;
use sha2::{Digest, Sha256};
use signature::Keypair;
use spki::EncodePublicKey;
use x509_cert::builder::{Builder, RequestBuilder};
use x509_cert::der::Encode;
use x509_cert::ext::{
    pkix::{BasicConstraints, KeyUsage},
    AsExtension, Extension,
};
use x509_cert::name::Name;

/// CSR Template Param
struct CsrTemplateParam {
    tbs_param: TbsParam,
    needle: Vec<u8>,
}

#[derive(Sequence, Default, Debug)]
struct TcgUeid<'a> {
    #[asn1(type = "OCTET STRING")]
    ueid: &'a [u8],
}

impl<'a> AssociatedOid for TcgUeid<'a> {
    const OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.23.133.5.4.4");
}

impl<'a> AsExtension for TcgUeid<'a> {
    fn critical(&self, _subject: &Name, _extensions: &[Extension]) -> bool {
        true
    }
}

/// CSR Tempate Builder  
pub struct CsrTemplateBuilder<'a, Key> {
    basic_constraints: Option<BasicConstraints>,
    key_usage: Option<KeyUsage>,
    tcg_ueid: Option<TcgUeid<'a>>,
    params: Vec<CsrTemplateParam>,
    _phantom: PhantomData<Key>,
}

pub trait BuilderKeys: Sized {
    type Signature: spki::SignatureBitStringEncoding;
    fn key_gen() -> Self;
}

impl BuilderKeys for p384::ecdsa::SigningKey {
    type Signature = ecdsa::der::Signature<NistP384>;
    fn key_gen() -> Self {
        let mut rng = rand::thread_rng();
        Self::random(&mut rng)
    }
}

impl<'a, Key> CsrTemplateBuilder<'a, Key>
where
    Key: BuilderKeys
        + spki::SignatureAlgorithmIdentifier
        + Keypair
        + signature::Signer<<Key as BuilderKeys>::Signature>,
    Key::VerifyingKey: EncodePublicKey,
{
    pub fn new() -> Self {
        Self {
            params: Vec::new(),
            _phantom: PhantomData,
            basic_constraints: None,
            key_usage: None,
            tcg_ueid: None,
        }
    }

    pub fn add_basic_constraints_ext(mut self, ca: bool, path_len: u32) -> Self {
        self.basic_constraints = Some(BasicConstraints {
            ca,
            path_len_constraint: Some(path_len as u8),
        });
        self
    }

    pub fn add_key_usage_ext(mut self, usage: KeyUsage) -> Self {
        self.key_usage = Some(usage);
        self
    }

    pub fn add_ueid_ext(mut self, ueid: &'a [u8]) -> Self {
        self.tcg_ueid = Some(TcgUeid { ueid });
        let param = CsrTemplateParam {
            tbs_param: TbsParam::new("UEID", 0, ueid.len()),
            needle: ueid.to_vec(),
        };
        self.params.push(param);

        self
    }

    pub fn tbs_template(mut self, subject_cn: &str) -> TbsTemplate {
        let key = Key::key_gen();

        // Calculate SHA-256 hash of public key
        let pk_der = key.verifying_key().to_public_key_der().unwrap();
        // Parse DER to obtain SubjectPublicKeyInfo and extract public key bytes
        let spki: spki::SubjectPublicKeyInfo<der::asn1::Any, der::asn1::BitString> =
            spki::SubjectPublicKeyInfo::from_der(pk_der.as_bytes()).unwrap();
        let pk_bytes = spki.subject_public_key.as_bytes().unwrap().to_vec();
        let param = CsrTemplateParam {
            tbs_param: TbsParam::new("PUBLIC_KEY", 0, pk_bytes.len()),
            needle: pk_bytes.clone(),
        };
        self.params.push(param);

        // Format the subject name with CN only
        let key_hash = hex::encode(Sha256::digest(&pk_bytes)).to_uppercase();
        let subject = format!("CN={}", subject_cn);
        let name = Name::from_str(&subject).unwrap();
        let param = CsrTemplateParam {
            tbs_param: TbsParam::new("SUBJECT_SN", 0, key_hash.len()),
            needle: key_hash.into_bytes(),
        };
        self.params.push(param);

        let mut builder = RequestBuilder::new(name, &key).unwrap();

        if let Some(basic_constraints) = self.basic_constraints {
            builder.add_extension(&basic_constraints).unwrap();
        }
        if let Some(ueid) = self.tcg_ueid {
            builder.add_extension(&ueid).unwrap();
        }
        let req = builder.build().unwrap();
        let der = req.to_der().unwrap();

        const TBS_TEMPLATE: &[u8] = &[
            48u8, 130u8, 1u8, 62u8, 2u8, 1u8, 0u8, 48u8, 105u8, 49u8, 28u8, 48u8, 26u8, 6u8, 3u8,
            85u8, 4u8, 3u8, 12u8, 19u8, 67u8, 97u8, 108u8, 105u8, 112u8, 116u8, 114u8, 97u8, 32u8,
            49u8, 46u8, 48u8, 32u8, 73u8, 68u8, 101u8, 118u8, 73u8, 68u8, 49u8, 73u8, 48u8, 71u8,
            6u8, 3u8, 85u8, 4u8, 5u8, 19u8, 64u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8,
            95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8,
            95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8,
            95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8,
            95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8,
            48u8, 118u8, 48u8, 16u8, 6u8, 7u8, 42u8, 134u8, 72u8, 206u8, 61u8, 2u8, 1u8, 6u8, 5u8,
            43u8, 129u8, 4u8, 0u8, 34u8, 3u8, 98u8, 0u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8,
            95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8,
            95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8,
            95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8,
            95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8,
            95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8,
            95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8,
            95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 160u8, 86u8, 48u8, 84u8, 6u8, 9u8, 42u8, 134u8,
            72u8, 134u8, 247u8, 13u8, 1u8, 9u8, 14u8, 49u8, 71u8, 48u8, 69u8, 48u8, 18u8, 6u8, 3u8,
            85u8, 29u8, 19u8, 1u8, 1u8, 255u8, 4u8, 8u8, 48u8, 6u8, 1u8, 1u8, 255u8, 2u8, 1u8, 5u8,
            48u8, 14u8, 6u8, 3u8, 85u8, 29u8, 15u8, 1u8, 1u8, 255u8, 4u8, 4u8, 3u8, 2u8, 2u8, 4u8,
            48u8, 31u8, 6u8, 6u8, 103u8, 129u8, 5u8, 5u8, 4u8, 4u8, 4u8, 21u8, 48u8, 19u8, 4u8,
            17u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8,
            95u8, 95u8, 95u8, 95u8,
        ];

        let req = x509_cert::request::CertReq::try_from(TBS_TEMPLATE).unwrap();

        // TODO move get_tbs from x509_openssl
        // Retrieve the To be signed portion from the CSR
        let mut tbs = get_tbs(der);

        // Calculate the offset of parameters and sanitize the TBS section
        let params = self
            .params
            .iter()
            .map(|p| sanitize(init_param(&p.needle, &tbs, p.tbs_param), &mut tbs))
            .collect();
        // Create the template
        TbsTemplate::new(tbs, params)
    }
}
