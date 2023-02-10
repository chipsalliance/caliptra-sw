/*++

Licensed under the Apache-2.0 license.

File Name:

    x509.rs

Abstract:

    File contains helper functions for cryptography and X509 object manipulation

--*/

use openssl::bn::BigNumContext;
use openssl::ec::EcGroup;
use openssl::ec::PointConversionForm;
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::PKey;
use openssl::pkey::Private;
use openssl::sha::Sha1;
use openssl::sha::Sha256;
use openssl::x509::extension::BasicConstraints;
use openssl::x509::extension::KeyUsage as Usage;
use openssl::x509::extension::SubjectKeyIdentifier;
use openssl::x509::X509Extension;
use openssl::x509::X509v3Context;

use crate::tbs::TbsParam;

/// Asymmetric Key
pub trait AsymKey: Default {
    /// Retrieve Private Key
    fn priv_key(&self) -> &PKey<Private>;

    /// Retrieve Public Key
    fn pub_key(&self) -> &[u8];

    /// Retrieve SHA-256 digest of the public key
    fn sha256(&self) -> [u8; 32] {
        let mut sha = Sha256::new();
        sha.update(self.pub_key());
        sha.finish()
    }

    /// Retrieve SHA1 digest of the public key
    fn sha1(&self) -> [u8; 20] {
        let mut sha = Sha1::new();
        sha.update(self.pub_key());
        sha.finish()
    }

    /// Retrieve the hex string of SHA-256 Digest of the public key
    fn hex_str(&self) -> String {
        hex::encode(self.sha256()).to_uppercase()
    }
}

/// Digest
pub trait Digest {
    /// Digest Algorithm
    fn algo() -> MessageDigest;
}

/// Signing Algorithm
pub trait SigningAlgorithm: Default {
    type AsymKey: AsymKey;
    type Digest: Digest;

    /// Generate Asymmetric Key Pair
    fn gen_key(&self) -> Self::AsymKey;

    /// Retrieve digest algorithm
    fn digest(&self) -> MessageDigest {
        Self::Digest::algo()
    }
}

/// ECC-348 Asymmetric Key Pair
pub struct Ecc384AsymKey {
    priv_key: PKey<Private>,
    pub_key: Vec<u8>,
}

impl AsymKey for Ecc384AsymKey {
    /// Retrieve Private Key
    fn priv_key(&self) -> &PKey<Private> {
        &self.priv_key
    }

    /// Retrieve Public Key
    fn pub_key(&self) -> &[u8] {
        &self.pub_key
    }
}

impl Default for Ecc384AsymKey {
    /// Returns the "default value" for a type.
    fn default() -> Self {
        let priv_key = PKey::ec_gen("secp384r1").unwrap();
        let ecc_group = EcGroup::from_curve_name(Nid::SECP384R1).unwrap();
        let mut bn_ctx = BigNumContext::new().unwrap();
        let pub_key = priv_key
            .ec_key()
            .unwrap()
            .public_key()
            .to_bytes(&ecc_group, PointConversionForm::UNCOMPRESSED, &mut bn_ctx)
            .unwrap();
        Self { priv_key, pub_key }
    }
}

/// SHA2-384 Algorithm
pub struct Sha384 {}

impl Digest for Sha384 {
    /// Retrieve the algorithm
    fn algo() -> MessageDigest {
        MessageDigest::sha384()
    }
}

#[derive(Default)]
pub struct EcdsaSha384Algo {}

impl SigningAlgorithm for EcdsaSha384Algo {
    type AsymKey = Ecc384AsymKey;
    type Digest = Sha384;

    fn gen_key(&self) -> Self::AsymKey {
        Self::AsymKey::default()
    }
}

bitfield::bitfield! {
    #[derive(Default, Debug, PartialEq, Eq, Clone, Copy)]
    /// Key Usage
    pub struct KeyUsage(u16);

    pub digital_signature, set_digital_signature: 0;
    pub non_repudiation, set_non_repudiation: 1;
    pub key_encipherment, set_key_encipherment: 2;
    pub data_encipherment, set_data_encipherment: 3;
    pub key_agreement, set_key_agreement: 4;
    pub key_cert_sign, set_key_cert_sign: 5;
    pub crl_sign, set_crl_sign: 6;
    pub encipher_only, set_encipher_only: 7;
    pub decipher_only, set_decipher_only: 8;
}

impl From<KeyUsage> for Usage {
    /// Converts to this type from the input type.
    fn from(value: KeyUsage) -> Self {
        let mut usage = Usage::new();

        if value.digital_signature() {
            usage.digital_signature();
        }

        if value.non_repudiation() {
            usage.non_repudiation();
        }

        if value.key_encipherment() {
            usage.key_encipherment();
        }

        if value.data_encipherment() {
            usage.data_encipherment();
        }

        if value.key_agreement() {
            usage.key_agreement();
        }

        if value.key_cert_sign() {
            usage.key_cert_sign();
        }

        if value.crl_sign() {
            usage.crl_sign();
        }

        if value.encipher_only() {
            usage.encipher_only();
        }

        if value.decipher_only() {
            usage.decipher_only();
        }

        usage
    }
}

/// Make X509 Basic Constraints Extension
pub fn make_basic_constraints_ext(ca: bool, path_len: u32) -> X509Extension {
    let mut ext = BasicConstraints::new();
    if ca {
        ext.ca();
    }
    ext.critical().pathlen(path_len).build().unwrap()
}

/// Make Key Usage Extension
pub fn make_key_usage_ext(key_usage: KeyUsage) -> X509Extension {
    let usage: Usage = key_usage.into();
    usage.build().unwrap()
}

/// Make TCG UEID extension
pub fn make_tcg_ueid_ext(ueid: &[u8]) -> X509Extension {
    #[derive(asn1::Asn1Read, asn1::Asn1Write)]
    struct TcgUeid<'a> {
        ueid: &'a [u8],
    }

    let tcg_ueid = TcgUeid { ueid };
    let der = asn1::write_single(&tcg_ueid).unwrap();
    let der_str = format!("DER:{}", hex::encode(der).to_uppercase());

    X509Extension::new(None, None, "2.23.133.5.4.4", &der_str).unwrap()
}

/// Make Subject Key ID extension
pub fn make_subj_key_id_ext(ctx: &X509v3Context) -> X509Extension {
    SubjectKeyIdentifier::new().build(ctx).unwrap()
}

/// Make Authority Key ID extension
pub fn make_auth_key_id_ext(key_id: &[u8]) -> X509Extension {
    #[derive(asn1::Asn1Read, asn1::Asn1Write)]
    struct AuthKeyId<'a> {
        #[implicit(0)]
        key_id: Option<&'a [u8]>,
    }

    let auth_key_id = AuthKeyId {
        key_id: Some(key_id),
    };

    let der = asn1::write_single(&auth_key_id).unwrap();
    let der_str = format!("DER:{}", hex::encode(der).to_uppercase());

    X509Extension::new(None, None, "2.5.29.35", &der_str).unwrap()
}

/// Retrieve the TBS from DER encoded vector
///
/// Note: Rust OpenSSL binding is missing the extensions to retrieve TBS portion of the X509
/// artifact
pub fn get_tbs(der: Vec<u8>) -> Vec<u8> {
    if der[0] != 0x30 {
        panic!("Invalid DER start tag");
    }

    let der_len_offset = 1;

    let tbs_offset = match der[der_len_offset] {
        0..=0x7F => der_len_offset + 1,
        0x81 => der_len_offset + 2,
        0x82 => der_len_offset + 3,
        _ => panic!("Unsupported DER Length"),
    };

    if der[tbs_offset] != 0x30 {
        panic!("Invalid TBS start tag");
    }

    let tbs_len_offset = tbs_offset + 1;
    let tbs_len = match der[tbs_len_offset] {
        0..=0x7F => der[tbs_len_offset] as usize + 2,
        0x81 => (der[tbs_len_offset + 1]) as usize + 3,
        0x82 => {
            (((der[tbs_len_offset + 1]) as usize) << u8::BITS)
                | (((der[tbs_len_offset + 2]) as usize) + 4)
        }
        _ => panic!("Invalid DER Length"),
    };

    der[tbs_offset..tbs_offset + tbs_len].to_vec()
}

/// Initialize template parameter with its offset
pub fn init_param(needle: &[u8], haystack: &[u8], param: TbsParam) -> TbsParam {
    assert_eq!(needle.len(), param.len);
    eprintln!("{}", param.name);
    let offset = haystack
        .windows(param.len)
        .position(|w| w == needle)
        .unwrap();

    TbsParam { offset, ..param }
}

/// Sanitize the TBS buffer for the specified parameter
pub fn sanitize(param: TbsParam, buf: &mut [u8]) -> TbsParam {
    for byte in buf.iter_mut().skip(param.offset).take(param.len) {
        *byte = 0x5F;
    }
    param
}
