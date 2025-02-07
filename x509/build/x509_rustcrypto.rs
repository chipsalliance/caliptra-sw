/*++

Licensed under the Apache-2.0 license.

File Name:

    x509_rustcrypto.rs

Abstract:

    File contains helper functions for cryptography and X509 object manipulation using RustCrypto

--*/

use caliptra_common::dice;
use p384::{
    ecdsa::{SigningKey, VerifyingKey, Signature},
    SecretKey, PublicKey,
};
use rand::rngs::OsRng;
use sha1::{Sha1, Digest as Sha1Digest};
use sha2::{Sha256, Digest as Sha2Digest};
use der::{
    asn1::{Any, ObjectIdentifier, Utf8StringRef},
    Sequence
};
use x509_cert::ext::pkix::KeyUsage;
use crate::tbs::TbsParam;

const FLAG_MASK: u32 = dice::FLAG_BIT_NOT_CONFIGURED
    | dice::FLAG_BIT_NOT_SECURE
    | dice::FLAG_BIT_DEBUG
    | dice::FLAG_BIT_FIXED_WIDTH;

/* Constants and OIDs similar to x509_openssl.rs */
const TCG_UEID_OID: &str = "2.23.133.5.4.4";
const TCG_TCB_INFO_OID: &str = "2.23.133.5.4.1";
const TCG_MULTI_TCB_INFO_OID: &str = "2.23.133.5.4.5";

#[derive(der::Sequence)]
#[asn1(tag_mode = "IMPLICIT")]
pub struct TcbInfo<'a> {
    #[asn1(context_specific = "0", optional = "true")]
    pub vendor: Option<Utf8StringRef<'a>>,
    
    #[asn1(context_specific = "1", optional = "true")]
    pub model: Option<Utf8StringRef<'a>>,
    
    #[asn1(context_specific = "2", optional = "true")]
    pub version: Option<Utf8StringRef<'a>>,
    
    #[asn1(context_specific = "3", optional = "true")]
    pub svn: Option<u32>,
    
    #[asn1(context_specific = "4", optional = "true")]
    pub layer: Option<u64>,
    
    #[asn1(context_specific = "5", optional = "true")]
    pub index: Option<u64>,
    
    #[asn1(context_specific = "6", optional = "true")]
    pub fwids: Option<der::asn1::SequenceOf<Fwid<'a>, 6>>,
    
    #[asn1(context_specific = "7", optional = "true")]
    pub flags: Option<der::asn1::BitString>,
    
    #[asn1(context_specific = "8", optional = "true")]
    pub vendor_info: Option<Vec<u8>>,
    
    #[asn1(context_specific = "9", optional = "true")]
    pub tcb_type: Option<Vec<u8>>,
    
    #[asn1(context_specific = "10", optional = "true")]
    pub flags_mask: Option<der::asn1::BitString>,
}

#[derive(der::Sequence)]
pub struct Fwid<'a> {
    pub hash_alg: der::asn1::ObjectIdentifier,
    #[asn1(type = "OCTET STRING")]
    pub digest: &'a [u8],
}

/// Asymmetric Key using RustCrypto traits
pub trait AsymKey: Default {
    /// Retrieve Private Key
    fn priv_key(&self) -> &signature::Signer;

    /// Retrieve Public Key
    fn pub_key(&self) -> &[u8];

    /// Retrieve SHA-256 digest of the public key
    fn sha256(&self) -> [u8; 32] {
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(self.pub_key());
        hasher.finalize().into()
    }

    /// Retrieve SHA1 digest of the public key
    fn sha1(&self) -> [u8; 20] {
        use sha1::{Sha1, Digest};
        let mut hasher = Sha1::new();
        hasher.update(self.pub_key());
        hasher.finalize().into()
    }

    /// Retrieve the hex string of SHA-256 Digest of the public key
    fn hex_str(&self) -> String {
        hex::encode(self.sha256()).to_uppercase()
    }
}

/// Digest trait for hash algorithms
pub trait Digest {
    /// Digest Algorithm
    fn algo() -> &'static digest::Algorithm;
}

/// Signing Algorithm trait using RustCrypto
pub trait SigningAlgorithm: Default {
    type AsymKey: AsymKey;
    type Digest: Digest;

    /// Generate Asymmetric Key Pair
    fn gen_key(&self) -> Self::AsymKey;

    /// Retrieve digest algorithm
    fn digest(&self) -> &'static digest::Algorithm {
        Self::Digest::algo()
    }
}

/// ECC-384 Asymmetric Key Pair
pub struct Ecc384AsymKey {
    signing_key: SigningKey,
    pub_key: Vec<u8>,
}

impl Default for Ecc384AsymKey {
    fn default() -> Self {
        // Generate a random key pair
        let signing_key = SigningKey::random(&mut OsRng);
        // Get the public key in uncompressed format
        let pub_key = VerifyingKey::from(&signing_key)
            .to_encoded_point(false)
            .as_bytes()
            .to_vec();
        
        Self {
            signing_key,
            pub_key,
        }
    }
}

impl AsymKey for Ecc384AsymKey {
    fn priv_key(&self) -> SigningKey {
        &self.signing_key
    }

    fn pub_key(&self) -> &[u8] {
        &self.pub_key
    }
}

bitfields::bitfields! {
    /// Key Usage flags
    #[derive(Default)]
    pub struct KeyUsage: u16 {
        const DIGITAL_SIGNATURE = 0x0001;
        const NON_REPUDIATION = 0x0002;
        const KEY_ENCIPHERMENT = 0x0004;
        const DATA_ENCIPHERMENT = 0x0008;
        const KEY_AGREEMENT = 0x0010;
        const KEY_CERT_SIGN = 0x0020;
        const CRL_SIGN = 0x0040;
        const ENCIPHER_ONLY = 0x0080;
        const DECIPHER_ONLY = 0x0100;
    }
}

/* Key Usage and Extension building functions */
pub fn make_basic_constraints_ext(ca: bool, path_len: u32) -> x509_cert::ext::Extension {
    let bc = x509_cert::ext::pkix::BasicConstraints {
        ca,
        path_len_constraint: if ca { Some(path_len as u8) } else { None },
    };
    bc.to_extension(&x509_cert::name::Name::default(), &[]).unwrap()
}

pub fn make_key_usage_ext(usage: KeyUsage) -> x509_cert::ext::Extension {
    let mut ku = x509_cert::ext::pkix::KeyUsage::default();
    
    if usage.contains(KeyUsage::DIGITAL_SIGNATURE) { ku.set_bit(0, true); }
    if usage.contains(KeyUsage::NON_REPUDIATION) { ku.set_bit(1, true); }
    if usage.contains(KeyUsage::KEY_ENCIPHERMENT) { ku.set_bit(2, true); }
    if usage.contains(KeyUsage::DATA_ENCIPHERMENT) { ku.set_bit(3, true); }
    if usage.contains(KeyUsage::KEY_AGREEMENT) { ku.set_bit(4, true); }
    if usage.contains(KeyUsage::KEY_CERT_SIGN) { ku.set_bit(5, true); }
    if usage.contains(KeyUsage::CRL_SIGN) { ku.set_bit(6, true); }
    if usage.contains(KeyUsage::ENCIPHER_ONLY) { ku.set_bit(7, true); }
    if usage.contains(KeyUsage::DECIPHER_ONLY) { ku.set_bit(8, true); }

    ku.to_extension(&x509_cert::name::Name::default(), &[]).unwrap()
}

pub fn make_tcg_ueid_ext(ueid: &[u8]) -> x509_cert::ext::Extension {
    x509_cert::ext::Extension {
        extn_id: der::::ObjectIdentifier::new_unwrap(TCG_UEID_OID),
        critical: false,
        extn_value: der::asn1::AnyRef::from_der(ueid).unwrap().into_owned(),
    }
}

pub fn make_subj_key_id_ext(key_id: &[u8]) -> x509_cert::ext::Extension {
    // Create a SubjectKeyIdentifier with the key ID as an OctetString
    let ski = x509_cert::ext::pkix::SubjectKeyIdentifier(der::asn1::OctetString::new(key_id).unwrap());
    // Use AsExtension trait to create the extension
    ski.to_extension(&x509_cert::name::Name::default(), &[]).unwrap()
}

pub fn make_auth_key_id_ext(key_id: &[u8]) -> x509_cert::ext::Extension {
    // Create an AuthorityKeyIdentifier with just the key identifier field
    let aki = x509_cert::ext::pkix::AuthorityKeyIdentifier {
        key_identifier: Some(der::asn1::OctetString::new(key_id).unwrap()),
        authority_cert_issuer: None,
        authority_cert_serial: None,
    };
    // Use AsExtension trait to create the extension
    aki.to_extension(&x509_cert::name::Name::default(), &[]).unwrap()
}
