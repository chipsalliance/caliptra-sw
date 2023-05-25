/*++

Licensed under the Apache-2.0 license.

File Name:

    x509.rs

Abstract:

    File contains helper functions for cryptography and X509 object manipulation

--*/

use caliptra_common::dice;

use hex::ToHex;

use openssl::bn::BigNumContext;
use openssl::ec::EcGroup;
use openssl::ec::EcKey;
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

const FLAG_MASK: u32 = dice::FLAG_BIT_NOT_CONFIGURED
    | dice::FLAG_BIT_NOT_SECURE
    | dice::FLAG_BIT_DEBUG
    | dice::FLAG_BIT_FIXED_WIDTH;

const AUTH_KEY_ID_OID: &str = "2.5.29.35";
const TCG_UEID_OID: &str = "2.23.133.5.4.4";
const TCG_TCB_INFO_OID: &str = "2.23.133.5.4.1";
const TCG_MULTI_TCB_INFO_OID: &str = "2.23.133.5.4.5";

#[derive(asn1::Asn1Write)]
struct TcbInfo<'a> {
    #[implicit(0)]
    vendor: Option<asn1::Utf8String<'a>>,
    #[implicit(1)]
    model: Option<asn1::Utf8String<'a>>,
    #[implicit(2)]
    version: Option<asn1::Utf8String<'a>>,
    #[implicit(3)]
    svn: Option<u32>,
    #[implicit(4)]
    layer: Option<u64>,
    #[implicit(5)]
    index: Option<u64>,
    #[implicit(6)]
    fwids: Option<asn1::SequenceOfWriter<'a, &'a Fwid<'a>>>,
    #[implicit(7)]
    flags: Option<asn1::BitString<'a>>,
    #[implicit(8)]
    vendor_info: Option<&'a [u8]>,
    #[implicit(9)]
    tcb_type: Option<&'a [u8]>,
    #[implicit(10)]
    flags_mask: Option<asn1::BitString<'a>>,
}

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
        let ecc_group = EcGroup::from_curve_name(Nid::SECP384R1).unwrap();
        let priv_key = EcKey::generate(&ecc_group).unwrap();
        let mut bn_ctx = BigNumContext::new().unwrap();
        let pub_key = priv_key
            .public_key()
            .to_bytes(&ecc_group, PointConversionForm::UNCOMPRESSED, &mut bn_ctx)
            .unwrap();
        Self {
            priv_key: PKey::from_ec_key(priv_key).unwrap(),
            pub_key,
        }
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

    X509Extension::new(None, None, TCG_UEID_OID, &der_str).unwrap()
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

    X509Extension::new(None, None, AUTH_KEY_ID_OID, &der_str).unwrap()
}

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
pub struct Fwid<'a> {
    pub(crate) hash_alg: asn1::ObjectIdentifier,
    pub(crate) digest: &'a [u8],
}

pub struct FwidParam<'a> {
    pub(crate) name: &'static str,
    pub(crate) fwid: Fwid<'a>,
}

fn fixed_width_svn(svn: u8) -> u16 {
    (1_u16 << 8) | svn as u16
}

// Make a tcg-dice-MultiTcbInfo extension
pub fn make_fmc_dice_tcb_info_ext(
    flags: u32,
    svn: u8,
    svn_fuses: u8,
    fwids: &[FwidParam],
) -> X509Extension {
    let wide_svn = fixed_width_svn(svn);
    let wide_svn_fuses = fixed_width_svn(svn_fuses);

    let be_flags = flags.to_be_bytes();
    let be_flags_mask = FLAG_MASK.to_be_bytes();

    let device_info = TcbInfo {
        vendor: Some(asn1::Utf8String::new("Caliptra")),
        model: Some(asn1::Utf8String::new("Device")),
        version: None,
        svn: Some(wide_svn_fuses.into()),
        layer: None,
        index: None,
        fwids: None,
        flags: asn1::BitString::new(be_flags.as_ref(), 0),
        vendor_info: None,
        tcb_type: None,
        flags_mask: asn1::BitString::new(be_flags_mask.as_ref(), 0),
    };

    let asn1_fwids: Vec<&Fwid> = fwids.iter().map(|f| &f.fwid).collect();

    let fmc_info = TcbInfo {
        vendor: Some(asn1::Utf8String::new("Caliptra")),
        model: Some(asn1::Utf8String::new("FMC")),
        version: None,
        svn: Some(wide_svn.into()),
        layer: None,
        index: None,
        fwids: Some(asn1::SequenceOfWriter::new(&asn1_fwids)),
        flags: None,
        vendor_info: None,
        tcb_type: None,
        flags_mask: None,
    };

    let tcb_infos = asn1::SequenceOfWriter::new(vec![&device_info, &fmc_info]);

    let der = asn1::write_single(&tcb_infos).unwrap();
    let der_str = format!("DER:{}", hex::encode(der).to_uppercase());
    X509Extension::new(None, None, TCG_MULTI_TCB_INFO_OID, &der_str).unwrap()
}

// Make a tcg-dice-TcbInfo extension
pub fn make_rt_dice_tcb_info_ext(svn: u8, fwids: &[FwidParam]) -> X509Extension {
    let wide_svn = fixed_width_svn(svn);
    let asn1_fwids: Vec<&Fwid> = fwids.iter().map(|f| &f.fwid).collect();

    let rt_info = TcbInfo {
        vendor: Some(asn1::Utf8String::new("Caliptra")),
        model: Some(asn1::Utf8String::new("RT")),
        version: None,
        svn: Some(wide_svn.into()),
        layer: None,
        index: None,
        fwids: Some(asn1::SequenceOfWriter::new(&asn1_fwids)),
        flags: None,
        vendor_info: None,
        tcb_type: None,
        flags_mask: None,
    };

    let der = asn1::write_single(&rt_info).unwrap();
    let der_str = format!("DER:{}", hex::encode(der).to_uppercase());
    X509Extension::new(None, None, TCG_TCB_INFO_OID, &der_str).unwrap()
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
    let pos = haystack.windows(param.len).position(|w| w == needle);

    match pos {
        Some(offset) => TbsParam { offset, ..param },
        None => panic!(
            "Could not find needle '{}' with value\n\n{}\n\nin haystack\n\n{}",
            param.name,
            needle.encode_hex::<String>(),
            haystack.encode_hex::<String>()
        ),
    }
}

/// Sanitize the TBS buffer for the specified parameter
pub fn sanitize(param: TbsParam, buf: &mut [u8]) -> TbsParam {
    for byte in buf.iter_mut().skip(param.offset).take(param.len) {
        *byte = 0x5F;
    }
    param
}
