/*++

Licensed under the Apache-2.0 license.

File Name:

    x509.rs

Abstract:

    File contains helper functions for cryptography and X509 object manipulation

--*/

use openssl::asn1::{Asn1Object, Asn1OctetString};
use openssl::bn::BigNumContext;
use openssl::ec::EcGroup;
use openssl::ec::EcKey;
use openssl::ec::PointConversionForm;
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::PKey;
use openssl::pkey::{Private, Public};
use openssl::pkey_ml_dsa::{PKeyMlDsaBuilder, PKeyMlDsaParams, Variant as MlDsaVariant};
use openssl::pkey_ml_kem::{PKeyMlKemBuilder, PKeyMlKemParams, Variant as MlKemVariant};
use openssl::sha::Sha1;
use openssl::sha::Sha256;
use openssl::x509::extension::BasicConstraints;
use openssl::x509::extension::KeyUsage as Usage;
use openssl::x509::extension::SubjectKeyIdentifier;
use openssl::x509::X509Extension;
use openssl::x509::X509v3Context;
use rand::Rng;

const FLAG_BIT_NOT_CONFIGURED: u32 = 1 << 0;
const FLAG_BIT_NOT_SECURE: u32 = 1 << 1;
const FLAG_BIT_DEBUG: u32 = 1 << 3;
const FLAG_BIT_FIXED_WIDTH: u32 = 1 << 31;

const FLAG_MASK: u32 =
    FLAG_BIT_NOT_CONFIGURED | FLAG_BIT_NOT_SECURE | FLAG_BIT_DEBUG | FLAG_BIT_FIXED_WIDTH;

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

/// ML-DSA87 Asymmetric Key Pair
pub struct MlDsa87AsymKey {
    priv_key: PKey<Private>,
    pub_key: Vec<u8>,
}

impl AsymKey for MlDsa87AsymKey {
    /// Retrieve Private Key
    fn priv_key(&self) -> &PKey<Private> {
        &self.priv_key
    }

    /// Retrieve Public Key
    fn pub_key(&self) -> &[u8] {
        &self.pub_key
    }
}

impl Default for MlDsa87AsymKey {
    /// Returns the "default value" for a type.
    fn default() -> Self {
        let mut random_bytes: [u8; 32] = [0; 32];
        let mut rng = rand::thread_rng();
        rng.fill(&mut random_bytes);
        let pk_builder =
            PKeyMlDsaBuilder::<Private>::from_seed(MlDsaVariant::MlDsa87, &random_bytes).unwrap();
        let private_key = pk_builder.build().unwrap();
        let public_params = PKeyMlDsaParams::<Public>::from_pkey(&private_key).unwrap();
        let public_key = public_params.public_key().unwrap();
        Self {
            priv_key: private_key,
            pub_key: public_key.to_vec(),
        }
    }
}

/// Nothing as MLDSA has it's internal hashing scheme
pub struct Noop {}

impl Digest for Noop {
    /// Retrieve the algorithm
    fn algo() -> MessageDigest {
        MessageDigest::null()
    }
}

#[derive(Default)]
pub struct MlDsa87Algo {}

impl SigningAlgorithm for MlDsa87Algo {
    type AsymKey = MlDsa87AsymKey;
    type Digest = Noop;

    fn gen_key(&self) -> Self::AsymKey {
        Self::AsymKey::default()
    }
}

pub struct MlKem1024Key {
    priv_key: PKey<Private>,
    pub_key: Vec<u8>,
}

#[derive(Default)]
pub struct MlKem1024Algo {}

impl SigningAlgorithm for MlKem1024Algo {
    type AsymKey = MlKem1024Key;
    type Digest = Noop;

    fn gen_key(&self) -> Self::AsymKey {
        Self::AsymKey::default()
    }
}

impl AsymKey for MlKem1024Key {
    /// Retrieve Public Key
    fn pub_key(&self) -> &[u8] {
        &self.pub_key
    }

    /// Retrieve Private Key
    fn priv_key(&self) -> &PKey<Private> {
        &self.priv_key
    }
}

impl Default for MlKem1024Key {
    /// Returns the "default value" for a type.
    fn default() -> Self {
        let mut random_bytes: [u8; 64] = [0; 64];
        let mut rng = rand::thread_rng();
        rng.fill(&mut random_bytes);
        let pk_builder =
            PKeyMlKemBuilder::<Private>::from_seed(MlKemVariant::MlKem1024, &random_bytes).unwrap();
        let private_key = pk_builder.build().unwrap();
        let public_params = PKeyMlKemParams::<Public>::from_pkey(&private_key).unwrap();
        let public_key = public_params.public_key().unwrap();
        Self {
            priv_key: private_key,
            pub_key: public_key.to_vec(),
        }
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
    let mut usage: Usage = key_usage.into();
    usage.critical().build().unwrap()
}

/// Make TCG UEID extension
pub fn make_tcg_ueid_ext(ueid: &[u8]) -> X509Extension {
    #[derive(asn1::Asn1Read, asn1::Asn1Write)]
    struct TcgUeid<'a> {
        ueid: &'a [u8],
    }

    let tcg_ueid = TcgUeid { ueid };
    let der = asn1::write_single(&tcg_ueid).unwrap();
    let der = Asn1OctetString::new_from_bytes(&der).unwrap();
    let oid = Asn1Object::from_str(TCG_UEID_OID).unwrap();
    X509Extension::new_from_der(&oid, false, &der).unwrap()
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
    let der = Asn1OctetString::new_from_bytes(&der).unwrap();
    let oid = Asn1Object::from_str(AUTH_KEY_ID_OID).unwrap();
    X509Extension::new_from_der(&oid, false, &der).unwrap()
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
    device_fwids: &[FwidParam],
    fmc_fwids: &[FwidParam],
) -> X509Extension {
    let wide_svn = fixed_width_svn(svn);
    let wide_svn_fuses = fixed_width_svn(svn_fuses);

    let be_flags = flags.to_be_bytes();
    let be_flags_mask = FLAG_MASK.reverse_bits().to_be_bytes();

    let device_asn1_fwids: Vec<&Fwid> = device_fwids.iter().map(|f| &f.fwid).collect();
    let device_info = TcbInfo {
        vendor: None,
        model: None,
        version: None,
        svn: Some(wide_svn_fuses.into()),
        layer: None,
        index: None,
        fwids: Some(asn1::SequenceOfWriter::new(&device_asn1_fwids)),
        flags: asn1::BitString::new(be_flags.as_ref(), 0),
        vendor_info: None,
        tcb_type: Some(b"DEVICE_INFO"),
        flags_mask: asn1::BitString::new(be_flags_mask.as_ref(), 0),
    };

    let fmc_asn1_fwids: Vec<&Fwid> = fmc_fwids.iter().map(|f| &f.fwid).collect();
    let fmc_info = TcbInfo {
        vendor: None,
        model: None,
        version: None,
        svn: Some(wide_svn.into()),
        layer: None,
        index: None,
        fwids: Some(asn1::SequenceOfWriter::new(&fmc_asn1_fwids)),
        flags: None,
        vendor_info: None,
        tcb_type: Some(b"FMC_INFO"),
        flags_mask: None,
    };

    let tcb_infos = asn1::SequenceOfWriter::new(vec![&device_info, &fmc_info]);

    let der = asn1::write_single(&tcb_infos).unwrap();
    let der = Asn1OctetString::new_from_bytes(&der).unwrap();
    let oid = Asn1Object::from_str(TCG_MULTI_TCB_INFO_OID).unwrap();
    X509Extension::new_from_der(&oid, false, &der).unwrap()
}

// Make a tcg-dice-TcbInfo extension
pub fn make_rt_dice_tcb_info_ext(svn: u8, fwids: &[FwidParam]) -> X509Extension {
    let wide_svn = fixed_width_svn(svn);
    let asn1_fwids: Vec<&Fwid> = fwids.iter().map(|f| &f.fwid).collect();

    let rt_info = TcbInfo {
        vendor: None,
        model: None,
        version: None,
        svn: Some(wide_svn.into()),
        layer: None,
        index: None,
        fwids: Some(asn1::SequenceOfWriter::new(&asn1_fwids)),
        flags: None,
        vendor_info: None,
        tcb_type: Some(b"RT_INFO"),
        flags_mask: None,
    };

    let der = asn1::write_single(&rt_info).unwrap();
    let der = Asn1OctetString::new_from_bytes(&der).unwrap();
    let oid = Asn1Object::from_str(TCG_TCB_INFO_OID).unwrap();
    X509Extension::new_from_der(&oid, false, &der).unwrap()
}

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
pub struct KemId(u16);
#[derive(asn1::Asn1Read, asn1::Asn1Write)]
pub struct KdfId(u16);
#[derive(asn1::Asn1Read, asn1::Asn1Write)]
pub struct AeadId(u16);

/// MEK MPA Spec v1
///
/// Section 4.2.2.1.3.1
#[derive(asn1::Asn1Read, asn1::Asn1Write)]
pub struct HPKEIdentifiers {
    kem_id: KemId,
    kdf_id: KdfId,
    aead_id: AeadId,
}

impl HPKEIdentifiers {
    pub fn new(kem_id: KemId, kdf_id: KdfId, aead_id: AeadId) -> Self {
        Self {
            kem_id,
            kdf_id,
            aead_id,
        }
    }
}

impl HPKEIdentifiers {
    // TCG_STORAGE_HPKE_
    pub const OID: &str = "2.23.133.21.1.1";

    /// KEM id's
    pub const ML_KEM_1024_IANA_CODE_POINT: KemId = KemId(0x0042);
    // TODO(clundin): This will be used in a follow up PR.
    #[allow(dead_code)]
    pub const ML_KEM_EC_P384_IANA_CODE_POINT: KemId = KemId(0x0052);
    pub const ECDH_P384_IANA_CODE_POINT: KemId = KemId(0x0011);

    /// KDF id's
    pub const HKDF_SHA384_IANA_CODE_POINT: KdfId = KdfId(0x0002);

    /// AEAD id's
    pub const AES_256_GCM_IANA_CODE_POINT: AeadId = AeadId(0x0002);
}

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
pub struct HPKEIdentifierExt<'a> {
    pub(crate) hpke_oid: asn1::ObjectIdentifier,
    pub(crate) critical: bool,
    pub(crate) extn_value: &'a [u8],
}

pub fn make_hpke_identifier_ext(identifiers: &HPKEIdentifiers) -> X509Extension {
    let der = asn1::write_single(&identifiers).unwrap();
    let der = Asn1OctetString::new_from_bytes(&der).unwrap();
    let oid = Asn1Object::from_str(HPKEIdentifiers::OID).unwrap();
    X509Extension::new_from_der(&oid, false, &der).unwrap()
}
