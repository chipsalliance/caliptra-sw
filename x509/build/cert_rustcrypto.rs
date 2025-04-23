/*++

Licensed under the Apache-2.0 license.

File Name:

    cert_rustcrypto.rs

Abstract:

    File contains generation of X509 Certificate Signing Request (CERT) To Be Signed (TBS)
    template using RustCrypto that can be substituted at firmware runtime.

--*/
use std::str::FromStr;

use crate::tbs::{get_tbs, init_param, sanitize, TbsParam, TbsTemplate};
use const_oid::{AssociatedOid, ObjectIdentifier};
use core::marker::PhantomData;
use der::asn1::UtcTime;
use der::DateTime;
use der::Decode;
use der::Sequence;
use ml_dsa::{KeyGen, MlDsa87};
use sha2::{Digest, Sha256};
use signature::Keypair;
use spki::EncodePublicKey;

use x509_cert::builder::{Builder, CertificateBuilder, Profile};
use x509_cert::der::Encode;
use x509_cert::ext::{
    pkix::{AuthorityKeyIdentifier, BasicConstraints, KeyUsage, SubjectKeyIdentifier},
    AsExtension, Extension,
};
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::time::Time;
use x509_cert::time::Validity;

/// CSR Template Param
struct CertTemplateParam {
    tbs_param: TbsParam,
    needle: Vec<u8>,
}

#[derive(Sequence, Default, Debug)]
struct TcgUeid<'a> {
    #[asn1(type = "OCTET STRING")]
    ueid: &'a [u8],
}

impl AssociatedOid for TcgUeid<'_> {
    const OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.23.133.5.4.4");
}

impl AsExtension for TcgUeid<'_> {
    fn critical(&self, _subject: &Name, _extensions: &[Extension]) -> bool {
        true
    }
}

#[derive(Sequence, Debug)]
pub struct Fwid<'a> {
    pub hash_alg: ObjectIdentifier,
    #[asn1(type = "BIT STRING")]
    pub digest: &'a [u8],
}

pub struct FwidParam<'a> {
    pub name: &'static str,
    pub fwid: Fwid<'a>,
}

const TCG_MULTI_TCB_INFO_OID: &str = "2.23.133.5.4.5";

fn fixed_width_svn(svn: u8) -> u16 {
    (1_u16 << 8) | svn as u16
}

#[derive(Sequence, Debug)]
struct MultiTcbInfo<'a> {
    tcb_infos: Vec<TcbInfo<'a>>,
}

impl AssociatedOid for MultiTcbInfo<'_> {
    const OID: ObjectIdentifier = ObjectIdentifier::new_unwrap(TCG_MULTI_TCB_INFO_OID);
}

impl AsExtension for MultiTcbInfo<'_> {
    fn critical(&self, _subject: &Name, _extensions: &[Extension]) -> bool {
        true
    }
}

#[derive(Sequence, Debug)]
#[asn1(tag_mode = "IMPLICIT")]
struct TcbInfo<'a> {
    #[asn1(context_specific = "0", optional = "true", type = "UTF8String")]
    vendor: Option<String>,

    #[asn1(context_specific = "1", optional = "true", type = "UTF8String")]
    model: Option<String>,

    #[asn1(context_specific = "2", optional = "true", type = "UTF8String")]
    version: Option<String>,

    #[asn1(context_specific = "3", optional = "true", tag_mode = "IMPLICIT")]
    svn: Option<u32>,

    #[asn1(context_specific = "4", optional = "true", tag_mode = "IMPLICIT")]
    layer: Option<u64>,

    #[asn1(context_specific = "5", optional = "true", tag_mode = "IMPLICIT")]
    index: Option<u64>,

    #[asn1(context_specific = "6", optional = "true", tag_mode = "IMPLICIT")]
    fwids: Option<Vec<Fwid<'a>>>,

    #[asn1(
        context_specific = "7",
        optional = "true",
        type = "BIT STRING",
        tag_mode = "IMPLICIT"
    )]
    flags: Option<&'a [u8]>,

    #[asn1(
        context_specific = "8",
        optional = "true",
        type = "OCTET STRING",
        tag_mode = "IMPLICIT"
    )]
    vendor_info: Option<&'a [u8]>,

    #[asn1(
        context_specific = "9",
        optional = "true",
        type = "OCTET STRING",
        tag_mode = "IMPLICIT"
    )]
    tcb_type: Option<&'a [u8]>,

    #[asn1(
        context_specific = "10",
        optional = "true",
        type = "BIT STRING",
        tag_mode = "IMPLICIT"
    )]
    flags_mask: Option<&'a [u8]>,
}

impl AssociatedOid for TcbInfo<'_> {
    const OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.23.133.5.4.1");
}

impl AsExtension for TcbInfo<'_> {
    fn critical(&self, _subject: &Name, _extensions: &[Extension]) -> bool {
        true
    }
}

/// CSR Tempate Builder
pub struct CertTemplateBuilder<'a, Key> {
    basic_constraints: Option<BasicConstraints>,
    key_usage: Option<KeyUsage>,
    tcg_ueid: Option<TcgUeid<'a>>,
    multi_tcb_info: Option<MultiTcbInfo<'a>>,
    single_tcb_info: Option<TcbInfo<'a>>,
    params: Vec<CertTemplateParam>,
    _phantom: PhantomData<Key>,
}

pub trait BuilderKeys: Sized {
    type Signature: spki::SignatureBitStringEncoding;
    fn key_gen() -> Self;
}

impl BuilderKeys for ml_dsa::KeyPair<MlDsa87> {
    type Signature = ml_dsa::Signature<MlDsa87>;
    fn key_gen() -> Self {
        let mut rng = rand::thread_rng();
        <MlDsa87 as KeyGen>::key_gen(&mut rng)
    }
}

impl<'a, Key> CertTemplateBuilder<'a, Key>
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
            multi_tcb_info: None,
            single_tcb_info: None,
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
        let param = CertTemplateParam {
            tbs_param: TbsParam::new("UEID", 0, ueid.len()),
            needle: ueid.to_vec(),
        };
        self.params.push(param);

        self
    }

    pub fn add_fmc_dice_tcb_info_ext(
        mut self,
        device_fwids: &'a [FwidParam<'a>],
        fmc_fwids: &'a [FwidParam<'a>],
    ) -> Self {
        // This method of finding the offsets is fragile. Especially for the 1 byte values.
        // These may need to be updated to stay unique when the cert template is updated.
        let flags: u32 = 0xC0C1C2C3;
        let svn: u8 = 0xC4;
        let svn_fuses: u8 = 0xC6;

        let wide_svn = fixed_width_svn(svn);
        let wide_svn_fuses = fixed_width_svn(svn_fuses);

        // No need to create a local variable for the mask

        // Create the device info TcbInfo
        let device_fwids_vec: Vec<Fwid> = device_fwids
            .iter()
            .map(|f| Fwid {
                hash_alg: f.fwid.hash_alg,
                digest: f.fwid.digest,
            })
            .collect();

        let device_info = TcbInfo {
            vendor: None,
            model: None,
            version: None,
            svn: Some(wide_svn_fuses as u32),
            layer: None,
            index: None,
            fwids: Some(device_fwids_vec),
            flags: Some(&[0xc0, 0xc1, 0xc2, 0xc3]),
            vendor_info: None,
            tcb_type: Some(b"DEVICE_INFO"),
            // Directly insert the flag mask bytes (FLAG_MASK.reverse_bits().to_be_bytes())
            // DICE flag bits
            // const FLAG_BIT_NOT_CONFIGURED: u32 = 1 << 0;
            // const FLAG_BIT_NOT_SECURE: u32 = 1 << 1;
            // const FLAG_BIT_DEBUG: u32 = 1 << 3;
            // const FLAG_BIT_FIXED_WIDTH: u32 = 1 << 31;
            flags_mask: Some(&[0xD0, 0x00, 0x00, 0x01]),
        };

        // Create the FMC info TcbInfo
        let fmc_fwids_vec: Vec<Fwid> = fmc_fwids
            .iter()
            .map(|f| Fwid {
                hash_alg: f.fwid.hash_alg,
                digest: f.fwid.digest,
            })
            .collect();

        let fmc_info = TcbInfo {
            vendor: None,
            model: None,
            version: None,
            svn: Some(wide_svn as u32),
            layer: None,
            index: None,
            fwids: Some(fmc_fwids_vec),
            flags: None,
            vendor_info: None,
            tcb_type: Some(b"FMC_INFO"),
            flags_mask: None,
        };

        // Create the MultiTcbInfo extension
        let multi_tcb_info = MultiTcbInfo {
            tcb_infos: vec![device_info, fmc_info],
        };

        // Add parameters for template generation
        self.params.push(CertTemplateParam {
            tbs_param: TbsParam::new("tcb_info_flags", 0, std::mem::size_of_val(&flags)),
            needle: flags.to_be_bytes().to_vec(),
        });

        self.params.push(CertTemplateParam {
            tbs_param: TbsParam::new("tcb_info_fw_svn", 0, std::mem::size_of_val(&svn)),
            needle: svn.to_be_bytes().to_vec(),
        });

        self.params.push(CertTemplateParam {
            tbs_param: TbsParam::new(
                "tcb_info_fw_svn_fuses",
                0,
                std::mem::size_of_val(&svn_fuses),
            ),
            needle: svn_fuses.to_be_bytes().to_vec(),
        });

        for fwid in device_fwids.iter().chain(fmc_fwids.iter()) {
            self.params.push(CertTemplateParam {
                tbs_param: TbsParam::new(fwid.name, 0, fwid.fwid.digest.len()),
                needle: fwid.fwid.digest.to_vec(),
            });
        }

        self.multi_tcb_info = Some(multi_tcb_info);

        // TODO: Complete implementation to add the extension to the certificate builder
        // This part would require more work with the RustCrypto builder API

        self
    }

    pub fn add_rt_dice_tcb_info_ext(mut self, svn: u8, fwids: &'a [FwidParam<'a>]) -> Self {
        let wide_svn = fixed_width_svn(svn);

        // Create the RT info TcbInfo
        let rt_fwids_vec: Vec<Fwid> = fwids
            .iter()
            .map(|f| Fwid {
                hash_alg: f.fwid.hash_alg,
                digest: f.fwid.digest,
            })
            .collect();

        let rt_info = TcbInfo {
            vendor: None,
            model: None,
            version: None,
            svn: Some(wide_svn as u32),
            layer: None,
            index: None,
            fwids: Some(rt_fwids_vec),
            flags: None,
            vendor_info: None,
            tcb_type: Some(b"RT_INFO"),
            flags_mask: None,
        };

        // Add parameters for template generation
        self.params.push(CertTemplateParam {
            tbs_param: TbsParam::new("tcb_info_fw_svn", 0, std::mem::size_of_val(&svn)),
            needle: svn.to_be_bytes().to_vec(),
        });

        for fwid in fwids.iter() {
            self.params.push(CertTemplateParam {
                tbs_param: TbsParam::new(fwid.name, 0, fwid.fwid.digest.len()),
                needle: fwid.fwid.digest.to_vec(),
            });
        }

        // Store the TcbInfo
        self.single_tcb_info = Some(rt_info);

        self
    }

    pub fn tbs_template(mut self, subject_cn: &str, issuer_cn: &str) -> TbsTemplate {
        let subject_key = Key::key_gen();
        let issuer_key = Key::key_gen();

        // Set the valid from time
        let not_before_dt = DateTime::new(2023, 1, 1, 0, 0, 0).unwrap();
        let not_before = UtcTime::from_date_time(not_before_dt).unwrap();
        let param = CertTemplateParam {
            tbs_param: TbsParam::new("NOT_BEFORE", 0, not_before.to_der().unwrap().len() - 2),
            needle: not_before.to_der().unwrap()[2..].to_vec(),
        };
        self.params.push(param);

        // Set the valid to time
        let not_after_dt = DateTime::new(2049, 12, 31, 23, 59, 59).unwrap();
        let not_after = UtcTime::from_date_time(not_after_dt).unwrap();
        let param = CertTemplateParam {
            tbs_param: TbsParam::new("NOT_AFTER", 0, not_after.to_der().unwrap().len() - 2),
            needle: not_after.to_der().unwrap()[2..].to_vec(),
        };
        self.params.push(param);

        let validity = Validity {
            not_before: Time::UtcTime(not_before),
            not_after: Time::UtcTime(not_after),
        };

        // Set the serial number
        let serial_number_bytes = [0x7fu8; 20];
        let serial_number = SerialNumber::new(&serial_number_bytes).unwrap();
        let param = CertTemplateParam {
            tbs_param: TbsParam::new("SERIAL_NUMBER", 0, serial_number_bytes.len()),
            needle: serial_number_bytes.to_vec(),
        };
        self.params.push(param);

        // Get the subject public key and encode it
        let subject_pk_der = subject_key.verifying_key().to_public_key_der().unwrap();
        // Parse DER to obtain SubjectPublicKeyInfo and extract public key bytes
        let subject_spki: spki::SubjectPublicKeyInfo<der::asn1::Any, der::asn1::BitString> =
            spki::SubjectPublicKeyInfo::from_der(subject_pk_der.as_bytes()).unwrap();
        let subject_pk_bytes = subject_spki.subject_public_key.as_bytes().unwrap().to_vec();
        let param = CertTemplateParam {
            tbs_param: TbsParam::new("PUBLIC_KEY", 0, subject_pk_bytes.len()),
            needle: subject_pk_bytes.clone(),
        };
        self.params.push(param);

        let subject_key_hash = hex::encode(Sha256::digest(&subject_pk_bytes)).to_uppercase();
        let subject = format!("CN={},serialNumber={}", subject_cn, subject_key_hash);
        let subject_name = Name::from_str(&subject).unwrap();
        let param = CertTemplateParam {
            tbs_param: TbsParam::new("SUBJECT_SN", 0, subject_key_hash.len()),
            needle: subject_key_hash.into_bytes(),
        };
        self.params.push(param);

        // Get the issuer public key and encode it
        let issuer_pk_der = issuer_key.verifying_key().to_public_key_der().unwrap();
        // Parse DER to obtain SubjectPublicKeyInfo and extract public key bytes
        let issuer_spki: spki::SubjectPublicKeyInfo<der::asn1::Any, der::asn1::BitString> =
            spki::SubjectPublicKeyInfo::from_der(issuer_pk_der.as_bytes()).unwrap();
        let issuer_pk_bytes = issuer_spki.subject_public_key.as_bytes().unwrap().to_vec();

        let issuer_key_hash = hex::encode(Sha256::digest(&issuer_pk_bytes)).to_uppercase();
        let issuer = format!("CN={},serialNumber={}", issuer_cn, issuer_key_hash);
        let issuer_name = Name::from_str(&issuer).unwrap();
        let profile = Profile::Manual {
            issuer: Some(issuer_name),
        };
        let param = CertTemplateParam {
            tbs_param: TbsParam::new("ISSUER_SN", 0, issuer_key_hash.len()),
            needle: issuer_key_hash.into_bytes(),
        };
        self.params.push(param);

        // Clone subject_spki before passing it to CertificateBuilder because it's needed later
        let mut builder = CertificateBuilder::new(
            profile,
            serial_number,
            validity,
            subject_name,
            subject_spki.clone(),
            &issuer_key,
        )
        .expect("Create certificate");

        if let Some(basic_constraints) = self.basic_constraints {
            builder.add_extension(&basic_constraints).unwrap();
        }
        if let Some(key_usage) = self.key_usage {
            builder.add_extension(&key_usage).unwrap();
        }
        if let Some(ueid) = self.tcg_ueid {
            builder.add_extension(&ueid).unwrap();
        }
        if let Some(ref multi_tcb_info) = self.multi_tcb_info {
            builder.add_extension(multi_tcb_info).unwrap();
        }

        if let Some(ref single_tcb_info) = self.single_tcb_info {
            builder.add_extension(single_tcb_info).unwrap();
        }

        // Add Subject Key Identifier
        let subject_key_bytes = subject_spki.subject_public_key.as_bytes().unwrap();
        let subject_key_hash = sha1::Sha1::digest(subject_key_bytes).as_slice().to_vec();
        let subject_key_octet = der::asn1::OctetString::new(subject_key_hash.clone()).unwrap();
        let subject_key_id = SubjectKeyIdentifier::from(subject_key_octet);
        builder.add_extension(&subject_key_id).unwrap();

        // Add Authority Key Identifier
        let issuer_key_bytes = issuer_spki.subject_public_key.as_bytes().unwrap();
        let issuer_key_hash = sha1::Sha1::digest(issuer_key_bytes).as_slice().to_vec();
        let authority_key_id = AuthorityKeyIdentifier {
            key_identifier: Some(der::asn1::OctetString::new(issuer_key_hash.clone()).unwrap()),
            authority_cert_issuer: None,
            authority_cert_serial_number: None,
        };
        builder.add_extension(&authority_key_id).unwrap();

        // Add parameters for template generation
        self.params.push(CertTemplateParam {
            tbs_param: TbsParam::new("SUBJECT_KEY_ID", 0, subject_key_hash.len()),
            needle: subject_key_hash,
        });

        self.params.push(CertTemplateParam {
            tbs_param: TbsParam::new("AUTHORITY_KEY_ID", 0, issuer_key_hash.len()),
            needle: issuer_key_hash,
        });

        let req = builder.build().unwrap();
        let der = req.to_der().unwrap();

        // Retrieve the To be signed portion from the CSR
        let mut tbs = get_tbs(der);

        // Match long params first to ensure a subset is not sanitized by a short param.
        self.params
            .sort_by(|a, b| a.needle.len().cmp(&b.needle.len()).reverse());

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
