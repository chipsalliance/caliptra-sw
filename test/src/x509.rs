// Licensed under the Apache-2.0 license

use std::error::Error;

use asn1::{ObjectIdentifier, ParseError, Utf8String};

pub const DICE_TCB_INFO_OID: ObjectIdentifier = asn1::oid!(2, 23, 133, 5, 4, 1);
pub const DICE_MULTI_TCB_INFO_OID: ObjectIdentifier = asn1::oid!(2, 23, 133, 5, 4, 5);

#[derive(Eq, PartialEq)]
pub struct DiceFwid {
    pub hash_alg: asn1::ObjectIdentifier,
    pub digest: Vec<u8>,
}
impl std::fmt::Debug for DiceFwid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DiceFwid")
            .field("hash_alg", &format!("{}", &self.hash_alg))
            .field("digest", &format!("{:02x?}", self.digest))
            .finish()
    }
}

#[derive(Debug, Default, Eq, PartialEq)]
pub struct DiceTcbInfo {
    pub vendor: Option<String>,
    pub model: Option<String>,
    pub version: Option<String>,
    pub svn: Option<u32>,
    pub layer: Option<u32>,
    pub index: Option<u32>,
    pub fwids: Vec<DiceFwid>,
    pub flags: Option<u32>,
    pub vendor_info: Option<Vec<u8>>,
    pub ty: Option<Vec<u8>>,
}

impl DiceTcbInfo {
    fn parse(d: &mut asn1::Parser) -> Result<Self, asn1::ParseError> {
        let result = DiceTcbInfo {
            vendor: d
                .read_optional_implicit_element::<Utf8String>(0)?
                .map(|s| s.as_str().into()),
            model: d
                .read_optional_implicit_element::<Utf8String>(1)?
                .map(|s| s.as_str().into()),
            version: d
                .read_optional_implicit_element::<Utf8String>(2)?
                .map(|s| s.as_str().into()),
            svn: d.read_optional_implicit_element(3)?,
            layer: d.read_optional_implicit_element(4)?,
            index: d.read_optional_implicit_element(5)?,
            fwids: d
                .read_optional_implicit_element::<asn1::Sequence>(6)?
                .map(|s| {
                    s.parse(|d| {
                        let mut result = vec![];
                        while !d.is_empty() {
                            result.push(d.read_element::<asn1::Sequence>()?.parse(|d| {
                                Ok(DiceFwid {
                                    hash_alg: d.read_element()?,
                                    digest: d.read_element::<&[u8]>()?.to_vec(),
                                })
                            })?);
                        }
                        Ok(result)
                    })
                })
                .transpose()?
                .unwrap_or_default(),
            flags: d
                .read_optional_implicit_element::<asn1::BitString>(7)?
                .and_then(|b| b.as_bytes().try_into().ok())
                .map(u32::from_be_bytes),
            vendor_info: d
                .read_optional_implicit_element::<&[u8]>(8)?
                .map(|s| s.to_vec()),
            ty: d
                .read_optional_implicit_element::<&[u8]>(9)?
                .map(|s| s.to_vec()),
        };
        d.read_optional_implicit_element::<u32>(10).unwrap();
        Ok(result)
    }
    fn parse_single(d: &mut asn1::Parser) -> Result<Self, asn1::ParseError> {
        d.read_element::<asn1::Sequence>()?.parse(Self::parse)
    }
    fn parse_multiple(d: &mut asn1::Parser) -> Result<Vec<Self>, asn1::ParseError> {
        d.read_element::<asn1::Sequence>()?.parse(|d| {
            let mut result = vec![];
            while !d.is_empty() {
                result.push(d.read_element::<asn1::Sequence>()?.parse(Self::parse)?);
            }
            Ok(result)
        })
    }

    pub fn find_multiple_in_cert(cert_der: &[u8]) -> Result<Vec<Self>, asn1::ParseError> {
        let Some(ext_der) = get_cert_extension(cert_der, &DICE_MULTI_TCB_INFO_OID)? else {
            return Ok(vec![]);
        };
        asn1::parse(ext_der, Self::parse_multiple)
    }
    pub fn find_single_in_cert(cert_der: &[u8]) -> Result<Option<Self>, asn1::ParseError> {
        let Some(ext_der) = get_cert_extension(cert_der, &DICE_TCB_INFO_OID)? else {
            return Ok(None)
        };
        asn1::parse(ext_der, Self::parse_single).map(Some)
    }
}

#[test]
fn test_tcb_info_parse() {
    let tcb_info = asn1::parse(
        &[
            0x30, 0x81, 0xbc, 0x30, 0x24, 0x80, 0x08, 0x43, 0x61, 0x6c, 0x69, 0x70, 0x74, 0x72,
            0x61, 0x81, 0x06, 0x44, 0x65, 0x76, 0x69, 0x63, 0x65, 0x83, 0x02, 0x01, 0x07, 0x87,
            0x05, 0x00, 0x80, 0x00, 0x00, 0x00, 0x8a, 0x05, 0x00, 0x80, 0x00, 0x00, 0x0b, 0x30,
            0x81, 0x93, 0x80, 0x08, 0x43, 0x61, 0x6c, 0x69, 0x70, 0x74, 0x72, 0x61, 0x81, 0x03,
            0x46, 0x4d, 0x43, 0x83, 0x02, 0x01, 0x09, 0xa6, 0x7e, 0x30, 0x3d, 0x06, 0x09, 0x60,
            0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x04, 0x30, 0xc6, 0x72, 0x45, 0x3a,
            0xc6, 0x55, 0x83, 0xbf, 0x9e, 0xb3, 0xe7, 0x16, 0xd8, 0x98, 0x58, 0x05, 0x2b, 0x16,
            0xb5, 0x9a, 0xeb, 0xba, 0x9d, 0x6b, 0x82, 0xaa, 0x49, 0x11, 0x29, 0xf7, 0x38, 0xab,
            0x69, 0xab, 0x4f, 0x5a, 0xac, 0xfd, 0x92, 0x68, 0xe6, 0xcc, 0x92, 0x7b, 0x8f, 0x0a,
            0x73, 0x24, 0x30, 0x3d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x02, 0x04, 0x30, 0xb8, 0x3a, 0xe1, 0x33, 0x17, 0x05, 0x24, 0x34, 0xe5, 0x40, 0x16,
            0x45, 0x52, 0xeb, 0xc6, 0x18, 0x11, 0x73, 0x5b, 0x4f, 0x3c, 0x9a, 0x03, 0xe8, 0xd2,
            0xfd, 0x92, 0x4a, 0x47, 0xb0, 0xe3, 0x5d, 0xf5, 0x79, 0x23, 0xba, 0x44, 0x2c, 0x45,
            0xab, 0x15, 0x62, 0x54, 0xf1, 0x70, 0x84, 0x2b, 0x65,
        ],
        DiceTcbInfo::parse_multiple,
    )
    .unwrap();

    assert_eq!(
        tcb_info,
        vec![
            DiceTcbInfo {
                vendor: Some("Caliptra".into()),
                model: Some("Device".into()),
                svn: Some(0x107),

                flags: Some(0x80000000),
                ..Default::default()
            },
            DiceTcbInfo {
                vendor: Some("Caliptra".into()),
                model: Some("FMC".into()),
                svn: Some(0x109),
                fwids: vec![
                    DiceFwid {
                        hash_alg: asn1::oid!(2, 16, 840, 1, 101, 3, 4, 2, 2),
                        digest: vec![
                            0xc6, 0x72, 0x45, 0x3a, 0xc6, 0x55, 0x83, 0xbf, 0x9e, 0xb3, 0xe7, 0x16,
                            0xd8, 0x98, 0x58, 0x05, 0x2b, 0x16, 0xb5, 0x9a, 0xeb, 0xba, 0x9d, 0x6b,
                            0x82, 0xaa, 0x49, 0x11, 0x29, 0xf7, 0x38, 0xab, 0x69, 0xab, 0x4f, 0x5a,
                            0xac, 0xfd, 0x92, 0x68, 0xe6, 0xcc, 0x92, 0x7b, 0x8f, 0x0a, 0x73, 0x24
                        ],
                    },
                    DiceFwid {
                        hash_alg: asn1::oid!(2, 16, 840, 1, 101, 3, 4, 2, 2),
                        digest: vec![
                            0xb8, 0x3a, 0xe1, 0x33, 0x17, 0x05, 0x24, 0x34, 0xe5, 0x40, 0x16, 0x45,
                            0x52, 0xeb, 0xc6, 0x18, 0x11, 0x73, 0x5b, 0x4f, 0x3c, 0x9a, 0x03, 0xe8,
                            0xd2, 0xfd, 0x92, 0x4a, 0x47, 0xb0, 0xe3, 0x5d, 0xf5, 0x79, 0x23, 0xba,
                            0x44, 0x2c, 0x45, 0xab, 0x15, 0x62, 0x54, 0xf1, 0x70, 0x84, 0x2b, 0x65
                        ],
                    },
                ],
                ..Default::default()
            },
        ]
    )
}

#[test]
fn test_tcb_info_find_multiple_in_cert_when_no_tcb_info() {
    let cert_der =
        include_bytes!("../tests/caliptra_integration_tests/smoke_testdata/ldevid_cert.der");
    assert_eq!(Ok(vec![]), DiceTcbInfo::find_multiple_in_cert(cert_der));
}

/// Extracts the DER bytes of an extension from x509 certificate bytes
/// (`cert_der`) with the provided `oid`.
pub(crate) fn get_cert_extension<'a>(
    cert_der: &'a [u8],
    oid: &asn1::ObjectIdentifier,
) -> Result<Option<&'a [u8]>, asn1::ParseError> {
    asn1::parse(cert_der, |d| {
        d.read_element::<asn1::Sequence>()?.parse(|d| {
            let result = d.read_element::<asn1::Sequence>()?.parse(|d| {
                d.read_explicit_element::<Option<u32>>(0)?; // version
                d.read_element::<asn1::BigInt>()?; // serial-number
                d.read_element::<asn1::Sequence>()?; // signature
                d.read_element::<asn1::Sequence>()?; // name
                d.read_element::<asn1::Sequence>()?; // validity
                d.read_element::<asn1::Sequence>()?; // subject
                d.read_element::<asn1::Sequence>()?; // subjectPublicKeyInfo
                d.read_optional_implicit_element::<asn1::BitString>(1)?; // issuerUniqueID
                d.read_optional_implicit_element::<asn1::BitString>(2)?; // subjectUniqueId
                let result = d.read_explicit_element::<asn1::Sequence>(3)?.parse(|d| {
                    let mut result = None;
                    while !d.is_empty() {
                        let found_result = d.read_element::<asn1::Sequence>()?.parse(|d| {
                            let item_oid = d.read_element::<asn1::ObjectIdentifier>()?;
                            d.read_element::<Option<bool>>()?; // critical
                            let value = d.read_element::<&[u8]>()?;
                            if &item_oid == oid {
                                Ok(Some(value))
                            } else {
                                Ok(None)
                            }
                        })?;
                        if let Some(found_result) = found_result {
                            if result.is_some() {
                                // The extension was found more than once
                                return Err(asn1::ParseError::new(asn1::ParseErrorKind::ExtraData));
                            }
                            result = Some(found_result);
                        }
                    }
                    Ok(result)
                })?;
                Ok(result)
            })?;
            d.read_element::<asn1::Sequence>()?; // signatureAlgorithm
            d.read_element::<asn1::BitString>()?; // signatureValue
            Ok(result)
        })
    })
}

#[test]
fn test_get_cert_extension() {
    let cert = include_bytes!("../tests/caliptra_integration_tests/smoke_testdata/ldevid_cert.der");

    assert_eq!(get_cert_extension(cert, &asn1::oid!(5, 3)), Ok(None));
    assert_eq!(
        get_cert_extension(cert, &asn1::oid!(2, 5, 29, 15)),
        Ok(Some([0x03, 0x02, 0x02, 0x04].as_slice()))
    );
}

pub(crate) fn replace_sig<'a>(
    cert_der: &'a [u8],
    new_sig: &[u8],
) -> Result<Vec<u8>, Box<dyn Error + 'static>> {
    let (tbs, sig_algorithm) = asn1::parse(cert_der, |d| {
        d.read_element::<asn1::Sequence>()?
            .parse(|d| -> Result<_, ParseError> {
                let tbs = d.read_element::<asn1::Sequence>()?;
                let sig_algorithm = d.read_element::<asn1::Sequence>()?;
                let _sig_value = d.read_element::<asn1::BitString>()?;
                Ok((tbs, sig_algorithm))
            })
    })?;
    Ok(asn1::write(|w| {
        w.write_element(&asn1::SequenceWriter::new(&|w| {
            w.write_element(&tbs)?;
            w.write_element(&sig_algorithm)?;
            w.write_element(&asn1::BitString::new(new_sig, 0))
        }))
    })
    .map_err(|e| format!("{:?}", e))?)
}

#[test]
fn test_replace_sig() {
    const REPLACED_KEY: &[u8] = &[0x01, 0x2, 0x3, 0x4];
    let cert_der =
        include_bytes!("../tests/caliptra_integration_tests/smoke_testdata/ldevid_cert.der");
    let cert_der_replaced = replace_sig(cert_der, REPLACED_KEY).unwrap();
    let cert = openssl::x509::X509::from_der(&cert_der_replaced).unwrap();
    assert_eq!(cert.signature().as_slice(), REPLACED_KEY);
}
