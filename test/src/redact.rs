// Licensed under the Apache-2.0 license

use openssl::nid::Nid;

use crate::{crypto::pubkey_ecdsa_der, UnwrapSingle};

fn replace(bytes: &mut [u8], search: &[u8], replace: &[u8]) {
    assert_eq!(search.len(), replace.len());
    let mut offsets = vec![];
    for window in bytes.windows(search.len()) {
        if window == search {
            offsets.push(window.as_ptr() as usize - bytes.as_ptr() as usize);
        }
    }
    for offset in offsets {
        bytes[offset..][..search.len()].copy_from_slice(replace);
    }
}

fn redact(bytes: &mut [u8], value_to_redact: &[u8]) {
    replace(bytes, value_to_redact, &vec![0x44; value_to_redact.len()]);
}

pub struct RedactOpts {
    pub keep_authority: bool,
}

// Redact with a real public key so openssl can parse the cert
const REDACTED_PUBLIC_KEY: &[u8] = &[
    0x04, 0xd1, 0x7f, 0xd2, 0x78, 0xd2, 0x2e, 0x75, 0xeb, 0xf0, 0xed, 0x36, 0x2d, 0xf0, 0x46, 0x18,
    0x24, 0xc4, 0x54, 0x5d, 0xdb, 0x07, 0x08, 0x53, 0xe8, 0xa2, 0xd3, 0xa9, 0xd0, 0xa3, 0xca, 0x59,
    0x8d, 0x86, 0x06, 0x08, 0x4e, 0x78, 0xab, 0xc8, 0xcf, 0x13, 0x5d, 0x5d, 0x1b, 0xbb, 0xd7, 0x6c,
    0xf2, 0x64, 0x49, 0x0e, 0xf4, 0xa2, 0x95, 0xfa, 0x8e, 0x0f, 0x0f, 0x1f, 0xee, 0x22, 0xfc, 0x88,
    0x57, 0x1a, 0x55, 0x9f, 0x7c, 0xe9, 0x68, 0xdc, 0x67, 0xc5, 0x13, 0xd7, 0xfc, 0xbb, 0x79, 0xb6,
    0x09, 0xda, 0x23, 0x1d, 0xef, 0xb1, 0xbf, 0x96, 0x72, 0x3d, 0xfd, 0xb2, 0x8d, 0x86, 0xf1, 0x6f,
    0x5d,
];

const REDACTED_SIGNATURE: &[u8] = &[
    0x30, 0x64, 0x02, 0x30, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44,
    0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44,
    0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44,
    0x44, 0x44, 0x44, 0x44, 0x02, 0x30, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44,
    0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44,
    0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44,
    0x44, 0x44, 0x44, 0x44, 0x44, 0x44,
];

/// Replace all the non-static fields with 0x44 bytes. This is useful for
/// creating golden-data for fmc-alias or rt-alias certs.
pub fn redact_cert(der: &[u8], opts: RedactOpts) -> Vec<u8> {
    let cert = openssl::x509::X509::from_der(der).unwrap();
    let mut result = crate::x509::replace_sig(der, REDACTED_SIGNATURE).unwrap();

    let pubkey_der = pubkey_ecdsa_der(&cert.public_key().unwrap());
    replace(&mut result, &pubkey_der, REDACTED_PUBLIC_KEY);

    redact(
        &mut result,
        &cert
            .serial_number()
            .to_bn()
            .unwrap()
            .to_vec_padded(20)
            .unwrap(),
    );
    redact(&mut result, cert.subject_key_id().unwrap().as_slice());
    redact(
        &mut result,
        cert.subject_name()
            .entries_by_nid(Nid::SERIALNUMBER)
            .unwrap_single()
            .data()
            .as_slice(),
    );

    if !opts.keep_authority {
        redact(&mut result, cert.authority_key_id().unwrap().as_slice());
        redact(
            &mut result,
            cert.issuer_name()
                .entries_by_nid(Nid::SERIALNUMBER)
                .unwrap_single()
                .data()
                .as_slice(),
        );
    }

    if let Some(tcb_info) =
        crate::x509::get_cert_extension(der, &crate::x509::DICE_MULTI_TCB_INFO_OID).unwrap()
    {
        redact(&mut result, tcb_info);
    }

    if let Some(tcb_info) =
        crate::x509::get_cert_extension(der, &crate::x509::DICE_TCB_INFO_OID).unwrap()
    {
        redact(&mut result, tcb_info);
    }

    result
}

#[test]
fn test_redact() {
    let mut value = vec![1_u8, 2, 3, 4, 5, 6, 7, 1, 2, 3, 4, 5, 6, 7];
    redact(&mut value, &[3, 4, 5]);
    assert_eq!(
        value,
        vec![1_u8, 2, 0x44, 0x44, 0x44, 6, 7, 1, 2, 0x44, 0x44, 0x44, 6, 7]
    )
}
