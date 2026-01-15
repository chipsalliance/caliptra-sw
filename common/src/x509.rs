/*++

Licensed under the Apache-2.0 license.

File Name:

    x509.rs

Abstract:

    File contains X509 Certificate & CSR related utility functions

--*/
use caliptra_drivers::*;
use core::mem::size_of;
use zerocopy::IntoBytes;

use crate::crypto::PubKey;

/// Get device serial number
///
/// # Arguments
///
/// * `soc_ifc` - SOC Interface object
///
/// # Returns
///
/// `[u8; 17]` - Byte 0 - Ueid Type, Bytes 1-16 Unique Endpoint Identifier
pub fn ueid(soc_ifc: &SocIfc) -> CaliptraResult<[u8; 17]> {
    let ueid = soc_ifc.fuse_bank().ueid();
    Ok(ueid)
}

/// Get public key bytes. Reverses the endianness of each dword in the public key.
///
/// # Arguments
///
/// * `pub_key` - ECC, MLDSA or ML-KEM Public Key
/// * `pub_key_bytes` - Buffer to hold the public key bytes
///
/// # Returns
///
/// `usize` - Number of bytes written to the buffer
#[inline(always)]
#[allow(clippy::cast_ptr_alignment)]
pub fn get_pubkey_bytes(pub_key: &PubKey, pub_key_bytes: &mut [u8]) -> usize {
    match pub_key {
        PubKey::Ecc(pub_key) => {
            let ecc_pubkey_der = pub_key.to_der();
            pub_key_bytes[..ecc_pubkey_der.len()].copy_from_slice(&ecc_pubkey_der);
            ecc_pubkey_der.len()
        }
        PubKey::Mldsa(pub_key) => {
            let mldsa_pubkey: &[u8; 2592] = &(*pub_key).into();
            pub_key_bytes.copy_from_slice(mldsa_pubkey);
            pub_key_bytes.len()
        }
        PubKey::MlKem(pub_key) => {
            let ml_kem_pubkey: &[u8; 1568] = pub_key.as_ref();
            pub_key_bytes[..ml_kem_pubkey.len()].copy_from_slice(ml_kem_pubkey);
            pub_key_bytes.len()
        }
    }
}

fn pub_key_digest(sha256: &mut Sha256, pub_key: &PubKey) -> CaliptraResult<Array4x8> {
    // Define an array large enough to hold the largest public key.
    let mut pub_key_bytes: [u8; size_of::<Mldsa87PubKey>()] = [0; size_of::<Mldsa87PubKey>()];
    let pub_key_size = get_pubkey_bytes(pub_key, &mut pub_key_bytes);
    sha256.digest(&pub_key_bytes[..pub_key_size])
}

/// Get X509 Subject Serial Number from public key
///
/// # Arguments
///
/// * `sha256`  - SHA256 Driver
/// * `pub_key` - ECC or MLDSA Public Key
///
/// # Returns
///
/// `[u8; 64]` - X509 Subject Identifier serial number
pub fn subj_sn(sha256: &mut Sha256, pub_key: &PubKey) -> CaliptraResult<[u8; 64]> {
    let digest = pub_key_digest(sha256, pub_key);
    let digest = okref(&digest)?;
    Ok(hex(&digest.into()))
}

/// Get Cert Subject Key Identifier
///
/// # Arguments
///
/// * `sha256`  - SHA256 Driver
/// * `pub_key` - Public Key
///
/// # Returns
///
/// `[u8; 20]` - X509 Subject Key Identifier
pub fn subj_key_id(sha256: &mut Sha256, pub_key: &PubKey) -> CaliptraResult<[u8; 20]> {
    let digest = pub_key_digest(sha256, pub_key);
    let digest: [u8; 32] = okref(&digest)?.into();
    Ok(digest[..20].try_into().unwrap())
}

/// Get Serial Number for ECC certificate.
///
/// # Arguments
///
/// * `sha256`  - SHA256 Driver
/// * `pub_key` - ECC Public Key
///
/// # Returns
///
/// `[u8; 20]` - X509 Serial Number
pub fn ecc_cert_sn(sha256: &mut Sha256, pub_key: &Ecc384PubKey) -> CaliptraResult<[u8; 20]> {
    let data = pub_key.to_der();
    let digest = sha256.digest(&data);
    let mut digest: [u8; 32] = okref(&digest)?.into();

    // Ensure the encoded integer is positive, and that the first octet
    // is non-zero (otherwise it will be considered padding, and the integer
    // will fail to parse if the MSB of the second octet is zero).
    digest[0] &= !0x80;
    digest[0] |= 0x04;

    Ok(digest[..20].try_into().unwrap())
}

/// Get Serial Number for Mldsa certificate.
///
/// # Arguments
///
/// * `sha256`  - SHA256 Driver
/// * `pub_key` - MLDSA Public Key
///
/// # Returns
///
/// `[u8; 20]` - X509 Serial Number
pub fn mldsa_cert_sn(sha256: &mut Sha256, pub_key: &Mldsa87PubKey) -> CaliptraResult<[u8; 20]> {
    let digest = sha256.digest(pub_key.as_bytes());
    let mut digest: [u8; 32] = okref(&digest)?.into();

    // Ensure the encoded integer is positive, and that the first octet
    // is non-zero (otherwise it will be considered padding, and the integer
    // will fail to parse if the MSB of the second octet is zero).
    digest[0] &= !0x80;
    digest[0] |= 0x04;

    Ok(digest[..20].try_into().unwrap())
}

/// Retrieve the TBS from DER encoded vector
///
/// Note: Rust OpenSSL binding is missing the extensions to retrieve TBS portion of the X509
/// artifact
#[cfg(feature = "std")]
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

/// Return the hex representation of the input `buf`
///
/// # Arguments
///
/// `buf` - Buffer
///
/// # Returns
///
/// `[u8; 64]` - Hex representation of the buffer
fn hex(buf: &[u8; 32]) -> [u8; 64] {
    fn ch(byte: u8) -> u8 {
        match byte & 0x0F {
            b @ 0..=9 => 48 + b,
            b @ 10..=15 => 55 + b,
            _ => unreachable!(),
        }
    }

    let mut hex = [0u8; 64];

    for (index, byte) in buf.iter().enumerate() {
        hex[index << 1] = ch((byte & 0xF0) >> 4);
        hex[(index << 1) + 1] = ch(byte & 0x0F);
    }

    hex
}
