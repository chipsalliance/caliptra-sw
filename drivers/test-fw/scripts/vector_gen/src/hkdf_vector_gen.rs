/*++

Licensed under the Apache-2.0 license.

File Name:

    hmac_hkdf_vector_gen.rs

Abstract:

    A vector generator for HKDF (RFC 5869) using SHA-384.

--*/

use crate::utils::*;
use hkdf::Hkdf;
use sha2::Sha384;

pub struct HkdfVector {
    pub ikm: [u8; 48],
    pub salt: Vec<u8>,
    pub info: Vec<u8>,
    pub prk: [u8; 48],
    pub okm: [u8; 48],
}

impl Default for HkdfVector {
    fn default() -> HkdfVector {
        HkdfVector {
            ikm: [0; 48],
            salt: Vec::new(),
            info: Vec::new(),
            prk: [0; 48],
            okm: [0; 48],
        }
    }
}

pub fn gen_vector(salt_len: usize, info_len: usize) -> HkdfVector {
    let mut vec = HkdfVector::default();

    rand_bytes(&mut vec.ikm);

    if salt_len > 0 {
        vec.salt.resize(salt_len, 0);
        rand_bytes(&mut vec.salt);
    }

    if info_len > 0 {
        vec.info.resize(info_len, 0);
        rand_bytes(&mut vec.info);
    }

    let salt = if vec.salt.is_empty() {
        None
    } else {
        Some(&vec.salt[..])
    };

    let (prk, hkdf) = Hkdf::<Sha384>::extract(salt, &vec.ikm);
    vec.prk.copy_from_slice(prk.as_slice());

    hkdf.expand(&vec.info, &mut vec.okm).unwrap();

    vec
}
