/*++

Licensed under the Apache-2.0 license.

File Name:

    hmac384_vector_gen.rs

Abstract:

    A vector generator for HMAC operations.

--*/

use caliptra_test::crypto::derive_ecdsa_keypair;
use openssl::{hash::MessageDigest, pkey::PKey, sign::Signer};

pub struct Hmac384Vector {
    pub seed: [u8; 48],
    pub data: Vec<u8>,
    // key = ECDSA_KEYGEN(seed).priv
    // out = HMAC(key, data)
    pub out_pub_x: [u8; 48], // ECDSA_KEYGEN(out).pub.x
    pub out_pub_y: [u8; 48], // ECDSA_KEYGEN(out).pub.y
}

impl Default for Hmac384Vector {
    fn default() -> Hmac384Vector {
        Hmac384Vector {
            seed: [0; 48],
            data: Vec::<u8>::default(),
            out_pub_x: [0; 48],
            out_pub_y: [0; 48],
        }
    }
}

fn rand_bytes(buf: &mut [u8]) {
    openssl::rand::rand_bytes(buf).unwrap()
}

fn hmac(key: &[u8], msg: &[u8], tag: &mut [u8]) {
    let pkey = PKey::hmac(key).unwrap();
    let mut signer = Signer::new(MessageDigest::sha384(), &pkey).unwrap();
    signer.update(msg).unwrap();
    signer.sign(tag).unwrap();
}

pub fn gen_vector(data_len: usize) -> Hmac384Vector {
    let mut vec = Hmac384Vector::default();

    vec.data.resize(data_len, 0);

    rand_bytes(&mut vec.seed);
    rand_bytes(&mut vec.data[..]);

    let (key, _, _) = derive_ecdsa_keypair(&vec.seed);

    let mut out_0 = [0u8; 48];
    hmac(&key, &vec.data[..], &mut out_0);
    (_, vec.out_pub_x, vec.out_pub_y) = derive_ecdsa_keypair(&out_0);

    vec
}
