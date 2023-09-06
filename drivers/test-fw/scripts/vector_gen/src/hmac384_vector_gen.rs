/*++

Licensed under the Apache-2.0 license.

File Name:

    hmac384_vector_gen.rs

Abstract:

    A vector generator for HMAC operations.

--*/

use openssl::{hash::MessageDigest, pkey::PKey, sign::Signer};
use p384::ecdsa::SigningKey;
use rfc6979::HmacDrbg;
use sha2::Sha384;

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

// Returns (priv, pub_x, pub_y)
fn ecdsa_keygen(key: &[u8]) -> ([u8; 48], [u8; 48], [u8; 48]) {
    let mut drbg = HmacDrbg::<Sha384>::new(key, &[0_u8; 48], &[]);
    let mut priv_key = [0u8; 48];
    drbg.fill_bytes(&mut priv_key);

    let ecc_point = SigningKey::from_bytes(&priv_key)
        .unwrap()
        .verifying_key()
        .to_encoded_point(false);

    let mut pub_x = [0u8; 48];
    let mut pub_y = [0u8; 48];

    pub_x.copy_from_slice(ecc_point.x().unwrap().as_slice());
    pub_y.copy_from_slice(ecc_point.y().unwrap().as_slice());

    (priv_key, pub_x, pub_y)
}

pub fn gen_vector(data_len: usize) -> Hmac384Vector {
    let mut vec = Hmac384Vector::default();

    vec.data.resize(data_len, 0);

    rand_bytes(&mut vec.seed);
    rand_bytes(&mut vec.data[..]);

    let (key, _, _) = ecdsa_keygen(&vec.seed);

    let mut out_0 = [0u8; 48];
    hmac(&key, &vec.data[..], &mut out_0);
    (_, vec.out_pub_x, vec.out_pub_y) = ecdsa_keygen(&out_0);

    vec
}
