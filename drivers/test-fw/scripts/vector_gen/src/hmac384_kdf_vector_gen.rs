/*++

Licensed under the Apache-2.0 license.

File Name:

    hmac384_kdf_vector_gen.rs

Abstract:

    A vector generator for an SP 800-108-compliant KDF.

--*/

use openssl::{hash::MessageDigest, pkey::PKey, sign::Signer};
use p384::ecdsa::SigningKey;
use rfc6979::HmacDrbg;
use sha2::Sha384;

pub struct Hmac384KdfVector {
    pub key_0: [u8; 48],
    pub msg_0: [u8; 48],
    pub kdf_key: [u8; 48], // HMAC(key=key_0, msg=msg_0)
    pub label: Vec<u8>,
    pub context: Vec<u8>,
    pub kdf_out: [u8; 48],   // KDF(key=kdf_key, label=label, context=context)
    pub out_pub_x: [u8; 48], // ECDSA_KEYGEN(kdf_out).pub.x
    pub out_pub_y: [u8; 48], // ECDSA_KEYGEN(kdf_out).pub.y
}

impl Default for Hmac384KdfVector {
    fn default() -> Hmac384KdfVector {
        Hmac384KdfVector {
            key_0: [0; 48],
            msg_0: [0; 48],
            kdf_key: [0; 48],
            label: Vec::<u8>::default(),
            context: Vec::<u8>::default(),
            kdf_out: [0; 48],
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

fn ecdsa_keygen(key: &[u8], out_pub_x: &mut [u8; 48], out_pub_y: &mut [u8; 48]) {
    let mut drbg = HmacDrbg::<Sha384>::new(key, &[0_u8; 48], &[]);
    let mut priv_key = [0u8; 48];
    drbg.fill_bytes(&mut priv_key);

    let ecc_point = SigningKey::from_bytes(&priv_key)
        .unwrap()
        .verifying_key()
        .to_encoded_point(false);

    out_pub_x.copy_from_slice(ecc_point.x().unwrap().as_slice());
    out_pub_y.copy_from_slice(ecc_point.y().unwrap().as_slice());
}

fn kdf(key: &[u8], label: &[u8], context: Option<&[u8]>, output: &mut [u8; 48]) {
    let ctr_be = 1_u32.to_be_bytes();

    let mut msg = Vec::<u8>::default();
    msg.extend_from_slice(&ctr_be);
    msg.extend_from_slice(label);

    if let Some(context) = context {
        msg.push(0x00);
        msg.extend_from_slice(context);
    }

    hmac(key, &msg, output);
}

pub fn gen_vector(label_len: usize, context_len: usize) -> Hmac384KdfVector {
    let mut vec = Hmac384KdfVector::default();

    vec.label.resize(label_len, 0);

    rand_bytes(&mut vec.key_0);
    rand_bytes(&mut vec.msg_0);
    rand_bytes(&mut vec.label[..]);

    let context = if context_len == 0 {
        None
    } else {
        vec.context.resize(context_len, 0);
        rand_bytes(&mut vec.context[..]);
        Some(&vec.context[..])
    };

    hmac(&vec.key_0, &vec.msg_0, &mut vec.kdf_key);
    kdf(&vec.kdf_key, &vec.label[..], context, &mut vec.kdf_out);
    ecdsa_keygen(&vec.kdf_out, &mut vec.out_pub_x, &mut vec.out_pub_y);

    vec
}
