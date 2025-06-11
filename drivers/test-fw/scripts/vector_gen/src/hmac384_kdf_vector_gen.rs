/*++

Licensed under the Apache-2.0 license.

File Name:

    hmac384_kdf_vector_gen.rs

Abstract:

    A vector generator for an SP 800-108-compliant KDF.

--*/

use crate::utils::*;

use caliptra_test::crypto::derive_ecdsa_keypair;

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

    hmac(&vec.key_0, &vec.msg_0, &mut vec.kdf_key, Digest::SHA384);
    kdf(
        &vec.kdf_key,
        &vec.label[..],
        context,
        &mut vec.kdf_out,
        Digest::SHA384,
    );
    (_, vec.out_pub_x, vec.out_pub_y) = derive_ecdsa_keypair(&vec.kdf_out);

    vec
}
