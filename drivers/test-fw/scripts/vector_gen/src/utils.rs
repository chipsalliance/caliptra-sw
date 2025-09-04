use openssl::{hash::MessageDigest, pkey::PKey, sign::Signer};

pub(crate) enum Digest {
    SHA384,
    SHA512,
}

pub(crate) fn rand_bytes(buf: &mut [u8]) {
    openssl::rand::rand_bytes(buf).unwrap()
}

pub(crate) fn hmac(key: &[u8], msg: &[u8], tag: &mut [u8], digest_type: Digest) {
    let pkey = PKey::hmac(key).unwrap();
    let digest = match digest_type {
        Digest::SHA384 => MessageDigest::sha384(),
        Digest::SHA512 => MessageDigest::sha512(),
    };

    let mut signer = Signer::new(digest, &pkey).unwrap();
    signer.update(msg).unwrap();
    signer.sign(tag).unwrap();
}

pub(crate) fn kdf<const N: usize>(
    key: &[u8],
    label: &[u8],
    context: Option<&[u8]>,
    output: &mut [u8; N],
    digest_type: Digest,
) {
    let ctr_be = 1_u32.to_be_bytes();

    let mut msg = Vec::<u8>::default();
    msg.extend_from_slice(&ctr_be);
    msg.extend_from_slice(label);

    if let Some(context) = context {
        msg.push(0x00);
        msg.extend_from_slice(context);
    }

    hmac(key, &msg, output, digest_type);
}
