// Licensed under the Apache-2.0 license

use caliptra_x509::{Ecdsa384CertBuilder, Ecdsa384CsrBuilder, Ecdsa384Signature};
use openssl::{
    ec::{EcGroup, EcKey},
    ecdsa::EcdsaSig,
    nid::Nid,
    pkey::{PKey, Private},
    sha::Sha384,
    x509::{X509Req, X509},
};

fn make_test_key() -> PKey<Private> {
    let ecc_group = EcGroup::from_curve_name(Nid::SECP384R1).unwrap();
    let ec_key = EcKey::generate(&ecc_group).unwrap();
    PKey::from_ec_key(ec_key).unwrap()
}

pub fn build_and_validate_csr(tbs: &[u8]) {
    let ec_key = make_test_key();

    let mut sha = Sha384::new();
    sha.update(tbs);
    let sig = EcdsaSig::sign(&sha.finish(), &ec_key.ec_key().unwrap()).unwrap();
    let ecdsa_sig = Ecdsa384Signature {
        r: TryInto::<[u8; 48]>::try_into(sig.r().to_vec_padded(48).unwrap()).unwrap(),
        s: TryInto::<[u8; 48]>::try_into(sig.s().to_vec_padded(48).unwrap()).unwrap(),
    };

    let builder = Ecdsa384CsrBuilder::new(tbs, &ecdsa_sig).unwrap();
    let mut buf = vec![0u8; builder.len()];
    if builder.build(&mut buf) == None {
        return;
    }

    let csr = X509Req::from_der(&buf).unwrap();
    assert!(csr.verify(&ec_key).unwrap());
}

pub fn build_and_validate_cert(tbs: &[u8]) {
    let ec_key = make_test_key();

    let mut sha = Sha384::new();
    sha.update(tbs);
    let sig = EcdsaSig::sign(&sha.finish(), &ec_key.ec_key().unwrap()).unwrap();
    let ecdsa_sig = Ecdsa384Signature {
        r: TryInto::<[u8; 48]>::try_into(sig.r().to_vec_padded(48).unwrap()).unwrap(),
        s: TryInto::<[u8; 48]>::try_into(sig.s().to_vec_padded(48).unwrap()).unwrap(),
    };

    let builder = Ecdsa384CertBuilder::new(tbs, &ecdsa_sig).unwrap();
    let mut buf = vec![0u8; builder.len()];
    if builder.build(&mut buf) == None {
        return;
    }

    let cert = X509::from_der(&buf).unwrap();
    assert!(cert.verify(&ec_key).unwrap());
}
