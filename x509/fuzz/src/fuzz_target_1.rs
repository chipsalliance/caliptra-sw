// Licensed under the Apache-2.0 license

#![cfg_attr(feature = "libfuzzer-sys", no_main)]

#[cfg(all(not(feature = "libfuzzer-sys"), not(feature = "afl")))]
compile_error!("Either feature \"libfuzzer-sys\" or \"afl\" must be enabled!");

#[cfg(feature = "libfuzzer-sys")]
use libfuzzer_sys::fuzz_target;

#[cfg(feature = "afl")]
use afl::fuzz;

use std::mem::size_of;

use caliptra_x509::{Ecdsa384CertBuilder, Ecdsa384Signature};
use openssl::x509::X509;

fn harness(data: &[u8]) {
    let tbs: &[u8];
    let sig: &Ecdsa384Signature;

    if data.len() < size_of::<Ecdsa384Signature>() {
        return;
    }

    // TODO: Alternatively, use structure-aware fuzzing, input comprising arguments
    unsafe {
        tbs = &data[size_of::<Ecdsa384Signature>()..];
        sig = &*(data.as_ptr() as *const Ecdsa384Signature);
    }

    let builder = Ecdsa384CertBuilder::new(tbs, sig).unwrap();
    let mut buf = vec![0u8; builder.len()];
    if builder.build(&mut buf) == None {
        return;
    }

    // NB: This assumes that if x509 is returned, it is valid.
    // - Currently, that's not the case. This *will* panic.
    let _cert = X509::from_der(&buf).unwrap();
    //assert!(_cert.unwrap().verify(issuer_key.priv_key()).unwrap());
}

// cargo-fuzz target
#[cfg(feature = "libfuzzer-sys")]
fuzz_target!(|data: &[u8]| {
    harness(data);
});

// cargo-afl target
#[cfg(feature = "afl")]
fn main() {
    fuzz!(|data: &[u8]| {
        harness(data);
    });
}
