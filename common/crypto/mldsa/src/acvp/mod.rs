// Licensed under the Apache-2.0 license

//! ML-DSA-87 known-answer tests from the NIST ACVP-Server vector set.
//!
//! Vectors are trimmed from upstream `internalProjection.json` files by
//! `extract.py` (see that file for provenance and the exact filter).
//!
//! Only the combinations the pure-software implementation can drive are
//! included. For signature verification that is the `external` interface with
//! `pure` preHash and internal mu (externalMu=false), which is what
//! `verify_internal` implements. The following ACVP groups are intentionally
//! NOT covered because the library does not implement their message
//! processing:
//!   * `internal` signature interface (no domain-separator prefix)
//!   * `externalMu` (caller-supplied mu)
//!   * `preHash` / HashML-DSA (OID-prefixed pre-hashed message)
//!
//! sigGen is not covered: those vectors supply an encoded private key (`sk`)
//! rather than the 32-byte seed the signer derives keys from, and the library
//! has no private-key decoder.

use crate::mldsa87::mldsa87_verify_with_context;
use crate::Mldsa87Result;
use crate::{
    Mldsa87, MLDSA87_PRIVATE_SEED_BYTES, MLDSA87_PUBLIC_KEY_BYTES, MLDSA87_SIGNATURE_BYTES,
};

fn hex_to_array<const N: usize>(s: &str) -> [u8; N] {
    let bytes = hex::decode(s).unwrap();
    assert_eq!(bytes.len(), N, "expected {} bytes, got {}", N, bytes.len());
    bytes.try_into().unwrap()
}

#[test]
fn test_acvp_mldsa87_keygen() {
    let json: serde_json::Value = serde_json::from_str(include_str!("key_gen.json")).unwrap();
    let mut count = 0;
    for group in json["testGroups"].as_array().unwrap() {
        if group["parameterSet"] != "ML-DSA-87" {
            continue;
        }
        for test in group["tests"].as_array().unwrap() {
            let seed = hex_to_array::<MLDSA87_PRIVATE_SEED_BYTES>(test["seed"].as_str().unwrap());
            let expected_pk = hex::decode(test["pk"].as_str().unwrap()).unwrap();

            let mut pk = [0u8; MLDSA87_PUBLIC_KEY_BYTES];
            Mldsa87::pub_from_seed(&seed, &mut pk);

            assert_eq!(pk, &expected_pk[..], "keygen tcId {} failed", test["tcId"]);
            count += 1;
        }
    }
    assert_eq!(count, 25, "unexpected ML-DSA-87 keygen case count");
}

#[test]
fn test_acvp_mldsa87_sigver() {
    let json: serde_json::Value = serde_json::from_str(include_str!("sig_ver.json")).unwrap();
    let mut count = 0;
    for group in json["testGroups"].as_array().unwrap() {
        if group["parameterSet"] != "ML-DSA-87" {
            continue;
        }
        for test in group["tests"].as_array().unwrap() {
            let pk = hex_to_array::<MLDSA87_PUBLIC_KEY_BYTES>(test["pk"].as_str().unwrap());
            let sig = hex_to_array::<MLDSA87_SIGNATURE_BYTES>(test["signature"].as_str().unwrap());
            let msg = hex::decode(test["message"].as_str().unwrap()).unwrap();
            let context = hex::decode(test["context"].as_str().unwrap_or("")).unwrap();
            let expected_pass = test["testPassed"].as_bool().unwrap();

            let result = mldsa87_verify_with_context(&pk, &sig, &msg, &context);
            let expected = if expected_pass {
                Mldsa87Result::Success
            } else {
                Mldsa87Result::SigVerifyFailed
            };
            assert_eq!(
                result, expected,
                "sigver tcId {} failed (reason: {})",
                test["tcId"], test["reason"]
            );
            count += 1;
        }
    }
    assert_eq!(count, 15, "unexpected ML-DSA-87 sigver case count");
}
