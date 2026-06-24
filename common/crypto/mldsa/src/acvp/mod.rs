// Licensed under the Apache-2.0 license

//! ML-DSA-87 known-answer tests from the NIST ACVP-Server vector set.
//!
//! Vectors are trimmed from upstream `internalProjection.json` files by
//! `extract.py` (see that file for provenance and the exact filter).
//!
//! Only the combinations the pure-software implementation can drive are
//! included:
//!   * keyGen: all 25 AFT cases (seed → public key).
//!   * sigVer: `external` interface, `pure` preHash, internal mu (externalMu=false).
//!   * sigGen: two deterministic groups —
//!       - group 5: `external` / `pure` / externalMu=false → `sign_with_context_from_sk`
//!       - group 11: `internal` / externalMu=true → `sign_mu_from_sk`
//!
//!     The sk-based signing functions are `#[cfg(test)]`-gated; they decode the
//!     FIPS 204 `skEncode` byte string purely to enable this KAT harness.
//!
//! The following ACVP groups are intentionally NOT covered because the library
//! does not implement their message processing:
//!   * `preHash` / HashML-DSA (OID-prefixed pre-hashed message)
//!   * `internal` / externalMu=false (raw message, no domain-separator prefix)
//!   * Non-deterministic groups (randomizer not captured in vectors)

use crate::mldsa87::mldsa87_verify_with_context;
use crate::Mldsa87Result;
use crate::{
    Mldsa87, MLDSA87_MU_BYTES, MLDSA87_PRIVATE_KEY_BYTES, MLDSA87_PRIVATE_SEED_BYTES,
    MLDSA87_PUBLIC_KEY_BYTES, MLDSA87_SIGNATURE_BYTES,
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

#[test]
fn test_acvp_mldsa87_siggen() {
    let json: serde_json::Value = serde_json::from_str(include_str!("sig_gen.json")).unwrap();
    let mut count = 0;
    for group in json["testGroups"].as_array().unwrap() {
        if group["parameterSet"] != "ML-DSA-87" {
            continue;
        }
        let external_mu = group["externalMu"].as_bool().unwrap();
        for test in group["tests"].as_array().unwrap() {
            let sk = hex_to_array::<MLDSA87_PRIVATE_KEY_BYTES>(test["sk"].as_str().unwrap());
            let expected_sig =
                hex_to_array::<MLDSA87_SIGNATURE_BYTES>(test["signature"].as_str().unwrap());
            let mut sig = [0u8; MLDSA87_SIGNATURE_BYTES];

            if external_mu {
                // Group 11: internal interface, mu provided directly
                let mu = hex_to_array::<MLDSA87_MU_BYTES>(test["mu"].as_str().unwrap());
                Mldsa87::sign_mu_deterministic_from_sk(&sk, &mu, &mut sig);
            } else {
                // Group 5: external interface with context
                let msg = hex::decode(test["message"].as_str().unwrap()).unwrap();
                let context = hex::decode(test["context"].as_str().unwrap_or("")).unwrap();
                Mldsa87::sign_with_context_deterministic_from_sk(&sk, &msg, &context, &mut sig);
            }

            assert_eq!(sig, expected_sig, "siggen tcId {} failed", test["tcId"]);
            count += 1;
        }
    }
    assert_eq!(count, 30, "unexpected ML-DSA-87 siggen case count");
}
