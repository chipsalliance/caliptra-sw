// Licensed under the Apache-2.0 license

// Tests taken from:
//     https://github.com/usnistgov/ACVP-Server/blob/master/gen-val/json-files/ML-DSA-keyGen-FIPS204/internalProjection.json

use crate::Mldsa87;
use crate::{MLDSA87_PRIVATE_SEED_BYTES, MLDSA87_PUBLIC_KEY_BYTES};

#[test]
fn test_acvp_mldsa87_keygen() {
    let json_str = include_str!("key_gen.json");
    let json: serde_json::Value = serde_json::from_str(json_str).unwrap();
    let test_groups = json["testGroups"].as_array().unwrap();
    for group in test_groups {
        if group["parameterSet"] != "ML-DSA-87" {
            continue;
        }
        let tests = group["tests"].as_array().unwrap();
        for test in tests {
            let seed_hex = test["seed"].as_str().unwrap();
            let pk_hex = test["pk"].as_str().unwrap();

            let seed = hex::decode(seed_hex).unwrap();
            let expected_pk = hex::decode(pk_hex).unwrap();

            let mut seed_arr = [0u8; MLDSA87_PRIVATE_SEED_BYTES];
            seed_arr.copy_from_slice(&seed);

            let mut pk = [0u8; MLDSA87_PUBLIC_KEY_BYTES];
            Mldsa87::pub_from_seed(&seed_arr, &mut pk);

            assert_eq!(pk, &expected_pk[..], "Test case {} failed", test["tcId"]);
        }
    }
}
