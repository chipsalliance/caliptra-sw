// Licensed under the Apache-2.0 license

// Tests take from:
//    https://github.com/usnistgov/ACVP-Server/blob/master/gen-val/json-files/SHAKE-128-FIPS202/internalProjection.json
//    https://github.com/usnistgov/ACVP-Server/blob/master/gen-val/json-files/SHAKE-256-FIPS202/internalProjection.json

use crate::{Shake128, Shake256};

#[test]
fn test_acvp_shake128() {
    let json_str = include_str!("shake128.json");
    let json: serde_json::Value = serde_json::from_str(json_str).unwrap();
    let test_groups = json["testGroups"].as_array().unwrap();
    for group in test_groups {
        let tests = group["tests"].as_array().unwrap();
        for test in tests {
            let msg_hex = test["msg"].as_str().unwrap();
            let md_hex = test["md"].as_str().unwrap();
            let out_len_bits = test["outLen"].as_u64().unwrap() as usize;

            let msg = hex::decode(msg_hex).unwrap();
            let expected = hex::decode(md_hex).unwrap();

            let mut shake = Shake128::new();
            shake.absorb(&msg);

            let out_bytes = (out_len_bits + 7) / 8;
            let mut out = vec![0; out_bytes];
            shake.squeeze(&mut out);

            // ACVP tests may specify lengths that are not multiples of 8.
            // The expected output is padded with zeros in the unused bits of the last byte.
            let rem = out_len_bits % 8;
            if rem != 0 {
                out[out_bytes - 1] <<= 8 - rem;
            }
            assert_eq!(out, &expected[..], "Test case {} failed", test["tcId"]);
        }
    }
}

#[test]
fn test_acvp_shake256() {
    let json_str = include_str!("shake256.json");
    let json: serde_json::Value = serde_json::from_str(json_str).unwrap();
    let test_groups = json["testGroups"].as_array().unwrap();
    for group in test_groups {
        let tests = group["tests"].as_array().unwrap();
        for test in tests {
            let msg_hex = test["msg"].as_str().unwrap();
            let md_hex = test["md"].as_str().unwrap();
            let out_len_bits = test["outLen"].as_u64().unwrap() as usize;

            let msg = hex::decode(msg_hex).unwrap();
            let expected = hex::decode(md_hex).unwrap();

            let mut shake = Shake256::new();
            shake.absorb(&msg);

            let out_bytes = (out_len_bits + 7) / 8;
            let mut out = vec![0; out_bytes];
            shake.squeeze(&mut out);

            // ACVP tests may specify lengths that are not multiples of 8.
            // The expected output is padded with zeros in the unused bits of the last byte.
            let rem = out_len_bits % 8;
            if rem != 0 {
                out[out_bytes - 1] <<= 8 - rem;
            }
            assert_eq!(out, &expected[..], "Test case {} failed", test["tcId"]);
        }
    }
}
