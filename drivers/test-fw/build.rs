/*++

Licensed under the Apache-2.0 license.

File Name:

    build.rs

Abstract:

    Cargo build file

--*/

use serde::{Deserialize, Serialize};
use std::env;
use std::fs;
use std::path::Path;

#[derive(Serialize, Deserialize)]
struct EncryptionJson {
    aad: String,
    ct: String,
    nonce: String,
    pt: String,
}

#[derive(Serialize, Deserialize)]
struct TestVectorJson {
    mode: u8,
    kem_id: u16,
    kdf_id: u16,
    aead_id: u16,
    info: String,
    #[serde(rename = "ikmE")]
    ikm_e: String,
    #[serde(rename = "ikmR")]
    ikm_r: String,
    #[serde(rename = "skRm")]
    sk_rm: String,
    #[serde(rename = "pkRm")]
    pk_rm: String,
    enc: String,
    shared_secret: String,
    suite_id: String,
    key: String,
    base_nonce: String,
    exporter_secret: String,
    encryptions: Vec<EncryptionJson>,
}

fn hex_to_byte_array(hex: &str) -> String {
    if hex.is_empty() {
        return "&[]".to_string();
    }
    let bytes = hex::decode(hex).unwrap();
    format!("&{:?}", bytes)
}

fn emit_vector(name: &str, v: &TestVectorJson) -> String {
    let mode = v.mode;
    let kem_id = v.kem_id;
    let kdf_id = v.kdf_id;
    let aead_id = v.aead_id;
    let info = hex_to_byte_array(&v.info);
    let ikm_e = hex_to_byte_array(&v.ikm_e);
    let ikm_r = hex_to_byte_array(&v.ikm_r);
    let sk_rm = hex_to_byte_array(&v.sk_rm);
    let pk_rm = hex_to_byte_array(&v.pk_rm);
    let enc = hex_to_byte_array(&v.enc);
    let shared_secret = hex_to_byte_array(&v.shared_secret);
    let suite_id = hex_to_byte_array(&v.suite_id);
    let key = hex_to_byte_array(&v.key);
    let base_nonce = hex_to_byte_array(&v.base_nonce);
    let encryptions = {
        let mut out = String::new();
        for e in &v.encryptions {
            out.push_str("        Encryption {\n");
            out.push_str(&format!(
                "            aad: {},\n",
                hex_to_byte_array(&e.aad)
            ));
            out.push_str(&format!("            ct: {},\n", hex_to_byte_array(&e.ct)));
            out.push_str(&format!(
                "            nonce: {},\n",
                hex_to_byte_array(&e.nonce)
            ));
            out.push_str(&format!("            pt: {},\n", hex_to_byte_array(&e.pt)));
            out.push_str("        },\n");
        }
        out
    };
    format!(
        r#"
        pub const {name}: &TestVector = &TestVector {{
            mode: {mode},
            kem_id: {kem_id},
            kdf_id: {kdf_id},
            aead_id: {aead_id},
            info: {info},
            ikm_e: {ikm_e},
            ikm_r: {ikm_r},
            sk_rm: {sk_rm},
            pk_rm: {pk_rm},
            enc: {enc},
            shared_secret: {shared_secret},
            suite_id: {suite_id},
            base_nonce: {base_nonce},
            key: {key},
            encryptions: &[{encryptions}],
        }};
    "#
    )
}

fn hpke_test_vectors() {
    let out_dir = env::var_os("OUT_DIR").unwrap();
    let dest_path = Path::new(&out_dir).join("hpke_test_vectors.rs");

    let types = r#"
pub struct Encryption {
    pub aad: &'static [u8],
    pub ct: &'static [u8],
    pub nonce: &'static [u8; 12],
    pub pt: &'static [u8],
}

pub struct TestVector {
    pub mode: u8,
    pub kem_id: u16,
    pub kdf_id: u16,
    pub aead_id: u16,
    pub info: &'static [u8],
    pub ikm_e: &'static [u8],
    pub ikm_r: &'static [u8],
    pub sk_rm: &'static [u8],
    pub pk_rm: &'static [u8],
    pub enc: &'static [u8],
    pub shared_secret: &'static [u8],
    pub suite_id: &'static [u8],
    pub key: &'static [u8],
    pub base_nonce: &'static [u8],
    pub encryptions: &'static [Encryption],
}"#;
    let mut code = String::from(types);

    let test_vectors = [
        (
            0x42,
            "../../test/src/crypto/test_vectors/hpke-pq.json",
            "MLKEM_TEST_VECTOR",
        ),
        (
            0x51,
            "../../test/src/crypto/test_vectors/hpke-pq.json",
            "HYBRID_TEST_VECTOR",
        ),
        (
            0x11,
            "../../test/src/crypto/test_vectors/hpke-p384.json",
            "P384_TEST_VECTOR",
        ),
    ];
    for (kem_id, json_path, name) in test_vectors {
        println!("cargo:rerun-if-changed={}", json_path);

        let json_data = fs::read_to_string(json_path).unwrap();
        let vectors: Vec<TestVectorJson> = serde_json::from_str(&json_data).unwrap();

        if let Some(v) = vectors
            .iter()
            .find(|v| (v.kem_id == kem_id) && v.kdf_id == 2 && v.aead_id == 2)
        {
            code.push_str(&emit_vector(name, v));
        }
    }

    fs::write(dest_path, code).expect("Could not write generated test vectors");
}

fn main() {
    if cfg!(feature = "riscv") {
        println!("cargo:rerun-if-changed=../../test-harness/scripts/rom.ld");
        println!("cargo:rustc-link-arg=-Ttest-harness/scripts/rom.ld");
    }
    hpke_test_vectors();
}
