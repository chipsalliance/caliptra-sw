/*++

Licensed under the Apache-2.0 license.

File Name:

    build.rs

Abstract:

    Build script for Caliptra ROM.

--*/

use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

use caliptra_common::x509::get_tbs;

fn preprocess(filename: &str, defines: &[(String, String)]) -> Vec<u8> {
    let mut cmd = Command::new("cc");
    cmd.arg("-E");
    for (key, val) in defines {
        cmd.arg(format!("-D{key}={val}"));
    }
    cmd.arg(filename);
    let out = cmd.output().unwrap();
    if !out.status.success() {
        panic!(
            "failed to use cc preprocessor {} {}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }
    out.stdout
}

fn workspace_dir() -> PathBuf {
    let output = std::process::Command::new(env!("CARGO"))
        .arg("locate-project")
        .arg("--workspace")
        .arg("--message-format=plain")
        .output()
        .unwrap()
        .stdout;
    let cargo_path = Path::new(std::str::from_utf8(&output).unwrap().trim());
    cargo_path.parent().unwrap().to_path_buf()
}

fn be_bytes_to_words(src: &[u8]) -> Vec<u32> {
    let mut dst = Vec::<u32>::new();

    for i in (0..src.len()).step_by(4) {
        dst.push(u32::from_be_bytes(src[i..i + 4].try_into().unwrap()));
    }

    dst
}

fn main() {
    if cfg!(not(feature = "std")) {
        use std::fs;

        let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
        fs::write(out_dir.join("rom.ld"), include_bytes!("src/rom.ld")).unwrap();

        let preprocessor_vars: Vec<_> = env::vars()
            .filter(|(k, _)| k.starts_with("CARGO_"))
            .collect();

        std::fs::write(
            out_dir.join("start_preprocessed.S"),
            preprocess("src/start.S", &preprocessor_vars),
        )
        .unwrap();

        println!("cargo:rustc-link-search={}", out_dir.display());
        println!("cargo:rustc-link-arg=-Trom.ld");
        println!("cargo:rerun-if-changed=src/rom.ld");
        println!("cargo:rerun-if-changed=src/start.S");
        println!("cargo:rerun-if-changed=build.rs");
    }

    if cfg!(feature = "fake-rom") {
        use const_gen::*;
        use openssl::bn::{BigNum, BigNumContext};
        use openssl::ec::EcGroup;
        use openssl::ecdsa::EcdsaSig;
        use openssl::nid::Nid;

        #[derive(CompileConst)]
        struct Array4xN(pub [u32; 12]);

        #[derive(CompileConst)]
        struct Ecc384PubKey {
            pub x: Array4xN,
            pub y: Array4xN,
        }
        #[derive(CompileConst)]
        pub struct Ecc384Signature {
            pub r: Array4xN,
            pub s: Array4xN,
        }

        let ws_dir = workspace_dir();

        // Create a closure to process ECC certificates
        let group = EcGroup::from_curve_name(Nid::SECP384R1).unwrap();
        let mut ctx = BigNumContext::new().unwrap();

        let mut process_ecc_cert = |cert_path: &str| -> (Ecc384PubKey, Ecc384Signature, Vec<u8>) {
            let file_path = ws_dir.join(cert_path);
            println!("cargo:rerun-if-changed={}", file_path.to_str().unwrap());

            let file_data = std::fs::read(&file_path).unwrap();
            let cert = openssl::x509::X509::from_der(&file_data).unwrap();
            let tbs = get_tbs(file_data);

            // Extract public key
            let pubkey = cert.public_key().unwrap();
            let pubkey = pubkey.ec_key().unwrap();
            let pubkey = pubkey.public_key();

            let mut x = BigNum::new().unwrap();
            let mut y = BigNum::new().unwrap();
            pubkey
                .affine_coordinates(&group, &mut x, &mut y, &mut ctx)
                .unwrap();

            let x_vec = x.to_vec();
            let x_words = be_bytes_to_words(&x_vec);
            let y_vec = y.to_vec();
            let y_words = be_bytes_to_words(&y_vec);

            let ecc_pubkey = Ecc384PubKey {
                x: Array4xN(x_words.try_into().unwrap()),
                y: Array4xN(y_words.try_into().unwrap()),
            };

            // Extract signature
            let signature = cert.signature().as_slice();
            let signature = EcdsaSig::from_der(signature).unwrap();

            let r = signature.r().to_vec();
            let r_words = be_bytes_to_words(&r);
            let s = signature.s().to_vec();
            let s_words = be_bytes_to_words(&s);

            let ecc_signature = Ecc384Signature {
                r: Array4xN(r_words.try_into().unwrap()),
                s: Array4xN(s_words.try_into().unwrap()),
            };

            (ecc_pubkey, ecc_signature, tbs)
        };

        // Process LDEVID ECC certificate
        let (ecc_ldev_pubkey, ecc_ldev_signature, ecc_ldev_tbs) = process_ecc_cert(
            "test/tests/caliptra_integration_tests/smoke_testdata/ldevid_cert_ecc.der",
        );

        // Process FMC alias ECC certificate
        let (ecc_fmc_pubkey, ecc_fmc_signature, ecc_fmc_tbs) = process_ecc_cert(
            "test/tests/caliptra_integration_tests/smoke_testdata/fmc_alias_cert_ecc.der",
        );

        // Create a closure to process MLDSA certificates
        let process_mldsa_cert = |cert_path: &str| -> (Vec<u8>, Vec<u8>, Vec<u8>) {
            let file_path = ws_dir.join(cert_path);
            println!("cargo:rerun-if-changed={}", file_path.to_str().unwrap());

            let file_data = std::fs::read(&file_path).unwrap();
            let cert = openssl::x509::X509::from_der(&file_data).unwrap();
            let tbs = get_tbs(file_data);

            // Extract public key
            let pubkey = cert.public_key().unwrap().raw_public_key().unwrap();

            // Pad MLDSA signature
            let mut signature = vec![0; 4628];
            signature[..4627].copy_from_slice(cert.signature().as_slice());

            (pubkey, signature, tbs)
        };

        // Process LDEVID MLDSA certificate
        let (mldsa_ldev_pubkey, mldsa_ldev_signature, mldsa_ldev_tbs) = process_mldsa_cert(
            "test/tests/caliptra_integration_tests/smoke_testdata/ldevid_cert_mldsa.der",
        );

        // Process FMC alias MLDSA certificate
        let (mldsa_fmc_pubkey, mldsa_fmc_signature, mldsa_fmc_tbs) = process_mldsa_cert(
            "test/tests/caliptra_integration_tests/smoke_testdata/fmc_alias_cert_mldsa.der",
        );

        // Generate Rust constants for all certificates
        let const_declarations = vec![
            const_array_declaration!(pub FAKE_FMC_ALIAS_ECC_TBS = ecc_fmc_tbs),
            const_array_declaration!(pub FAKE_FMC_ALIAS_MLDSA_PUB_KEY = mldsa_fmc_pubkey),
            const_array_declaration!(pub FAKE_FMC_ALIAS_MLDSA_SIG = mldsa_fmc_signature),
            const_array_declaration!(pub FAKE_FMC_ALIAS_MLDSA_TBS = mldsa_fmc_tbs),
            const_array_declaration!(pub FAKE_LDEV_ECC_TBS = ecc_ldev_tbs),
            const_array_declaration!(pub FAKE_LDEV_MLDSA_PUB_KEY = mldsa_ldev_pubkey),
            const_array_declaration!(pub FAKE_LDEV_MLDSA_SIG = mldsa_ldev_signature),
            const_array_declaration!(pub FAKE_LDEV_MLDSA_TBS = mldsa_ldev_tbs),
            const_declaration!(pub FAKE_FMC_ALIAS_ECC_PUB_KEY = ecc_fmc_pubkey),
            const_declaration!(pub FAKE_FMC_ALIAS_ECC_SIG = ecc_fmc_signature),
            const_declaration!(pub FAKE_LDEV_ECC_PUB_KEY = ecc_ldev_pubkey),
            const_declaration!(pub FAKE_LDEV_ECC_SIG = ecc_ldev_signature),
        ]
        .join("\n");

        let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
        std::fs::write(out_dir.join("fake_consts.rs"), const_declarations).unwrap();
    }
}
