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

        println!("!!!!!!!!!!");

        println!("cargo:rustc-link-search={}", out_dir.display());
        println!("cargo:rustc-link-arg=-Trom.ld");
        println!("cargo:rerun-if-changed=src/rom.ld");
        println!("cargo:rerun-if-changed=src/start.S");
        println!("cargo:rerun-if-changed=build.rs");
        println!("cargo:rerun-if-changed=test-fw/start_min.S");

        fs::write(out_dir.join("rom.ld"), include_bytes!("src/rom.ld")).unwrap();

        let preprocessor_vars: Vec<_> = env::vars()
            .filter(|(k, _)| k.starts_with("CARGO_"))
            .collect();

        std::fs::write(
            out_dir.join("start_preprocessed.S"),
            preprocess("src/start.S", &preprocessor_vars),
        )
        .unwrap();
    }

    if cfg!(feature = "fake-rom") {
        use x509_parser::nom::Parser;
        use x509_parser::prelude::{FromDer, X509CertificateParser};
        use x509_parser::signature_value::EcdsaSigValue;

        let ws_dir = workspace_dir();
        let ldev_file = std::fs::read(
            ws_dir.join("test/tests/caliptra_integration_tests/smoke_testdata/ldevid_cert.der"),
        )
        .unwrap();

        let mut parser = X509CertificateParser::new();
        let (_, cert) = parser.parse(&ldev_file).unwrap();

        let tbs = cert.tbs_certificate.as_ref();
        let (_, sig) = EcdsaSigValue::from_der(cert.signature_value.as_ref()).unwrap();

        // Get words of Signature r and s
        let mut r = sig.r.as_ref();
        r = &r[r.len() - 48..];
        let r_words = be_bytes_to_words(r);

        let mut s = sig.s.as_ref();
        s = &s[s.len() - 48..];
        let s_words = be_bytes_to_words(s);

        let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
        std::fs::write(out_dir.join("ldev_tbs.der"), tbs).unwrap();
        std::fs::write(
            out_dir.join("ldev_sig_r_words.txt"),
            format!("{:?}", r_words),
        )
        .unwrap();
        std::fs::write(
            out_dir.join("ldev_sig_s_words.txt"),
            format!("{:?}", s_words),
        )
        .unwrap();
    }
}
