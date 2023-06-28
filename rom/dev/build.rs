/*++

Licensed under the Apache-2.0 license.

File Name:

    build.rs

Abstract:

    Build script for Caliptra ROM.

--*/

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

fn main() {
    if cfg!(not(feature = "std")) {
        use std::env;
        use std::fs;
        use std::path::PathBuf;

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
}
