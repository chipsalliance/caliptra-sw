/*++

Licensed under the Apache-2.0 license.

File Name:

    build.rs

Abstract:

    Build script for Caliptra ROM Test Runtime.

--*/

fn main() {
    cfg_if::cfg_if! {
        if #[cfg(not(feature = "std"))] {
            use std::env;
            use std::fs;
            use std::path::PathBuf;

            let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
            let ld_script = include_str!("src/rt.ld")
                .replace("#MANIFEST_SIZE#", &caliptra_image_types::IMAGE_MANIFEST_BYTE_SIZE.to_string());
            fs::write(out_dir.join("rt.ld"), ld_script).unwrap();

            println!("cargo:rustc-link-search={}", out_dir.display());
            println!("cargo:rustc-link-arg=-Trt.ld");
            println!("cargo:rerun-if-changed=src/rt.ld");
            println!("cargo:rerun-if-changed=src/start.S");
            println!("cargo:rerun-if-changed=build.rs");
        }
    }
}
