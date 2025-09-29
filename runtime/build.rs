/*++

Licensed under the Apache-2.0 license.

File Name:

    build.rs

Abstract:

    Build script for Caliptra Runtime.

--*/

fn main() {
    cfg_if::cfg_if! {
        if #[cfg(not(feature = "std"))] {
            use caliptra_gen_linker_scripts::gen_memory_x;
            use std::env;
            use std::fs;
            use std::path::PathBuf;

            let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

            let memory_x_str = gen_memory_x(caliptra_common::RUNTIME_ORG, caliptra_common::RUNTIME_SIZE);
            let dest_path = out_dir.join("memory.x");

            match fs::read_to_string(&dest_path) {
                // memory.x already exists with the data we want.
                Ok(existing) if existing.contains(&memory_x_str) => (),
                _ => {
                    fs::write(&dest_path, memory_x_str).expect("Unable to generate memory.x");
                }
            }

            println!("cargo:rustc-link-search={}", out_dir.display());

            println!("cargo:rerun-if-changed=memory.x");
            println!("cargo:rustc-link-arg=-Tmemory.x");

            println!("cargo:rustc-link-arg=-Tlink.x");
            println!("cargo:rerun-if-changed=build.rs");
            println!("cargo:rustc-env=ARBITRARY_MAX_HANDLES=32");
        }
    }
}
