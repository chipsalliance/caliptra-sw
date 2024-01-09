/*++

Licensed under the Apache-2.0 license.

File Name:

    build.rs

Abstract:

    Build script for Caliptra Runtime.

--*/

use sha2::{Digest, Sha384};
use std::env;
use std::fs;
use std::path::PathBuf;

type Pcr = [u8; 48];

fn extend_pcr_gen(file_name: &str, old_pcr: &Pcr, extension_data: &Pcr) -> Pcr {
    let mut hasher = Sha384::new();
    let mut pcr_new: [u8; 96] = [0u8; 96];

    pcr_new[..48].copy_from_slice(old_pcr);
    pcr_new[48..].copy_from_slice(extension_data);

    hasher.update(pcr_new);
    let result = hasher.finalize();
    let result: Pcr = result.as_slice().try_into().expect("error finalizing hash");

    // write out hash to build dir
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap()).join(file_name);
    fs::write(&out_dir, result).unwrap();

    println!(
        "cargo:rustc-env={}={}",
        file_name,
        &out_dir.into_os_string().into_string().unwrap()
    );

    result
}

fn main() {
    cfg_if::cfg_if! {
        if #[cfg(not(feature = "std"))] {
            use caliptra_gen_linker_scripts::gen_memory_x;

            let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

            fs::write(out_dir.join("memory.x"),gen_memory_x(caliptra_common::RUNTIME_ORG, caliptra_common::RUNTIME_SIZE)
            .as_bytes())
            .expect("Unable to generate memory.x");

            println!("cargo:rustc-link-search={}", out_dir.display());

            println!("cargo:rerun-if-changed=memory.x");
            println!("cargo:rustc-link-arg=-Tmemory.x");

            println!("cargo:rustc-link-arg=-Tlink.x");
            println!("cargo:rerun-if-changed=build.rs");
        }
    }

    // Generate test data for `runtime/tests/runtime_integration_tests/test_pcr.rs:test_extend_pcr_cmd_multiple_extensions`
    let pcr_4: Pcr = [0u8; 48];
    let pcr_4 = extend_pcr_gen("TEST_EXTEND_1", &pcr_4, &[0u8; 48]);
    let pcr_4 = extend_pcr_gen("TEST_EXTEND_2", &pcr_4, &[0u8; 48]);
    let extension_data: Pcr = [
        225, 73, 188, 244, 110, 120, 121, 204, 185, 203, 86, 129, 104, 186, 33, 110, 125, 116, 216,
        80, 244, 199, 184, 21, 127, 187, 78, 122, 18, 26, 32, 48, 171, 251, 17, 20, 67, 224, 15,
        81, 144, 232, 190, 103, 213, 7, 199, 148,
    ];
    let _pcr_4 = extend_pcr_gen("TEST_EXTEND_3", &pcr_4, &extension_data);
}
