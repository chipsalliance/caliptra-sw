// Licensed under the Apache-2.0 license

extern crate cbindgen;

use std::path::PathBuf;
use std::{env, str::FromStr};

fn main() {
    // Get Crate dir
    let crate_dir = env::var("CARGO_MANIFEST_DIR").unwrap();

    // Generate Config
    let config = cbindgen::Config {
        header: Some(String::from_str("// Licensed under the Apache-2.0 license").unwrap()),
        language: cbindgen::Language::C,
        include_guard: Some("HW_MODEL_C_BINDING_OUT_CALIPTRA_MODEL_H".to_string()),
        cpp_compat: true,
        ..Default::default()
    };

    // Generate Output file
    let out_file = PathBuf::from(&crate_dir)
        .join("out")
        .join("caliptra_model.h");

    // Generate caliptra_model.h
    cbindgen::Builder::new()
        .with_crate(crate_dir)
        .with_config(config)
        .generate()
        .expect("Unable to generate bindings")
        .write_to_file(out_file);
}
