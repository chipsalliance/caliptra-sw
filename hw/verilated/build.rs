// Licensed under the Apache-2.0 license

use std::{
    ffi::OsStr,
    fs::File,
    io::{BufRead, BufReader},
    iter,
    path::{Path, PathBuf},
    process,
};

static DEP_FILES: &[&str] = &[
    "caliptra_verilated.cpp",
    "caliptra_verilated.h",
    "caliptra_verilated.sv",
    "out",
    "Makefile",
    "../config/caliptra_top_tb.vf",
];

fn cmd_args(cmd: &mut process::Command) -> Vec<&OsStr> {
    iter::once(cmd.get_program())
        .chain(cmd.get_args())
        .collect()
}

fn run_command(cmd: &mut process::Command) {
    match cmd.status() {
        Err(err) => {
            eprintln!("Command {:?} failed: {}", cmd_args(cmd), err);
            std::process::exit(1);
        }
        Ok(status) => {
            if !status.success() {
                eprintln!("Command {:?} exit code {:?}", cmd_args(cmd), status.code());
                eprintln!("Please ensure that you have verilator 5.004 or later installed");
                std::process::exit(1);
            }
        }
    }
}

fn add_filename(filename: &Path) -> impl FnOnce(std::io::Error) -> std::io::Error + '_ {
    move |e| std::io::Error::new(e.kind(), format!("{filename:?}: {e}"))
}

fn sv_files(manifest_dir: &Path) -> Result<Vec<String>, std::io::Error> {
    let mut result = vec![];
    let filename = manifest_dir.join("../1.0/rtl/src/integration/config/caliptra_top_tb.vf");
    for line in BufReader::new(File::open(&filename).map_err(add_filename(&filename))?).lines() {
        let line = line?;
        if line.starts_with('+') {
            continue;
        }
        result.push(line.replace("${WORKSPACE}/Caliptra", "../../.."));
    }
    Ok(result)
}

fn main() {
    if std::env::var_os("CARGO_FEATURE_VERILATOR").is_none() {
        return;
    }
    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());

    let files = match sv_files(&manifest_dir) {
        Ok(files) => files,
        Err(e) => panic!(
            "{e}; run \"git submodule update --init\" to ensure the RTL submodule is populated."
        ),
    };

    let mut make_cmd = process::Command::new("make");
    make_cmd.current_dir(&manifest_dir);
    if std::env::var_os("CARGO_FEATURE_ITRNG").is_some() {
        make_cmd.arg("EXTRA_VERILATOR_FLAGS=-DCALIPTRA_INTERNAL_TRNG");
    }

    run_command(&mut make_cmd);

    for p in DEP_FILES {
        println!("cargo:rerun-if-changed={}", manifest_dir.join(p).display());
    }
    for p in files {
        println!("cargo:rerun-if-changed={}", manifest_dir.join(p).display());
    }

    println!("cargo:rustc-link-search={}/out", manifest_dir.display());
    println!("cargo:rustc-link-lib=static=caliptra_verilated");
    println!("cargo:rustc-link-lib=dylib=stdc++");
}
