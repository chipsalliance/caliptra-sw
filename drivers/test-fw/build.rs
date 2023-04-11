/*++

Licensed under the Apache-2.0 license.

File Name:

    build.rs

Abstract:

    Cargo build file

--*/

fn main() {
    println!("cargo:rerun-if-changed=../../test-harness/scripts/rom.ld");
    println!("cargo:rustc-link-arg=-Ttest-harness/scripts/rom.ld");
}
