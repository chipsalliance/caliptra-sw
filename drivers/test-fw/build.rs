/*++

Licensed under the Apache-2.0 license.

File Name:

    build.rs

Abstract:

    Cargo build file

--*/

fn main() {
    println!("cargo:rerun-if-changed=scripts/rom.ld");
    println!("cargo:rerun-if-changed=src/bin/start.S");
    println!("cargo:rustc-link-arg=-Tdrivers/test-fw/scripts/rom.ld");
}
