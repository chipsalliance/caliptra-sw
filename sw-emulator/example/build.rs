/*++

Licensed under the Apache-2.0 license.

File Name:

    build.rs

Abstract:

    Cargo build file

--*/

fn main() {
    println!("cargo:rerun-if-changed=src/link.ld");
    println!("cargo:rerun-if-changed=src/start.S");
}
