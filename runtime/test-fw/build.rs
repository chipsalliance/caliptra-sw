// Licensed under the Apache-2.0 license

fn main() {
    cfg_if::cfg_if! {
        if #[cfg(not(feature = "std"))] {
            cfg_if::cfg_if! {
                if #[cfg(feature = "runtime")] {
                    use std::env;
                    use std::fs;
                    use std::path::PathBuf;

                    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
                    // Put the linker script somewhere the linker can find it.
                    fs::write(out_dir.join("memory.x"), include_bytes!("../memory.x")).unwrap();
                    println!("cargo:rustc-link-search={}", out_dir.display());

                    println!("cargo:rerun-if-changed=memory.x");
                    println!("cargo:rustc-link-arg=-Tmemory.x");

                    println!("cargo:rustc-link-arg=-Tlink.x");
                } else {
                    println!("cargo:rerun-if-changed=../../test-harness/scripts/rom.ld");
                    println!("cargo:rustc-link-arg=-Ttest-harness/scripts/rom.ld");
                }
            }
        }
    }
}
