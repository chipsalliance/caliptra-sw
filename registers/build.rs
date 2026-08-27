// Licensed under the Apache-2.0 license

fn main() {
    let rev = std::env::var("CALIPTRA_HW_REV").unwrap_or_else(|_| "latest".to_string());
    match rev.as_str() {
        "latest" => println!("cargo::rustc-cfg=hw_rev=\"latest\""),
        "2.0" => println!("cargo::rustc-cfg=hw_rev=\"2.0\""),
        "2.1" => println!("cargo::rustc-cfg=hw_rev=\"2.1\""),
        _ => panic!("Unsupported CALIPTRA_HW_REV: {}", rev),
    }
    println!("cargo:rerun-if-env-changed=CALIPTRA_HW_REV");
}
