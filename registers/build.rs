// Licensed under the Apache-2.0 license

fn main() {
    let rev = std::env::var("CALIPTRA_HW_REV").unwrap_or_else(|_| "2.2".to_string());
    match rev.as_str() {
        "latest" | "2.2" => {}
        _ => panic!("This development branch supports only Caliptra 2.2, not {rev}"),
    }
    println!("cargo:rerun-if-env-changed=CALIPTRA_HW_REV");
}
