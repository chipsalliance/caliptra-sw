// Licensed under the Apache-2.0 license

fn main() {
    println!("cargo:rerun-if-env-changed=CALIPTRA_HW_REV");
    let revision = match std::env::var("CALIPTRA_HW_REV") {
        Ok(revision) => revision,
        Err(std::env::VarError::NotPresent) => "latest".into(),
        Err(err) => panic!("Invalid CALIPTRA_HW_REV: {err}"),
    };
    let final_block = std::env::var_os("CARGO_FEATURE_HMAC_FINAL_BLOCK").is_some();
    if final_block {
        assert_eq!(
            revision, "latest",
            "hmac-final-block requires CALIPTRA_HW_REV=latest (Caliptra 2.2 hardware)"
        );
    }
    if std::env::var("CARGO_CFG_TARGET_ARCH").as_deref() == Ok("riscv32") && revision == "latest" {
        assert!(
            final_block,
            "Caliptra 2.2/latest firmware requires hmac-final-block; use cargo xtask build or pass --features caliptra-drivers/hmac-final-block"
        );
    }
}
