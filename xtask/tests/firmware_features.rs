// Licensed under the Apache-2.0 license

use std::process::Command;

#[test]
fn firmware_features_query_has_machine_readable_stdout() {
    for revision in ["2.1", "latest"] {
        let output = Command::new(env!("CARGO_BIN_EXE_xtask"))
            .env("CALIPTRA_HW_REV", revision)
            .args([
                "--verbose",
                "build",
                "features",
                "--package",
                "caliptra-rom",
                "--features",
                "cfi,emu",
            ])
            .output()
            .unwrap();
        assert!(output.status.success());
        assert_eq!(output.stdout, b"cfi,emu,riscv\n");
        assert!(output.stderr.is_empty());
    }
}

#[test]
fn firmware_features_query_reports_errors_on_stderr() {
    let output = Command::new(env!("CARGO_BIN_EXE_xtask"))
        .env("CALIPTRA_HW_REV", "2.1")
        .args([
            "--rev",
            "2.2",
            "build",
            "features",
            "--package",
            "caliptra-rom",
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr)
        .contains("Unsupported CALIPTRA_HW_REV=\"2.2\" for caliptra-rom; expected 2.1 or latest"));
}
