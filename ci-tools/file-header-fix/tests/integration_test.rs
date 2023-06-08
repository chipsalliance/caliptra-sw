// Licensed under the Apache-2.0 license

use std::{
    env::temp_dir,
    fs,
    path::{Path, PathBuf},
    process::Stdio,
};

const PROGRAM_BIN: &str = env!("CARGO_BIN_EXE_caliptra-file-header-fix");

#[test]
fn test_usage() {
    let out = std::process::Command::new(PROGRAM_BIN)
        .arg("--help")
        .stderr(Stdio::inherit())
        .output()
        .unwrap();

    assert_eq!(out.status.code(), Some(1));
    assert_eq!(
        std::str::from_utf8(&out.stdout),
        Ok("Usage: file-header-fix [--check]\n")
    );
}

#[test]
fn test_check_only_failure() {
    let tmp_dir = TmpDir::new("caliptra-file-header-fix-test-check-only-failure").unwrap();
    tmp_dir.write("ignore.txt", "Hi!");
    tmp_dir.write("scripts/foo.sh", "echo Hi\n");
    tmp_dir.write("hello.rs", "// Licensed under the Apache-2.0 license.\n");
    tmp_dir.write("foo.rs", "#![no_std]\n");
    let out = std::process::Command::new(PROGRAM_BIN)
        .current_dir(&tmp_dir.0)
        .arg("--check")
        .stderr(Stdio::inherit())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert_eq!(std::str::from_utf8(&out.stdout), Ok(
        "File \"./foo.rs\" doesn't contain \"Licensed under the Apache-2.0 license\" in the first 3 lines\n\
         File \"./scripts/foo.sh\" doesn't contain \"Licensed under the Apache-2.0 license\" in the first 3 lines\n\
         To fix, run \"cargo run --bin file-header-fix\" in the workspace directory.\n"));

    // Make sure it didn't rewrite
    assert_eq!(tmp_dir.read("foo.rs"), "#![no_std]\n");
}

#[test]
fn test_check_only_success() {
    let tmp_dir = TmpDir::new("caliptra-file-header-fix-test-check-only-success").unwrap();
    tmp_dir.write("ignore.txt", "Hi!");
    tmp_dir.write("scripts/foo.sh", "# Licensed under the Apache-2.0 license");
    tmp_dir.write("hello.rs", "/* Licensed under the Apache-2.0 license.\n */");
    tmp_dir.write("foo.rs", "// Licensed under the Apache-2.0 license");
    let out = std::process::Command::new(PROGRAM_BIN)
        .current_dir(&tmp_dir.0)
        .arg("--check")
        .stderr(Stdio::inherit())
        .output()
        .unwrap();
    assert_eq!(std::str::from_utf8(&out.stdout), Ok(""));
    assert_eq!(out.status.code(), Some(0));
    // Make sure it didn't rewrite
    assert_eq!(
        tmp_dir.read("hello.rs"),
        "/* Licensed under the Apache-2.0 license.\n */"
    );
}

#[test]
fn test_fix() {
    let tmp_dir = TmpDir::new("caliptra-file-header-fix").unwrap();
    tmp_dir.write("ignore.txt", "Hi!");
    tmp_dir.write("target/bar/foo.rs", "Ignore Me!");
    tmp_dir.write("hello.rs", "/* Licensed under the Apache-2.0 license. */\n");
    tmp_dir.write("foo.rs", "#![no_std]\n");
    tmp_dir.write("main.rs", "\nfn main() {}\n");
    tmp_dir.write("include/empty.h", "");
    tmp_dir.write(
        "scripts/foo.sh",
        "# Licensed under the Fishy Proprietary License v6.66",
    );
    let out = std::process::Command::new(PROGRAM_BIN)
        .current_dir(&tmp_dir.0)
        .stderr(Stdio::inherit())
        .output()
        .unwrap();
    assert_eq!(std::str::from_utf8(&out.stdout), Ok(""));
    assert_eq!(out.status.code(), Some(0));

    // .txt should be ignored
    assert_eq!(tmp_dir.read("ignore.txt"), "Hi!");

    // target/ directories should be ignored
    assert_eq!(tmp_dir.read("target/bar/foo.rs"), "Ignore Me!");

    // formatting should not have been changed
    assert_eq!(
        tmp_dir.read("hello.rs"),
        "/* Licensed under the Apache-2.0 license. */\n"
    );

    // License prepended with extra newline
    assert_eq!(
        tmp_dir.read("foo.rs"),
        "// Licensed under the Apache-2.0 license\n\
         \n\
         #![no_std]\n"
    );

    // License prepended without extra newline
    assert_eq!(
        tmp_dir.read("main.rs"),
        "// Licensed under the Apache-2.0 license\n\
         \n\
         fn main() {}\n"
    );

    assert_eq!(
        tmp_dir.read("include/empty.h"),
        "// Licensed under the Apache-2.0 license\n\n"
    );

    // code reviewers should notice the file has two licenses
    assert_eq!(tmp_dir.read("scripts/foo.sh"), "# Licensed under the Apache-2.0 license\n\
                                                \n\
                                                # Licensed under the Fishy Proprietary License v6.66");
}

struct TmpDir(pub PathBuf);
impl TmpDir {
    fn new(name: &str) -> std::io::Result<Self> {
        let dir = temp_dir().join(name);
        fs::create_dir(&dir)?;
        Ok(Self(dir))
    }
    fn read(&self, path: impl AsRef<Path>) -> String {
        std::fs::read_to_string(self.0.join(path)).unwrap()
    }
    fn write(&self, path: impl AsRef<Path>, contents: &str) {
        let path = self.0.join(path);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(path, contents).unwrap();
    }
}
impl Drop for TmpDir {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).ok();
    }
}
