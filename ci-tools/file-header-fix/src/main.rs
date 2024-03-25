// Licensed under the Apache-2.0 license

use std::{
    fs::File,
    io::{BufRead, BufReader, Error, ErrorKind},
    path::{Path, PathBuf},
};

const REQUIRED_TEXT: &str = "Licensed under the Apache-2.0 license";
const EXTENSIONS: &[&str] = &["rs", "h", "c", "cpp", "cc", "toml", "sh", "py", "ld", "go"];

const IGNORED_PATHS: &[&str] = &[
    // BSD-licensed
    "./sw-emulator/compliance-test/target-files/link.ld",
    "./runtime/dpe",
    "./hw-latest/fpga/caliptra_build",
    "./hw/fpga/caliptra_build",
    "./hw/1.0/rtl",
    "./hw/latest/rtl",
    "./ci-tools/fpga-boss/image/mnt",
    "./ci-tools/fpga-image/out",
];

const IGNORED_DIRS: &[&str] = &[".git", "caliptra-rtl", "out", "target"];

fn add_path(path: &Path) -> impl Fn(Error) -> Error + Copy + '_ {
    move |e: Error| Error::new(e.kind(), format!("{path:?}: {e}"))
}

fn check_file_contents(path: &Path, contents: impl BufRead) -> Result<(), Error> {
    const N: usize = 3;
    let wrap_err = add_path(path);

    for line in contents.lines().take(N) {
        if line.map_err(wrap_err)?.contains(REQUIRED_TEXT) {
            return Ok(());
        }
    }
    Err(Error::new(
        ErrorKind::Other,
        format!("File {path:?} doesn't contain {REQUIRED_TEXT:?} in the first {N} lines"),
    ))
}

fn check_file(path: &Path) -> Result<(), Error> {
    let wrap_err = add_path(path);
    check_file_contents(path, BufReader::new(File::open(path).map_err(wrap_err)?))
}

fn fix_file(path: &Path) -> Result<(), Error> {
    let wrap_err = add_path(path);

    let mut contents = Vec::from(match path.extension().and_then(|s| s.to_str()) {
        Some("rs" | "h" | "c" | "cpp" | "cc" | "go") => format!("// {REQUIRED_TEXT}\n"),
        Some("toml" | "sh" | "py") => format!("# {REQUIRED_TEXT}\n"),
        Some("ld") => format!("/* {REQUIRED_TEXT} */\n"),
        other => {
            return Err(std::io::Error::new(
                ErrorKind::Other,
                format!("Unknown extension {other:?}"),
            ))
        }
    });
    let mut prev_contents = std::fs::read(path).map_err(wrap_err)?;
    if prev_contents.first() != Some(&b'\n') {
        contents.push(b'\n');
    }
    contents.append(&mut prev_contents);
    std::fs::write(path, contents)?;
    Ok(())
}

fn find_files(dir: &Path, result: &mut Vec<PathBuf>) -> Result<(), Error> {
    let wrap_err = add_path(dir);
    for file in std::fs::read_dir(dir).map_err(wrap_err)? {
        let file = file.map_err(wrap_err)?;
        let file_path = &file.path();
        let wrap_err = add_path(file_path);
        let file_type = file.file_type().map_err(wrap_err)?;
        if let Some(file_path) = file_path.to_str() {
            if IGNORED_PATHS.contains(&file_path) {
                continue;
            }
        }
        if file_type.is_dir() {
            if let Some(file_name) = file.file_name().to_str() {
                if IGNORED_DIRS.contains(&file_name) {
                    continue;
                }
            }
            find_files(file_path, result)?;
        }
        if let Some(Some(extension)) = file.path().extension().map(|s| s.to_str()) {
            if file_type.is_file() && EXTENSIONS.contains(&extension) {
                result.push(file_path.into());
            }
        }
    }
    Ok(())
}

fn main() {
    let args: Vec<_> = std::env::args().skip(1).collect();
    let pwd = Path::new(".");

    let check_only = if args == ["--check"] {
        true
    } else if args.is_empty() {
        false
    } else {
        println!("Usage: file-header-fix [--check]");
        std::process::exit(1);
    };

    let mut files = Vec::new();
    find_files(pwd, &mut files).unwrap();
    files.sort();
    let mut failed = false;
    for file in files.iter() {
        if !check_only && check_file(file).is_err() {
            fix_file(file).unwrap();
        }
        if let Err(e) = check_file(file) {
            println!("{e}");
            failed = true;
        }
    }
    if failed {
        println!("To fix, run \"ci-tools/file-header-fix.sh\" from the repo root.");
        std::process::exit(2);
    }
}

#[cfg(test)]
mod test {
    use crate::*;

    #[test]
    fn test_check_success() {
        check_file_contents(
            Path::new("foo/bar.rs"),
            "# Licensed under the Apache-2.0 license".as_bytes(),
        )
        .unwrap();
        check_file_contents(
            Path::new("foo/bar.rs"),
            "/*\n * Licensed under the Apache-2.0 license\n */".as_bytes(),
        )
        .unwrap();
    }

    #[test]
    fn test_check_failures() {
        assert_eq!(
            check_file_contents(Path::new("foo/bar.rs"), "int main()\n {\n // foobar\n".as_bytes()).unwrap_err().to_string(),
             "File \"foo/bar.rs\" doesn't contain \"Licensed under the Apache-2.0 license\" in the first 3 lines");

        assert_eq!(
            check_file_contents(Path::new("bar/foo.sh"), "".as_bytes()).unwrap_err().to_string(),
             "File \"bar/foo.sh\" doesn't contain \"Licensed under the Apache-2.0 license\" in the first 3 lines");

        let err = check_file_contents(Path::new("some/invalid_utf8_file"), [0x80].as_slice())
            .unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidData);
        assert!(err.to_string().contains("some/invalid_utf8_file"));
    }
}
