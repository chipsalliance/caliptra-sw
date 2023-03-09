/*++

Licensed under the Apache-2.0 license.

File Name:

    fs.rs

Abstract:

    Offers filesystem functionality similar to std::fs but with better error
    messages that include the path.

--*/

use std::fmt::Debug;
use std::path::{Path, PathBuf};

/// Same as [`std::fs::create_dir`] but with more informative errors.
pub fn create_dir<P: AsRef<Path> + Debug>(path: P) -> std::io::Result<()> {
    std::fs::create_dir(&path)
        .map_err(|err| annotate_error(err, &format!("while creating dir {:?}", path)))
}

/// Same as [`std::fs::write`] but with more informative errors.
#[allow(dead_code)]
pub fn write<P: AsRef<Path> + Debug, C: AsRef<[u8]>>(path: P, contents: C) -> std::io::Result<()> {
    std::fs::write(&path, contents)
        .map_err(|err| annotate_error(err, &format!("while writing to file {:?}", path)))
}

/// Same as [`std::fs::read`] but with more informative errors.
pub fn read<P: AsRef<Path> + Debug>(path: P) -> std::io::Result<Vec<u8>> {
    std::fs::read(&path)
        .map_err(|err| annotate_error(err, &format!("while reading from file {:?}", path)))
}

pub struct TempFile {
    path: PathBuf,
}
impl TempFile {
    #[allow(dead_code)]
    pub fn new() -> std::io::Result<Self> {
        Ok(Self {
            path: Path::join(&std::env::temp_dir(), rand_str()?),
        })
    }
    pub fn with_extension(ext: &str) -> std::io::Result<Self> {
        Ok(Self {
            path: Path::join(&std::env::temp_dir(), rand_str()? + ext),
        })
    }
    pub fn path(&self) -> &Path {
        &self.path
    }
}
impl Debug for TempFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Debug::fmt(&self.path, f)
    }
}
impl AsRef<Path> for TempFile {
    fn as_ref(&self) -> &Path {
        &self.path
    }
}
impl Drop for TempFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(self.path());
    }
}

/// A temporary directory that will be deleted (best-effort) when the
/// [`TempDir`] is dropped.
pub struct TempDir {
    path: PathBuf,
}
impl TempDir {
    /// Creates a new temporary directory in the system temp directory
    /// with a random name.
    pub fn new() -> std::io::Result<Self> {
        let path = Path::join(&std::env::temp_dir(), rand_str()?);
        create_dir(&path)?;
        Ok(Self { path })
    }
    pub fn path(&self) -> &Path {
        &self.path
    }
}
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(self.path());
    }
}
impl Debug for TempDir {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Debug::fmt(&self.path, f)
    }
}
impl AsRef<Path> for TempDir {
    fn as_ref(&self) -> &Path {
        &self.path
    }
}

pub fn annotate_error(err: std::io::Error, suffix: &str) -> std::io::Error {
    std::io::Error::new(err.kind(), err.to_string() + ": " + suffix)
}

fn rand_str() -> std::io::Result<String> {
    let chars = b"abcdefghijklmnopqrstuvwxyz123456";
    let mut result = vec![0u8; 24];
    if let Err(err) = getrandom::getrandom(&mut result) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("Unable to retrive random data from OS: {}", err),
        ));
    }
    for ch in result.iter_mut() {
        *ch = chars[usize::from(*ch & 0x1f)];
    }
    Ok(String::from_utf8(result).unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{io::ErrorKind, sync::Mutex};

    #[test]
    fn test_create_dir_success() {
        let tmp_dir = TempDir::new().unwrap();
        let my_dir_path = tmp_dir.path().join("my_unique_and_awesome_dir");

        create_dir(&my_dir_path).unwrap();
        assert!(std::fs::metadata(&my_dir_path).unwrap().is_dir());
    }

    #[test]
    fn test_create_dir_failure() {
        let tmp_dir = TempDir::new().unwrap();
        let my_dir_path = tmp_dir.path().join("my_unique_and_awesome_dir");
        create_dir(&my_dir_path).unwrap();

        let result = create_dir(&my_dir_path);
        assert!(result.is_err());
        let err = result.err().unwrap();
        assert_eq!(err.kind(), ErrorKind::AlreadyExists);
        assert!(err.to_string().contains("while creating dir"));
        assert!(err.to_string().contains("my_unique_and_awesome_dir"));
    }

    #[test]
    fn test_read_and_write_success() {
        let tmp_file = TempFile::with_extension(".txt").unwrap();

        // Read-and-write success case
        write(&tmp_file, "Hello world").unwrap();
        assert_eq!(read(&tmp_file).unwrap(), b"Hello world");
    }

    #[test]
    fn test_read_failure() {
        let tmp_file = TempFile::with_extension(".txt").unwrap();

        let result = read(&tmp_file);
        assert!(result.is_err());
        let err = result.err().unwrap();
        assert_eq!(err.kind(), ErrorKind::NotFound);
        assert!(err
            .to_string()
            .contains(&format!("while reading from file {:?}", tmp_file.path())));
    }

    #[test]
    fn test_write_failure() {
        let no_such_dir = TempFile::new().unwrap();
        let file_path = no_such_dir.path().join("foobar");

        let result = write(&file_path, "Hello world!");
        assert!(result.is_err());
        let err = result.err().unwrap();
        assert_eq!(err.kind(), ErrorKind::NotFound);
        assert!(err
            .to_string()
            .contains(&format!("while writing to file {:?}", file_path)));
    }

    #[test]
    fn test_tempfile() {
        let temp_files = [
            TempFile::new().unwrap(),
            TempFile::new().unwrap(),
            TempFile::with_extension(".o").unwrap(),
            TempFile::with_extension(".o").unwrap(),
        ];

        let paths: Vec<PathBuf> = temp_files.iter().map(|t| t.path().to_path_buf()).collect();

        assert!(paths.iter().all(|p| !p.exists()));
        assert!([&paths[2], &paths[3]]
            .iter()
            .all(|p| p.to_str().unwrap().ends_with(".o")));
        assert_ne!(&paths[0], &paths[1]);
        assert_ne!(&paths[2], &paths[3]);
        write(&paths[0], "Hello").unwrap();
        write(&temp_files[2], "World").unwrap();

        assert!([&paths[0], &paths[2]].iter().all(|p| p.exists()));
        assert!([&paths[1], &paths[3]].iter().all(|p| !p.exists()));
        drop(temp_files);
        assert!(paths.iter().all(|p| !p.exists()));
    }

    #[test]
    fn test_tempfile_drop_on_panic() {
        let tmp_path: Mutex<Option<PathBuf>> = Mutex::new(None);
        let err = std::panic::catch_unwind(|| {
            let tmp = TempFile::new().unwrap();
            write(&tmp, "hello").unwrap();
            *tmp_path.lock().unwrap() = Some(tmp.path().to_owned());
            assert!(tmp.path().exists());
            panic!("fake panic");
        })
        .err()
        .unwrap();
        assert_eq!(*err.downcast_ref::<&'static str>().unwrap(), "fake panic");
        assert!(!tmp_path.into_inner().unwrap().unwrap().exists());
    }

    #[test]
    fn test_tempdir_deleted() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().to_owned();
        assert!(path.is_dir());
        write(path.join("file0.txt"), "Hello").unwrap();
        write(path.join("file1.txt"), "world!").unwrap();

        assert!([&path, &path.join("file0.txt"), &path.join("file1.txt")]
            .iter()
            .all(|p| p.exists()));
        drop(dir);
        assert!([&path, &path.join("file0.txt"), &path.join("file1.txt")]
            .iter()
            .all(|p| !p.exists()));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_tempdir_delete_error() {
        use std::os::unix::prelude::PermissionsExt;

        let dir = TempDir::new().unwrap();
        let dir_path = dir.path().to_owned();
        let inner_dir = dir.path().join("inner");
        create_dir(&inner_dir).unwrap();
        let file_path = inner_dir.join("file0.txt");
        write(&file_path, "Hello").unwrap();
        std::fs::set_permissions(&inner_dir, std::fs::Permissions::from_mode(0o000)).unwrap();

        assert!([&dir_path, &inner_dir].iter().all(|p| p.exists()));
        drop(dir);
        // Note: attempts to remove the directory on drop are best effort
        assert!([&dir_path, &inner_dir].iter().all(|p| p.exists()));

        std::fs::set_permissions(&inner_dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::remove_dir_all(dir_path).unwrap();
    }
}
