// Licensed under the Apache-2.0 license

use std::{fs, io, path::PathBuf};

use crate::util::hex;

pub trait Cache {
    fn set(&self, key: &str, val: &[u8]) -> io::Result<()>;
    fn get(&self, key: &str) -> io::Result<Option<Vec<u8>>>;
}

pub struct FsCache {
    dir: PathBuf,
}
impl FsCache {
    pub fn new(dir: PathBuf) -> io::Result<Self> {
        fs::create_dir_all(&dir)?;
        Ok(Self { dir })
    }
}
impl Cache for FsCache {
    fn set(&self, key: &str, val: &[u8]) -> io::Result<()> {
        fs::write(self.dir.join(hex(key.as_bytes())), val)
    }

    fn get(&self, key: &str) -> io::Result<Option<Vec<u8>>> {
        match fs::read(self.dir.join(hex(key.as_bytes()))) {
            Ok(data) => Ok(Some(data)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }
}
