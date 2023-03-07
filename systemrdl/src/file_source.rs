// Licensed under the Apache-2.0 license

use crate::string_arena::StringArena;
use std::path::Path;

#[cfg(test)]
use std::{
    collections::HashMap,
    io::{Error, ErrorKind},
    path::PathBuf,
};

pub trait FileSource {
    fn read_to_string(&self, path: &Path) -> std::io::Result<&str>;
}

#[derive(Default)]
pub struct FsFileSource {
    arena: StringArena,
}

impl FsFileSource {
    pub fn new() -> Self {
        FsFileSource {
            arena: StringArena::new(),
        }
    }
}

impl FileSource for FsFileSource {
    fn read_to_string(&self, path: &Path) -> std::io::Result<&str> {
        Ok(self.arena.add(std::fs::read_to_string(path)?))
    }
}

#[cfg(test)]
pub struct MemFileSource {
    arena: crate::string_arena::StringArena,
    map: HashMap<PathBuf, String>,
}
#[cfg(test)]
impl MemFileSource {
    pub fn from_entries(entries: &[(PathBuf, String)]) -> Self {
        Self {
            arena: StringArena::new(),
            map: entries.iter().cloned().collect(),
        }
    }
}
#[cfg(test)]
impl FileSource for MemFileSource {
    fn read_to_string(&self, path: &Path) -> std::io::Result<&str> {
        Ok(self.arena.add(
            self.map
                .get(path)
                .ok_or(Error::new(ErrorKind::NotFound, path.to_string_lossy()))?
                .clone(),
        ))
    }
}
