// Licensed under the Apache-2.0 license

use std::{io, path::Path};

use caliptra_builder::{elf_size, FwId};

/// Trait for building artifacts and measuring their size.
pub trait ArtifactBuilder {
    /// Unique name for this artifact (used in reports and cache keys).
    fn name(&self) -> &str;

    /// Build the artifact and return its size.
    /// Returns None if build fails (graceful degradation).
    fn build_and_measure(&self, workspace: &Path) -> Option<u64>;
}

/// Builds Caliptra firmware using caliptra_builder and measures ELF size.
pub struct CaliptraFirmwareBuilder {
    name: String,
    fwid: FwId<'static>,
}

impl CaliptraFirmwareBuilder {
    pub fn new(name: impl Into<String>, fwid: FwId<'static>) -> Self {
        Self {
            name: name.into(),
            fwid,
        }
    }

    fn build_elf(&self, workspace: &Path) -> io::Result<u64> {
        let elf_bytes = caliptra_builder::build_firmware_elf_uncached(Some(workspace), &self.fwid)?;
        elf_size(&elf_bytes)
    }
}

impl ArtifactBuilder for CaliptraFirmwareBuilder {
    fn name(&self) -> &str {
        &self.name
    }

    fn build_and_measure(&self, workspace: &Path) -> Option<u64> {
        match self.build_elf(workspace) {
            Ok(size) => Some(size),
            Err(err) => {
                println!("Error building {}: {err}", self.name);
                None
            }
        }
    }
}
