use crate::git;
use caliptra_builder::{elf_size, firmware, FwId};
use serde::{Deserialize, Serialize};
use std::io;

#[derive(Clone, Copy, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct Sizes {
    pub rom_size_with_uart: Option<u64>,
    pub rom_size_prod: Option<u64>,
    pub fmc_size_with_uart: Option<u64>,
    pub app_size_with_uart: Option<u64>,
}

impl Sizes {
    pub fn update_from(&mut self, other: &Sizes) {
        self.rom_size_with_uart = other.rom_size_with_uart.or(self.rom_size_with_uart);
        self.rom_size_prod = other.rom_size_prod.or(self.rom_size_prod);
        self.fmc_size_with_uart = other.fmc_size_with_uart.or(self.fmc_size_with_uart);
        self.app_size_with_uart = other.app_size_with_uart.or(self.app_size_with_uart);
    }
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct SizeRecord {
    pub commit: git::CommitInfo,
    pub sizes: Sizes,
}

pub fn compute_size(worktree: &git::WorkTree, commit_id: &str) -> Sizes {
    // TODO: consider using caliptra_builder from the same repo as the firmware
    let fwid_elf_size = |fwid: &FwId| -> io::Result<u64> {
        let workspace_dir = Some(worktree.path);
        let elf_bytes = caliptra_builder::build_firmware_elf_uncached(workspace_dir, fwid)?;
        elf_size(&elf_bytes)
    };
    let fwid_elf_size_or_none = |fwid: &FwId| -> Option<u64> {
        match fwid_elf_size(fwid) {
            Ok(result) => Some(result),
            Err(err) => {
                println!("Error building commit {}: {err}", commit_id);
                None
            }
        }
    };

    Sizes {
        rom_size_with_uart: fwid_elf_size_or_none(&firmware::ROM_WITH_UART),
        rom_size_prod: fwid_elf_size_or_none(&firmware::ROM),
        fmc_size_with_uart: fwid_elf_size_or_none(&firmware::FMC_WITH_UART),
        app_size_with_uart: fwid_elf_size_or_none(&firmware::APP_WITH_UART),
    }
}