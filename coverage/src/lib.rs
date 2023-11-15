// Licensed under the Apache-2.0 license

use anyhow::Context;
use bit_vec::BitVec;
use caliptra_builder::{build_firmware_elf, FwId, SymbolType};
use elf::endian::AnyEndian;
use elf::ElfBytes;
use std::collections::hash_map::{DefaultHasher, Entry};
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::hash::Hasher;
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};

pub const CPTRA_COVERAGE_PATH: &str = "CPTRA_COVERAGE_PATH";

pub struct CoverageMap {
    pub map: HashMap<u64, BitVec>,
}

impl CoverageMap {
    pub fn new(paths: Vec<PathBuf>) -> Self {
        let mut map = HashMap::<u64, BitVec>::default();
        for path in paths {
            if let Some(new_entry) = get_entry_from_path(&path) {
                match map.entry(new_entry.0) {
                    Entry::Vacant(e) => {
                        e.insert(new_entry.1);
                    }
                    Entry::Occupied(mut e) => {
                        e.get_mut().or(&new_entry.1);
                    }
                }
            }
        }
        Self { map }
    }
}
pub struct CoverageMapEntry(u64, BitVec);
pub fn get_entry_from_path(path: &PathBuf) -> Option<CoverageMapEntry> {
    let filename = path.file_name().and_then(|val| val.to_str());
    if let Some(filename) = filename {
        let prefix = filename
            .split('-')
            .nth(1)
            .and_then(|val| val.strip_suffix(".bitvec"));

        if let Some(prefix) = prefix {
            if let Ok(tag) = prefix.parse() {
                if let Ok(bitmap) = read_bitvec_from_file(path) {
                    return Some(CoverageMapEntry(tag, bitmap));
                }
            }
        }
    }
    None
}

pub fn dump_emu_coverage_to_file(
    coverage_path: &str,
    tag: u64,
    bitmap: &BitVec,
) -> std::io::Result<()> {
    let mut filename = format!("CovData{}", hex::encode(rand::random::<[u8; 16]>()));
    filename.push_str(&'-'.to_string());
    filename.push_str(&tag.to_string());
    filename.push_str(".bitvec");

    let path = std::path::Path::new(coverage_path).join(filename);

    let file = File::create(path)?;
    let mut writer = BufWriter::new(file);
    serde_json::to_writer(&mut writer, &bitmap)?;
    writer.flush()?;
    Ok(())
}

pub fn uncovered_functions<'a>(elf_bytes: &'a [u8], bitmap: &'a BitVec) -> std::io::Result<()> {
    let symbols = caliptra_builder::elf_symbols(elf_bytes)?;

    let filter = symbols
        .iter()
        .filter(|sym| sym.ty == SymbolType::Func)
        .filter(|function| {
            let mut pc_range = function.value..function.value + function.size;
            !pc_range.any(|pc| bitmap.get(pc as usize).unwrap_or(false))
        });

    for f in filter {
        println!(
            "not covered : (NAME:{})  (start:{}) (size:{})",
            f.name, f.value, f.size
        );
    }

    Ok(())
}

pub fn get_bitvec_paths(dir: &str) -> Result<Vec<PathBuf>, Box<dyn std::error::Error>> {
    let paths = std::fs::read_dir(dir)?
        // Filter out all those directory entries which couldn't be read
        .filter_map(|res| res.ok())
        // Map the directory entries to paths
        .map(|dir_entry| dir_entry.path())
        // Filter out all paths with extensions other than `bitvec`
        .filter_map(|path| {
            if path.extension().map_or(false, |ext| ext == "bitvec") {
                Some(path)
            } else {
                None
            }
        })
        .collect::<Vec<_>>();
    Ok(paths)
}

pub fn read_bitvec_from_file<P: AsRef<Path>>(
    path: P,
) -> Result<bit_vec::BitVec, Box<dyn std::error::Error>> {
    // Open the file in read-only mode with buffer.
    let file = File::open(path)?;
    let reader = BufReader::new(file);

    // Read the JSON contents of the file as an instance of `User`.
    let coverage = serde_json::from_reader(reader)?;

    // Return the bitmap
    Ok(coverage)
}

pub fn get_tag_from_image(image: &[u8]) -> u64 {
    let mut hasher = DefaultHasher::new();
    std::hash::Hash::hash_slice(image, &mut hasher);
    hasher.finish()
}

pub fn get_tag_from_fw_id(id: &FwId<'static>) -> Option<u64> {
    if let Ok(rom) = caliptra_builder::build_firmware_rom(id) {
        return Some(get_tag_from_image(&rom));
    }
    None
}

pub fn collect_instr_pcs(id: &FwId<'static>) -> anyhow::Result<Vec<u32>> {
    let elf_bytes = build_firmware_elf(id)?;

    let elf_file = ElfBytes::<AnyEndian>::minimal_parse(&elf_bytes)
        .with_context(|| "Failed to parse elf file")?;

    let (load_addr, text_section) = read_section(&elf_file, ".text", true)?;

    let mut index = 0_usize;

    let mut instr_pcs = Vec::<u32>::new();

    while index < text_section.len() {
        let instruction = &text_section[index..index + 2];
        let instruction = u16::from_le_bytes([instruction[0], instruction[1]]);

        match instruction & 0b11 {
            0 | 1 | 2 => {
                index += 2;
            }
            _ => {
                index += 4;
            }
        }
        instr_pcs.push(load_addr + index as u32);
    }
    Ok(instr_pcs)
}

/// Read a section from ELF file
fn read_section<'a>(
    elf_file: &'a ElfBytes<AnyEndian>,
    name: &str,
    required: bool,
) -> anyhow::Result<(u32, &'a [u8])> {
    let load_addr: u32;
    let section = elf_file
        .section_header_by_name(name)
        .with_context(|| format!("Failed to find {name} section"))?;
    if let Some(section) = section {
        let data = elf_file
            .section_data(&section)
            .with_context(|| format!("Failed to read {name} section"))?
            .0;
        load_addr = section.sh_addr as u32;
        Ok((load_addr, data))
    } else {
        if required {
            anyhow::bail!("{} section not found", name)
        }
        Ok((0, &[]))
    }
}

pub fn parse_trace_file(trace_file_path: &str) -> HashSet<u32> {
    let mut unique_pcs = HashSet::new();

    // Open the trace file
    if let Ok(file) = File::open(trace_file_path) {
        let reader = BufReader::new(file);

        // Iterate through each line in the trace file
        for line in reader.lines() {
            match line {
                Ok(line) => {
                    // Check if the line starts with "pc="
                    if line.starts_with("pc=") {
                        // Extract the PC by splitting the line at '=' and parsing the hexadecimal value
                        if let Some(pc_str) = line.strip_prefix("pc=") {
                            if let Ok(pc) = u32::from_str_radix(pc_str.trim_start_matches("0x"), 16)
                            {
                                unique_pcs.insert(pc);
                            }
                        }
                    }
                }
                Err(_) => println!("Trace is malformed"),
            }
        }
    }

    unique_pcs
}

pub mod calculator {
    use bit_vec::BitVec;

    use super::*;

    pub fn coverage_from_bitmap(coverage: &BitVec, instr_pcs: &[u32]) -> i32 {
        let mut hit = 0;
        for pc in instr_pcs {
            if coverage[*pc as usize] {
                hit += 1;
            }
        }
        hit
    }

    pub fn coverage_from_instr_trace(trace_path: &str, instr_pcs: &[u32]) -> i32 {
        // Count the nunmer of instructions executed
        let unique_executed_pcs = parse_trace_file(trace_path);
        let mut hit = 0;
        for pc in unique_executed_pcs.iter() {
            if instr_pcs.contains(pc) {
                hit += 1;
            }
        }
        hit
    }
}

#[test]
fn test_parse_trace_file() {
    // Create a temporary trace file for testing
    let temp_trace_file = "temp_trace.txt";
    let trace_data = vec![
        "SoC write4 *0x300300bc <- 0x0",
        "SoC write4 *0x30030110 <- 0x2625a00",
        "SoC write4 *0x30030114 <- 0x0",
        "SoC write4 *0x300300b8 <- 0x1",
        "pc=0x0",
        "pc=0x4",
        "pc=0x4",
        "pc=0x4",
        "pc=0x0",
    ];

    // Write the test data to the temporary trace file
    std::fs::write(temp_trace_file, trace_data.join("\n"))
        .expect("Failed to write test trace file");

    // Call the function to parse the test trace file
    let unique_pcs = parse_trace_file(temp_trace_file);

    // Define the expected unique PCs based on the test data
    let expected_pcs: HashSet<u32> = vec![0x0, 0x4].into_iter().collect();

    // Assert that the result matches the expected unique PCs
    assert_eq!(unique_pcs, expected_pcs);

    // Clean up: remove the temporary trace file
    std::fs::remove_file(temp_trace_file).expect("Failed to remove test trace file");
}

#[test]
fn test_coverage_map_creation_no_data_files_found() {
    let tag = 123_u64;

    let paths = Vec::new();

    let cv = CoverageMap::new(paths);
    assert_eq!(None, cv.map.get(&tag));
}

#[test]
fn test_coverage_map_creation_data_files() {
    let tag = 123_u64;

    let bitmap = BitVec::from_elem(1024, false);
    assert!(dump_emu_coverage_to_file("/tmp", tag, &bitmap).is_ok());

    let paths = get_bitvec_paths("/tmp").unwrap();

    let cv = CoverageMap::new(paths);
    assert!(cv.map.get(&tag).is_some());
}
