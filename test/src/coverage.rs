// Licensed under the Apache-2.0 license

use anyhow::Context;
use caliptra_builder::{build_firmware_elf, FwId};
use elf::endian::AnyEndian;
use elf::ElfBytes;
use std::collections::HashSet;
use std::fs::File;
use std::io::{BufRead, BufReader};

pub fn collect_instr_pcs(id: &FwId<'static>) -> anyhow::Result<Vec<u32>> {
    let elf_bytes = build_firmware_elf(id).unwrap();

    let elf_file = ElfBytes::<AnyEndian>::minimal_parse(&elf_bytes)
        .with_context(|| "Failed to parse elf file")?;

    let (load_addr, text_section) = read_section(&elf_file, ".text", true).unwrap();

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

#[cfg(all(not(feature = "verilator"), not(feature = "fpga_realtime")))]
pub mod calculator {
    use super::*;

    pub fn coverage_from_bitmap(hw: &caliptra_hw_model::ModelEmulated, instr_pcs: &[u32]) -> i32 {
        let coverage = hw.code_coverage_bitmap();

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
