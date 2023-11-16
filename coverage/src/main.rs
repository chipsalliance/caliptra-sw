// Licensed under the Apache-2.0 license

use bit_vec::BitVec;
use caliptra_builder::build_firmware_elf;
use caliptra_coverage::calculator;
use caliptra_coverage::collect_instr_pcs;
use caliptra_coverage::get_bitvec_paths;
use caliptra_coverage::CoverageMap;
use caliptra_coverage::CPTRA_COVERAGE_PATH;

use caliptra_builder::firmware::ROM_WITH_UART;
use caliptra_coverage::get_tag_from_fw_id;
use caliptra_coverage::invoke_objdump;
use caliptra_coverage::uncovered_functions;

pub fn highlight_covered_instructions_in_objdump_output(bitmap: &BitVec, output: String) {
    let mut is_disassembly = false;
    let re = regex::Regex::new(r"^\s*(?P<address>[0-9a-f]+):\s*(?P<instruction>[0-9a-f]+\s+.+)")
        .unwrap();

    for line in output.lines() {
        if line.contains("Disassembly of section") {
            is_disassembly = true;
            continue;
        }

        if is_disassembly && re.is_match(line) {
            if let Some(captures) = re.captures(line) {
                let pc = usize::from_str_radix(&captures["address"], 16).unwrap();
                if bitmap.get(pc).unwrap_or(false) {
                    let s = format!("[*]{}", line);
                    println!("{s}");
                } else {
                    println!("   {}", line);
                }
            }
        } else {
            println!("   {}", line);
        }
    }
}

fn main() -> std::io::Result<()> {
    let cov_path = std::env::var(CPTRA_COVERAGE_PATH).unwrap_or_else(|_| "".into());
    if cov_path.is_empty() {
        return Ok(());
    }

    let paths = get_bitvec_paths(cov_path.as_str()).unwrap();
    if paths.is_empty() {
        println!("{} coverage files found", paths.len());
        return Ok(());
    }

    let tag = get_tag_from_fw_id(&ROM_WITH_UART).unwrap();

    println!("{} coverage files found", paths.len());
    let instr_pcs = collect_instr_pcs(&ROM_WITH_UART).unwrap();
    println!("ROM instruction count = {}", instr_pcs.len());

    let cv = CoverageMap::new(paths);
    let bv = cv
        .map
        .get(&tag)
        .expect("Coverage data  not found for image");

    let elf_bytes = build_firmware_elf(&ROM_WITH_UART)?;

    uncovered_functions(&elf_bytes, bv)?;

    println!(
        "Coverage for ROM_WITH_UART is {}%",
        (100 * calculator::coverage_from_bitmap(bv, &instr_pcs)) as f32 / instr_pcs.len() as f32
    );

    if let Some(fw_dir) = std::env::var_os("CALIPTRA_PREBUILT_FW_DIR") {
        let path = std::path::PathBuf::from(fw_dir).join(ROM_WITH_UART.elf_filename());

        let objdump_output = invoke_objdump(&path.to_string_lossy());
        highlight_covered_instructions_in_objdump_output(bv, objdump_output.unwrap());
    } else {
        println!("Prebuilt firmware not found");
    }
    Ok(())
}
