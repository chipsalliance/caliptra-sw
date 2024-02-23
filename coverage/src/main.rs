// Licensed under the Apache-2.0 license

use bit_vec::BitVec;
use caliptra_builder::build_firmware_elf;
use caliptra_builder::firmware::APP_WITH_UART;
use caliptra_builder::firmware::FMC_WITH_UART;
use caliptra_coverage::calculator;
use caliptra_coverage::collect_instr_pcs;
use caliptra_coverage::get_bitvec_paths;
use caliptra_coverage::CoverageMap;
use caliptra_coverage::CPTRA_COVERAGE_PATH;

use caliptra_builder::firmware::ROM_WITH_UART;
use caliptra_coverage::get_tag_from_fw_id;
use caliptra_coverage::invoke_objdump;
use caliptra_coverage::uncovered_functions;
use caliptra_drivers::memory_layout::ICCM_ORG;
use caliptra_drivers::memory_layout::ROM_ORG;
use caliptra_image_types::IMAGE_MANIFEST_BYTE_SIZE;

pub fn highlight_covered_instructions_in_objdump_output(
    base_address: usize,
    bitmap: &BitVec,
    output: String,
) {
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
                if bitmap.get(pc - base_address).unwrap_or(false) {
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

    uncovered_functions(ROM_ORG as usize, &elf_bytes, bv)?;

    println!(
        "Coverage for ROM_WITH_UART is {}%",
        (100 * calculator::coverage_from_bitmap(ROM_ORG as usize, bv, &instr_pcs)) as f32
            / instr_pcs.len() as f32
    );

    if let Some(fw_dir) = std::env::var_os("CALIPTRA_PREBUILT_FW_DIR") {
        let path = std::path::PathBuf::from(fw_dir).join(ROM_WITH_UART.elf_filename());

        let objdump_output = invoke_objdump(&path.to_string_lossy());
        highlight_covered_instructions_in_objdump_output(
            caliptra_drivers::memory_layout::ROM_ORG as usize,
            bv,
            objdump_output.unwrap(),
        );
    } else {
        println!("Prebuilt firmware not found");
    }

    let iccm_image_tag = {
        let image = caliptra_builder::build_and_sign_image(
            &FMC_WITH_UART,
            &APP_WITH_UART,
            caliptra_builder::ImageOptions {
                app_version: caliptra_builder::version::get_runtime_version(),
                ..Default::default()
            },
        )
        .unwrap();

        let image = image.to_bytes().unwrap();
        let iccm_image = &image.as_slice()[IMAGE_MANIFEST_BYTE_SIZE..];

        caliptra_coverage::get_tag_from_image(iccm_image)
    };
    let iccm_bitmap = cv
        .map
        .get(&iccm_image_tag)
        .expect("Coverage data not found for ICCM image");

    let iccm_images = vec![&FMC_WITH_UART, &APP_WITH_UART];

    for e in iccm_images {
        println!("////////////////////////////////////");
        println!("Coverage report for {}", e.bin_name);
        println!("////////////////////////////////////");
        let instr_pcs = collect_instr_pcs(e).unwrap();
        println!("{} instruction count = {}", e.bin_name, instr_pcs.len());
        println!(
            "Coverage % is {}%",
            (100 * calculator::coverage_from_bitmap(ICCM_ORG as usize, iccm_bitmap, &instr_pcs))
                as f32
                / instr_pcs.len() as f32
        );

        let elf_bytes = build_firmware_elf(e)?;
        uncovered_functions(ICCM_ORG as usize, &elf_bytes, iccm_bitmap)?;

        if let Some(fw_dir) = std::env::var_os("CALIPTRA_PREBUILT_FW_DIR") {
            let path = std::path::PathBuf::from(fw_dir).join(e.elf_filename());

            let objdump_output = invoke_objdump(&path.to_string_lossy());
            highlight_covered_instructions_in_objdump_output(
                ICCM_ORG as usize,
                iccm_bitmap,
                objdump_output.unwrap(),
            );
        } else {
            println!("Prebuilt firmware not found");
        }
    }

    Ok(())
}
