// Licensed under the Apache-2.0 license

use caliptra_builder::build_firmware_elf;
use caliptra_coverage::calculator;
use caliptra_coverage::collect_instr_pcs;
use caliptra_coverage::get_bitvec_paths;
use caliptra_coverage::CoverageMap;
use caliptra_coverage::CPTRA_COVERAGE_PATH;

use caliptra_builder::firmware::ROM_WITH_UART;
use caliptra_coverage::get_tag_from_fw_id;
use caliptra_coverage::uncovered_functions;

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

    let tag = get_tag_from_fw_id(&ROM_WITH_UART);

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
    Ok(())
}
