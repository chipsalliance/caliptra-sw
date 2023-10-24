// Licensed under the Apache-2.0 license

use caliptra_coverage::calculator;
use caliptra_coverage::collect_instr_pcs;
use caliptra_coverage::get_bitvec_paths;
use caliptra_coverage::CoverageMap;

use caliptra_builder::firmware::ROM_WITH_UART;
use caliptra_coverage::get_tag_from_fw_id;

fn main() {
    let paths = get_bitvec_paths("/tmp").unwrap();
    let tag = get_tag_from_fw_id(&ROM_WITH_UART);

    println!("{} coverage files found", paths.len());
    let instr_pcs = collect_instr_pcs(&ROM_WITH_UART).unwrap();
    println!("ROM instruction count = {}", instr_pcs.len());

    let cv = CoverageMap::new(paths);
    let bv = cv
        .map
        .get(&tag)
        .expect("Coverage data  not found for image");

    println!(
        "Coverage for ROM_WITH_UART is {}%",
        (100 * calculator::coverage_from_bitmap(bv, &instr_pcs)) as f32 / instr_pcs.len() as f32
    );
}
