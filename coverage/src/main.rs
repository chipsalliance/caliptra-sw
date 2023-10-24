// Licensed under the Apache-2.0 license

use caliptra_coverage::bitwise_or_bitvecs;
use caliptra_coverage::get_bitvec_paths;
use caliptra_coverage::read_bitvec_from_file;

use caliptra_coverage::{calculator, collect_instr_pcs};

use caliptra_builder::firmware::ROM_WITH_UART;

fn main() {
    let paths = get_bitvec_paths("/tmp").unwrap();

    println!("{} coverage files found", paths.len());
    let mut bvs: Vec<bit_vec::BitVec> = Vec::new();
    let instr_pcs = collect_instr_pcs(&ROM_WITH_UART).unwrap();
    println!("ROM insrtruction count = {}", instr_pcs.len());

    for path in paths {
        let bv = read_bitvec_from_file(&path).unwrap();
        bvs.push(bv);
    }

    let bv = bitwise_or_bitvecs(&bvs);
    println!(
        "ROM coverage : {}%",
        (100 * calculator::coverage_from_bitmap(&bv, &instr_pcs)) as f32 / instr_pcs.len() as f32
    );
}
