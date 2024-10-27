// Licensed under the Apache-2.0 license
#[cfg(all(not(feature = "verilator"), not(feature = "fpga_realtime")))]
#[test]
fn test_emu_coverage() {
    use std::path::PathBuf;

    use caliptra_api::SocManager;
    use caliptra_builder::firmware;
    use caliptra_coverage::{calculator, collect_instr_pcs};
    use caliptra_emu_cpu::CoverageBitmaps;
    use caliptra_hw_model::HwModel;
    use caliptra_hw_model::{BootParams, InitParams};

    const TRACE_PATH: &str = "/tmp/caliptra_coverage_trace.txt";

    let instr_pcs = collect_instr_pcs(firmware::rom_from_env()).unwrap();

    let coverage_from_bitmap = {
        let rom = caliptra_builder::build_firmware_rom(firmware::rom_from_env()).unwrap();
        let mut hw = caliptra_hw_model::new(
            InitParams {
                rom: &rom,
                trace_path: Some(PathBuf::from(TRACE_PATH)),
                ..Default::default()
            },
            BootParams {
                ..Default::default()
            },
        )
        .unwrap();
        // Upload FW
        hw.step_until(|m| m.soc_ifc().cptra_flow_status().read().ready_for_fw());
        let CoverageBitmaps { rom, iccm: _iccm } = hw.code_coverage_bitmap();
        calculator::coverage_from_bitmap(0, rom, &instr_pcs)
    };

    println!(
        "Test coverage using different methods {} , {}",
        coverage_from_bitmap,
        calculator::coverage_from_instr_trace(TRACE_PATH, &instr_pcs)
    );
    assert_eq!(
        coverage_from_bitmap,
        calculator::coverage_from_instr_trace(TRACE_PATH, &instr_pcs)
    );
}
