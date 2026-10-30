// Licensed under the Apache-2.0 license

use caliptra_api::SocManager;
use caliptra_builder::firmware;
use caliptra_builder::firmware::rom_tests::{TEST_FMC_INTERACTIVE, TEST_FMC_WITH_UART};
use caliptra_builder::firmware::APP_WITH_UART;
use caliptra_builder::ImageOptions;
use caliptra_common::RomBootStatus::*;
use caliptra_hw_model::BootParams;
use caliptra_hw_model::HwModel;
use caliptra_hw_model::InitParams;
use caliptra_hw_model::TrngMode;
use ureg::MmioMut;

#[test]
#[cfg_attr(any(feature = "verilator", feature = "fpga_realtime"), ignore)]
fn test_cold_reset_external_direct() {
    let rom = caliptra_builder::build_firmware_rom(firmware::rom_from_env()).unwrap();
    let image_bundle = caliptra_builder::build_and_sign_image(
        &TEST_FMC_WITH_UART,
        &APP_WITH_UART,
        ImageOptions::default(),
    )
    .unwrap();
    let image_bytes = image_bundle.to_bytes().unwrap();

    for trng_mode in [TrngMode::Internal, TrngMode::External] {
        for initial_dbg_manuf_service_reg in [0, 0x2] {
            let mut hw = caliptra_hw_model::new_unbooted(InitParams {
                rom: &rom,
                itrng_nibbles: Box::new(std::iter::from_fn(|| panic!("unexpected iTRNG request"))),
                etrng_responses: Box::new(std::iter::from_fn(|| {
                    panic!("unexpected eTRNG request")
                })),
                trng_mode: Some(trng_mode),
                ..Default::default()
            })
            .unwrap();

            // The emulator allows injection of the otherwise read-only generic input wires.
            let generic_input = hw.soc_ifc().cptra_generic_input_wires().at(0).ptr;
            unsafe {
                hw.mmio_mut().write_volatile(generic_input, 1);
            }
            hw.soc_ifc_trng()
                .cptra_trng_data()
                .write(&[0x1234_5678; 12]);
            hw.boot(BootParams {
                initial_dbg_manuf_service_reg,
                ..Default::default()
            })
            .unwrap();

            hw.step_until_boot_status(CfiInitialized.into(), false);
            hw.step_until_boot_status(KatStarted.into(), false);
            hw.step_until_boot_status(KatComplete.into(), false);
            hw.step_until(|m| m.soc_ifc().cptra_flow_status().read().ready_for_fw());
            hw.upload_firmware(&image_bytes).unwrap();
            hw.step_until_boot_status(ColdResetComplete.into(), true);
            hw.step_until_exit_success().unwrap();
            assert_eq!(u32::from(hw.soc_ifc_trng().cptra_trng_status().read()), 0);
        }
    }
}

#[test]
#[cfg_attr(any(feature = "verilator", feature = "fpga_realtime"), ignore)]
fn test_itrng_ro_filter_config() {
    use caliptra_registers::soc_ifc::regs::CptraItrngEntropyConfig1WriteVal;

    let rom = caliptra_builder::build_firmware_rom(firmware::rom_from_env()).unwrap();
    let image_bundle = caliptra_builder::build_and_sign_image(
        &TEST_FMC_INTERACTIVE,
        &APP_WITH_UART,
        ImageOptions::default(),
    )
    .unwrap();
    let image_bytes = image_bundle.to_bytes().unwrap();

    // RSVD bit 0 = 1 (enable), RSVD bits [2:1] = 0b10 (sel=2) → rsvd = 0b101 = 5
    let entropy_config = CptraItrngEntropyConfig1WriteVal::from(0u32).rsvd(5);

    let mut hw = caliptra_hw_model::new(
        InitParams {
            rom: &rom,
            trng_mode: Some(TrngMode::Internal),
            ..Default::default()
        },
        BootParams {
            initial_repcnt_thresh_reg: Some(entropy_config),
            ..Default::default()
        },
    )
    .unwrap();

    hw.step_until(|m| m.soc_ifc().cptra_flow_status().read().ready_for_fw());
    hw.upload_firmware(&image_bytes).unwrap();
    hw.step_until_boot_status(ColdResetComplete.into(), true);

    // Read entropy_src CONF fields back via test FMC mailbox command.
    // Response: bits [3:0] = rng_bit_enable, bits [5:4] = rng_bit_sel.
    let resp = hw.mailbox_execute(0x1000_000F, &[]).unwrap().unwrap();
    let result = u32::from_le_bytes(resp[..4].try_into().unwrap());

    // kMultiBitBool4True = 6 means filter is enabled.
    assert_eq!(result & 0xf, 6, "rng_bit_enable should be TRUE (6)");
    assert_eq!((result >> 4) & 0x3, 2, "rng_bit_sel should be 2");

    hw.mailbox_execute(0x1000_000C, &[]).unwrap();
    hw.step_until_exit_success().unwrap();
}
