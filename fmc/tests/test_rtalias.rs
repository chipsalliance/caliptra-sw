// Licensed under the Apache-2.0 license
use caliptra_builder::{FwId, ImageOptions, FMC_WITH_UART, ROM_WITH_UART};
use caliptra_hw_model::{BootParams, HwModel, InitParams};

const RT_ALIAS_DERIVED_CDI_COMPLETE: u32 = 0x400;
const RT_ALIAS_KEY_PAIR_DERIVATION_COMPLETE: u32 = 0x401;
const RT_ALIAS_SUBJ_ID_SN_GENERATION_COMPLETE: u32 = 0x402;
const RT_ALIAS_SUBJ_KEY_ID_GENERATION_COMPLETE: u32 = 0x403;
const RT_ALIAS_CERT_SIG_GENERATION_COMPLETE: u32 = 0x404;
const RT_ALIAS_DERIVATION_COMPLETE: u32 = 0x405;

#[test]
fn test_boot_status_reporting() {
    let rom = caliptra_builder::build_firmware_rom(&ROM_WITH_UART).unwrap();

    pub const MOCK_RT_WITH_UART: FwId = FwId {
        crate_name: "caliptra-fmc-mock-rt",
        bin_name: "caliptra-fmc-mock-rt",
        features: &["emu"],
        workspace_dir: None,
    };

    let image = caliptra_builder::build_and_sign_image(
        &FMC_WITH_UART,
        &MOCK_RT_WITH_UART,
        ImageOptions::default(),
    )
    .unwrap();

    let mut hw = caliptra_hw_model::new(BootParams {
        init_params: InitParams {
            rom: &rom,
            ..Default::default()
        },
        fw_image: Some(&image.to_bytes().unwrap()),
        ..Default::default()
    })
    .unwrap();

    hw.step_until_boot_status(RT_ALIAS_DERIVED_CDI_COMPLETE, true);
    hw.step_until_boot_status(RT_ALIAS_KEY_PAIR_DERIVATION_COMPLETE, true);
    hw.step_until_boot_status(RT_ALIAS_SUBJ_ID_SN_GENERATION_COMPLETE, true);
    hw.step_until_boot_status(RT_ALIAS_SUBJ_KEY_ID_GENERATION_COMPLETE, true);
    hw.step_until_boot_status(RT_ALIAS_CERT_SIG_GENERATION_COMPLETE, true);
    hw.step_until_boot_status(RT_ALIAS_DERIVATION_COMPLETE, true);

    let mut output = vec![];
    hw.copy_output_until_exit_success(&mut output).unwrap();
}
