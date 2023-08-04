// Licensed under the Apache-2.0 license
use caliptra_builder::{FwId, ImageOptions, FMC_WITH_UART, ROM_WITH_UART};
use caliptra_common::keyids::{KEY_ID_RT_CDI, KEY_ID_RT_PRIV_KEY};
use caliptra_common::FirmwareHandoffTable;
use caliptra_common::HandOffDataHandle;
use caliptra_common::Vault;
use caliptra_hw_model::{BootParams, HwModel, InitParams};
use zerocopy::{AsBytes, FromBytes};

const RT_ALIAS_DERIVED_CDI_COMPLETE: u32 = 0x400;
const RT_ALIAS_KEY_PAIR_DERIVATION_COMPLETE: u32 = 0x401;
const RT_ALIAS_SUBJ_ID_SN_GENERATION_COMPLETE: u32 = 0x402;
const RT_ALIAS_SUBJ_KEY_ID_GENERATION_COMPLETE: u32 = 0x403;
const RT_ALIAS_CERT_SIG_GENERATION_COMPLETE: u32 = 0x404;
const RT_ALIAS_DERIVATION_COMPLETE: u32 = 0x405;

/// The FMC CDI is stored in a 32-bit DataVault sticky register.
const fn rt_cdi_store() -> HandOffDataHandle {
    HandOffDataHandle(((Vault::KeyVault as u32) << 12) | KEY_ID_RT_CDI as u32)
}

const fn rt_priv_key_store() -> HandOffDataHandle {
    HandOffDataHandle(((Vault::KeyVault as u32) << 12) | KEY_ID_RT_PRIV_KEY as u32)
}

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

#[test]
fn test_fht_update() {
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

    let result = hw.mailbox_execute(0x1000_0003, &[]);
    assert!(result.is_ok());

    let data = result.unwrap().unwrap();
    let fht = FirmwareHandoffTable::read_from_prefix(data.as_bytes()).unwrap();

    assert_eq!(fht.rt_cdi_kv_hdl, rt_cdi_store());
    assert_eq!(fht.rt_priv_key_kv_hdl, rt_priv_key_store());

    // [TODO] Expand test to validate additional FHT fields.
}
