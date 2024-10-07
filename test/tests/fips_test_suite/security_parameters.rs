// Licensed under the Apache-2.0 license
#![allow(dead_code)]

use crate::common;

use caliptra_builder::firmware::ROM_WITH_FIPS_TEST_HOOKS;
use caliptra_common::mailbox_api::*;
use caliptra_drivers::FipsTestHook;
use caliptra_hw_model::{BootParams, DeviceLifecycle, HwModel, InitParams, SecurityState};
use caliptra_image_crypto::OsslCrypto as Crypto;
use caliptra_image_gen::ImageGenerator;
use caliptra_image_types::ImageManifest;
use ureg::{Mmio, MmioMut};

use common::*;
use zerocopy::FromBytes;

// TODO: This may differ per environment (0s vs Fs)
const INACCESSIBLE_READ_VALUE: u32 = 0x0;

fn prove_jtag_inaccessible<T: HwModel>(_hw: &mut T) {
    // TODO: Add generic JTAG functions to FW model so something like what's below can work
    // #[cfg(feature = "fpga_realtime")]
    // assert_eq!(_hw.launch_openocd().unwrap_err(), caliptra_hw_model::OpenOcdError::NotAccessible);
}

fn attempt_csp_fuse_read<T: HwModel>(hw: &mut T) {
    let uds_ptr = hw.soc_ifc().fuse_uds_seed().at(0).ptr;
    let uds_read_val =
        unsafe { caliptra_hw_model::BusMmio::new(hw.axi_bus()).read_volatile(uds_ptr) };

    let field_entropy_ptr = hw.soc_ifc().fuse_field_entropy().at(0).ptr;
    let field_entropy_read_val =
        unsafe { caliptra_hw_model::BusMmio::new(hw.axi_bus()).read_volatile(field_entropy_ptr) };

    // TODO: Add exception for SW emulator (does not model locked registers at the MMIO level)
    assert_eq!(uds_read_val, INACCESSIBLE_READ_VALUE);
    assert_eq!(field_entropy_read_val, INACCESSIBLE_READ_VALUE);
}

fn attempt_psp_fuse_modify<T: HwModel>(hw: &mut T) {
    let owner_pk_hash_read_orig_val = hw.soc_ifc().fuse_key_manifest_pk_hash().at(0).read();

    // TODO: Add exception for SW emulator (write failure panics)
    // Try to write a new value
    let owner_pk_hash_ptr = hw.soc_ifc().fuse_key_manifest_pk_hash().at(0).ptr;
    unsafe {
        caliptra_hw_model::BusMmio::new(hw.axi_bus()).write_volatile(owner_pk_hash_ptr, 0xaaaaaaaa)
    };

    let owner_pk_hash_read_val = hw.soc_ifc().fuse_key_manifest_pk_hash().at(0).read();

    // Make sure the value was unchanged
    assert_eq!(owner_pk_hash_read_orig_val, owner_pk_hash_read_val);
}

fn attempt_keyvault_access<T: HwModel>(hw: &mut T) {
    const KV_KEY_CTRL_ADDR: u32 = 0x1001_8000;
    let kv_key_ctrl_ptr = KV_KEY_CTRL_ADDR as *mut u32;

    // Attempt to read keyvault module from the SoC side
    // This is not visible to the SoC, but shared modules (mailbox, SHA engine, etc.) use a 1:1
    // address mapping between the SoC and Caliptra
    let kv_key_ctrl_val =
        unsafe { caliptra_hw_model::BusMmio::new(hw.axi_bus()).read_volatile(kv_key_ctrl_ptr) };
    assert_eq!(kv_key_ctrl_val, INACCESSIBLE_READ_VALUE);

    // Attempt to write
    unsafe {
        caliptra_hw_model::BusMmio::new(hw.axi_bus()).write_volatile(kv_key_ctrl_ptr, 0xffffffff)
    };

    // Read again
    let kv_key_ctrl_val =
        unsafe { caliptra_hw_model::BusMmio::new(hw.axi_bus()).read_volatile(kv_key_ctrl_ptr) };
    assert_eq!(kv_key_ctrl_val, INACCESSIBLE_READ_VALUE);
}

fn attempt_caliptra_dccm_access<T: HwModel>(hw: &mut T) {
    const DCCM_BASE: u32 = 0x5000_0000;
    let dccm_ptr = DCCM_BASE as *mut u32;

    // Attempt to read DCCM module from the SoC side
    // This is not visible to the SoC, but shared modules (mailbox, SHA engine, etc.) use a 1:1
    // address mapping between the SoC and Caliptra
    let dccm_val = unsafe { caliptra_hw_model::BusMmio::new(hw.axi_bus()).read_volatile(dccm_ptr) };
    assert_eq!(dccm_val, INACCESSIBLE_READ_VALUE);

    // Attempt to write
    unsafe { caliptra_hw_model::BusMmio::new(hw.axi_bus()).write_volatile(dccm_ptr, 0xffffffff) };

    // Read again
    let dccm_val = unsafe { caliptra_hw_model::BusMmio::new(hw.axi_bus()).read_volatile(dccm_ptr) };
    assert_eq!(dccm_val, INACCESSIBLE_READ_VALUE);
}

fn attempt_mbox_access<T: HwModel>(hw: &mut T) {
    // Makes sure we can't read anything from dataout
    let dataout_val = hw.soc_mbox().dataout().read();
    assert_eq!(dataout_val, 0x0);
}

fn attempt_ssp_access<T: HwModel>(hw: &mut T) {
    prove_jtag_inaccessible(hw);

    // TODO: Enable on other environments (not possible on SW emulator)
    #[cfg(feature = "verilator")]
    attempt_csp_fuse_read(hw);

    // TODO: Enable on other environments (not possible on SW emulator)
    #[cfg(feature = "verilator")]
    attempt_psp_fuse_modify(hw);

    // TODO: Enable on other environments (not possible on SW emulator)
    #[cfg(feature = "verilator")]
    attempt_keyvault_access(hw);

    // TODO: Enable on other environments (not possible on SW emulator)
    #[cfg(feature = "verilator")]
    attempt_caliptra_dccm_access(hw);

    // TODO: Enable on other environments (not possible on SW emulator)
    #[cfg(feature = "verilator")]
    attempt_mbox_access(hw);
}

#[test]
pub fn attempt_ssp_access_rom() {
    let fuses = caliptra_hw_model::Fuses {
        //field_entropy
        key_manifest_pk_hash: [0x55555555u32; 12],
        ..Default::default()
    };

    let security_state = *SecurityState::default()
        .set_debug_locked(true)
        .set_device_lifecycle(DeviceLifecycle::Production);

    let mut hw = fips_test_init_to_rom(
        Some(InitParams {
            security_state,
            ..Default::default()
        }),
        Some(BootParams {
            fuses,
            ..Default::default()
        }),
    );

    // Perform all the SSP access attempts
    attempt_ssp_access(&mut hw);
}

#[test]
#[cfg(not(feature = "test_env_immutable_rom"))]
pub fn attempt_ssp_access_fw_load() {
    let rom = caliptra_builder::build_firmware_rom(&ROM_WITH_FIPS_TEST_HOOKS).unwrap();

    let fw_image = fips_fw_image();
    let manifest = ImageManifest::read_from_prefix(&*fw_image).unwrap();

    let gen = ImageGenerator::new(Crypto::default());
    let vendor_pubkey_digest = gen.vendor_pubkey_digest(&manifest.preamble).unwrap();
    let fuses = caliptra_hw_model::Fuses {
        //field_entropy
        key_manifest_pk_hash: vendor_pubkey_digest,
        life_cycle: DeviceLifecycle::Production,
        ..Default::default()
    };

    let security_state = *SecurityState::default()
        .set_debug_locked(true)
        .set_device_lifecycle(DeviceLifecycle::Production);

    let mut hw = fips_test_init_to_rom(
        Some(InitParams {
            rom: &rom,
            security_state,
            ..Default::default()
        }),
        Some(BootParams {
            fuses,
            initial_dbg_manuf_service_reg: (FipsTestHook::HALT_FW_LOAD as u32) << HOOK_CODE_OFFSET,
            ..Default::default()
        }),
    );

    // Start the FW load (don't wait for a result)
    hw.start_mailbox_execute(u32::from(CommandId::FIRMWARE_LOAD), &fw_image)
        .unwrap();

    // Wait for ACK that ROM reached halt point
    hook_wait_for_complete(&mut hw);

    // Perform all the SSP access attempts
    attempt_ssp_access(&mut hw);

    // Tell ROM to continue
    hook_code_write(&mut hw, FipsTestHook::CONTINUE);

    // Wait for ACK that ROM continued
    hook_wait_for_complete(&mut hw);

    // Wait for the FW load to report success
    hw.finish_mailbox_execute().unwrap();
}

#[test]
pub fn attempt_ssp_access_rt() {
    let fw_image = fips_fw_image();
    let manifest = ImageManifest::read_from_prefix(&*fw_image).unwrap();

    let gen = ImageGenerator::new(Crypto::default());
    let vendor_pubkey_digest = gen.vendor_pubkey_digest(&manifest.preamble).unwrap();
    let fuses = caliptra_hw_model::Fuses {
        //field_entropy
        key_manifest_pk_hash: vendor_pubkey_digest,
        life_cycle: DeviceLifecycle::Production,
        ..Default::default()
    };

    let security_state = *SecurityState::default()
        .set_debug_locked(true)
        .set_device_lifecycle(DeviceLifecycle::Production);

    let mut hw = fips_test_init_to_rt(
        Some(InitParams {
            security_state,
            ..Default::default()
        }),
        Some(BootParams {
            fw_image: Some(&fw_image),
            fuses,
            ..Default::default()
        }),
    );

    // Perform all the SSP access attempts
    attempt_ssp_access(&mut hw);
}
