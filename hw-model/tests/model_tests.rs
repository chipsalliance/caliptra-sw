// Licensed under the Apache-2.0 license

use caliptra_builder::firmware;
use caliptra_hw_model::{BootParams, DefaultHwModel, HwModel, InitParams};
use caliptra_hw_model_types::ErrorInjectionMode;
use caliptra_test_harness_types as harness;

fn run_fw_elf(elf: &[u8]) -> DefaultHwModel {
    let rom = caliptra_builder::elf2rom(elf).unwrap();
    let model = caliptra_hw_model::new(BootParams {
        init_params: InitParams {
            rom: &rom,
            ..Default::default()
        },
        ..Default::default()
    })
    .unwrap();
    model
}

#[test]
fn test_iccm_byte_write_nmi_failure() {
    let elf = caliptra_builder::build_firmware_elf(&firmware::hw_model_tests::TEST_ICCM_BYTE_WRITE)
        .unwrap();
    let symbols = caliptra_builder::elf_symbols(&elf).unwrap();
    let main_symbol = symbols.iter().find(|s| s.name == "main").unwrap();
    let main_addr = main_symbol.value as u32;

    let mut model = run_fw_elf(&elf);
    model.step_until_exit_success().unwrap_err();

    let soc_ifc: caliptra_registers::soc_ifc::RegisterBlock<_> = model.soc_ifc();
    assert_eq!(
        soc_ifc.cptra_fw_error_non_fatal().read(),
        harness::ERROR_NMI
    );
    let nmi_info = harness::ExtErrorInfo::from(soc_ifc.cptra_fw_extended_error_info().read());

    // Exactly where the PC is when the NMI fires is a bit fuzzy...
    assert!(nmi_info.mepc >= main_addr + 4 && nmi_info.mepc <= main_addr + 24);
    assert_eq!(nmi_info.mcause, harness::NMI_CAUSE_DBUS_STORE_ERROR);
}

#[test]
fn test_iccm_unaligned_write_nmi_failure() {
    let elf =
        caliptra_builder::build_firmware_elf(&firmware::hw_model_tests::TEST_ICCM_UNALIGNED_WRITE)
            .unwrap();
    let symbols = caliptra_builder::elf_symbols(&elf).unwrap();
    let main_symbol = symbols.iter().find(|s| s.name == "main").unwrap();
    let main_addr = main_symbol.value as u32;

    let mut model = run_fw_elf(&elf);
    model.step_until_exit_success().unwrap_err();

    let soc_ifc: caliptra_registers::soc_ifc::RegisterBlock<_> = model.soc_ifc();
    assert_eq!(
        soc_ifc.cptra_fw_error_non_fatal().read(),
        harness::ERROR_NMI
    );
    let ext_info = harness::ExtErrorInfo::from(soc_ifc.cptra_fw_extended_error_info().read());

    // Exactly where the PC is when the NMI fires is a bit fuzzy...
    assert!(ext_info.mepc >= main_addr + 4 && ext_info.mepc <= main_addr + 24);
    assert_eq!(ext_info.mcause, harness::NMI_CAUSE_DBUS_STORE_ERROR);
}

#[test]
fn test_iccm_write_locked_nmi_failure() {
    let elf =
        caliptra_builder::build_firmware_elf(&firmware::hw_model_tests::TEST_ICCM_WRITE_LOCKED)
            .unwrap();

    let mut model = run_fw_elf(&elf);
    model.step_until_exit_success().unwrap_err();
    let soc_ifc: caliptra_registers::soc_ifc::RegisterBlock<_> = model.soc_ifc();
    assert_eq!(
        soc_ifc.cptra_fw_error_non_fatal().read(),
        harness::ERROR_NMI
    );
    let ext_info = harness::ExtErrorInfo::from(soc_ifc.cptra_fw_extended_error_info().read());
    assert_eq!(ext_info.mcause, harness::NMI_CAUSE_DBUS_STORE_ERROR);
}

#[test]
fn test_invalid_instruction_exception_failure() {
    let elf =
        caliptra_builder::build_firmware_elf(&firmware::hw_model_tests::TEST_INVALID_INSTRUCTION)
            .unwrap();

    let mut model = run_fw_elf(&elf);
    model.step_until_exit_success().unwrap_err();
    let soc_ifc: caliptra_registers::soc_ifc::RegisterBlock<_> = model.soc_ifc();
    assert_eq!(
        soc_ifc.cptra_fw_error_non_fatal().read(),
        harness::ERROR_EXCEPTION
    );
    let ext_info = harness::ExtErrorInfo::from(soc_ifc.cptra_fw_extended_error_info().read());
    assert_eq!(
        ext_info.mcause,
        harness::EXCEPTION_CAUSE_ILLEGAL_INSTRUCTION_ERROR
    );
}

#[test]
fn test_write_to_rom() {
    let elf =
        caliptra_builder::build_firmware_elf(&firmware::hw_model_tests::TEST_WRITE_TO_ROM).unwrap();
    let mut model = run_fw_elf(&elf);
    model.step_until_exit_success().unwrap_err();
    let soc_ifc: caliptra_registers::soc_ifc::RegisterBlock<_> = model.soc_ifc();
    assert_eq!(
        soc_ifc.cptra_fw_error_non_fatal().read(),
        harness::ERROR_EXCEPTION
    );
}

#[test]
fn test_iccm_double_bit_ecc_nmi_failure() {
    let elf =
        caliptra_builder::build_firmware_elf(&firmware::hw_model_tests::TEST_ICCM_DOUBLE_BIT_ECC)
            .unwrap();

    let mut model = run_fw_elf(&elf);

    model.ecc_error_injection(ErrorInjectionMode::IccmDoubleBitEcc);

    model.step_until_exit_success().unwrap_err();
    let soc_ifc: caliptra_registers::soc_ifc::RegisterBlock<_> = model.soc_ifc();
    assert_eq!(
        soc_ifc.cptra_fw_error_non_fatal().read(),
        harness::ERROR_EXCEPTION
    );
    let ext_info = harness::ExtErrorInfo::from(soc_ifc.cptra_fw_extended_error_info().read());
    assert_eq!(
        ext_info.mcause,
        harness::EXCEPTION_CAUSE_INSTRUCTION_ACCESS_FAULT
    );
}

#[test]
fn test_dccm_double_bit_ecc_nmi_failure() {
    let elf =
        caliptra_builder::build_firmware_elf(&firmware::hw_model_tests::TEST_DCCM_DOUBLE_BIT_ECC)
            .unwrap();

    let mut model = run_fw_elf(&elf);

    model.ecc_error_injection(ErrorInjectionMode::DccmDoubleBitEcc);

    model.step_until_exit_success().unwrap_err();
    let soc_ifc: caliptra_registers::soc_ifc::RegisterBlock<_> = model.soc_ifc();
    assert_eq!(
        soc_ifc.cptra_fw_error_non_fatal().read(),
        harness::ERROR_EXCEPTION
    );
    let ext_info = harness::ExtErrorInfo::from(soc_ifc.cptra_fw_extended_error_info().read());
    assert_eq!(ext_info.mcause, harness::EXCEPTION_CAUSE_LOAD_ACCESS_FAULT);
}

#[test]
fn test_pcr_extend() {
    let elf =
        caliptra_builder::build_firmware_elf(&firmware::hw_model_tests::TEST_PCR_EXTEND).unwrap();

    let mut model = run_fw_elf(&elf);

    model.step_until_exit_success().unwrap();
}
