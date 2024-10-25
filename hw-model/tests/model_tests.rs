// Licensed under the Apache-2.0 license

use caliptra_api::SocManager;
use caliptra_builder::firmware;
use caliptra_hw_model::{BootParams, DefaultHwModel, HwModel, InitParams};
use caliptra_hw_model_types::ErrorInjectionMode;
use caliptra_test_harness_types as harness;

fn run_fw_elf(elf: &[u8]) -> DefaultHwModel {
    let rom = caliptra_builder::elf2rom(elf).unwrap();
    let model = caliptra_hw_model::new(
        InitParams {
            rom: &rom,
            random_sram_puf: false,
            ..Default::default()
        },
        BootParams::default(),
    )
    .unwrap();
    model
}

fn run_fw_elf_with_rand_puf(elf: &[u8]) -> DefaultHwModel {
    let rom = caliptra_builder::elf2rom(elf).unwrap();
    let model = caliptra_hw_model::new(
        InitParams {
            rom: &rom,
            ..Default::default()
        },
        BootParams::default(),
    )
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
    // FPGA realtime model doesn't support ecc error injection
    #![cfg_attr(feature = "fpga_realtime", ignore)]

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
    // FPGA realtime model doesn't support ecc error injection
    #![cfg_attr(feature = "fpga_realtime", ignore)]

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
fn test_uninitialized_dccm_read() {
    #![cfg_attr(not(feature = "verilator"), ignore)]

    let mut model = run_fw_elf_with_rand_puf(
        &caliptra_builder::build_firmware_elf(&firmware::hw_model_tests::TEST_UNITIALIZED_READ)
            .unwrap(),
    );

    const DCCM_ADDR: u32 = 0x5000_0000;
    const DCCM_SIZE: u32 = 128 * 1024;

    model.soc_ifc().cptra_rsvd_reg().at(0).write(|_| DCCM_ADDR);
    model.soc_ifc().cptra_rsvd_reg().at(1).write(|_| DCCM_SIZE);

    model.step_until_exit_failure().unwrap();

    let ext_info =
        harness::ExtErrorInfo::from(model.soc_ifc().cptra_fw_extended_error_info().read());
    assert_eq!(ext_info.mcause, harness::EXCEPTION_CAUSE_LOAD_ACCESS_FAULT);
    assert_eq!(
        ext_info.mscause,
        harness::MCAUSE_LOAD_ACCESS_FAULT_MSCAUSE_DCCM_DOUBLE_BIT_ECC
    );
    assert!(model.soc_ifc().cptra_hw_error_fatal().read().dccm_ecc_unc());
}

#[test]
fn test_uninitialized_iccm_read() {
    #![cfg_attr(not(feature = "verilator"), ignore)]

    let mut model = run_fw_elf_with_rand_puf(
        &caliptra_builder::build_firmware_elf(&firmware::hw_model_tests::TEST_UNITIALIZED_READ)
            .unwrap(),
    );

    const ICCM_ADDR: u32 = 0x4000_0000;
    const ICCM_SIZE: u32 = 128 * 1024;

    model.soc_ifc().cptra_rsvd_reg().at(0).write(|_| ICCM_ADDR);
    model.soc_ifc().cptra_rsvd_reg().at(1).write(|_| ICCM_SIZE);

    model.step_until_exit_failure().unwrap();

    let ext_info =
        harness::ExtErrorInfo::from(model.soc_ifc().cptra_fw_extended_error_info().read());
    assert_eq!(
        ext_info.mcause,
        harness::NMI_CAUSE_DBUS_NON_BLOCKING_LOAD_ERROR
    );
    assert_eq!(ext_info.mscause, 0);
}

#[test]
fn test_uninitialized_mbox_read() {
    #![cfg_attr(not(feature = "verilator"), ignore)]

    let mut model = run_fw_elf_with_rand_puf(
        &caliptra_builder::build_firmware_elf(&firmware::hw_model_tests::TEST_UNITIALIZED_READ)
            .unwrap(),
    );

    #[cfg(feature = "verilator")]
    model.corrupt_mailbox_ecc_double_bit();

    const MBOX_ADDR: u32 = 0x3000_0000;

    model.soc_ifc().cptra_rsvd_reg().at(0).write(|_| MBOX_ADDR);
    model.soc_ifc().cptra_rsvd_reg().at(1).write(|_| 1024);

    assert!(!model
        .soc_ifc()
        .cptra_hw_error_non_fatal()
        .read()
        .mbox_ecc_unc());
    // NOTE: CPU execution will continue after the ECC error
    model.step_until_exit_success().unwrap();
    assert!(model
        .soc_ifc()
        .cptra_hw_error_non_fatal()
        .read()
        .mbox_ecc_unc());
}

#[test]
fn test_pcr_extend() {
    let elf =
        caliptra_builder::build_firmware_elf(&firmware::hw_model_tests::TEST_PCR_EXTEND).unwrap();

    let mut model = run_fw_elf(&elf);

    model.step_until_exit_success().unwrap();
}
