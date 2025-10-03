// Licensed under the Apache-2.0 license

//! A very simple program that responds to the mailbox.

#![no_main]
#![no_std]

// Needed to bring in startup code
#[allow(unused)]
use caliptra_test_harness;

use caliptra_drivers::{Dma, DmaMmio, SocIfc};
use caliptra_registers::{self, soc_ifc::SocIfcReg};
use caliptra_test_harness::println;
use ureg::{Mmio, MmioMut};

const MCI_TOP_REG_RESET_REASON_OFFSET: u32 = 0x38;
const MCI_TOP_REG_RESET_STATUS_OFFSET: u32 = 0x3c;
const MCI_TOP_REG_MCU_SRAM_OFFSET: u32 = 0xc00000;

const FW_HITLESS_UPD_RESET: u32 = 0b1 << 0;

#[panic_handler]
pub fn panic(_info: &core::panic::PanicInfo) -> ! {
    caliptra_drivers::ExitCtrl::exit(1)
}

fn write_mcu_word(mmio: &DmaMmio, offset: u32, value: u32) {
    unsafe {
        mmio.write_volatile(offset as *mut u32, value);
    }
}

fn read_mcu_word(mmio: &DmaMmio, offset: u32) -> u32 {
    unsafe { mmio.read_volatile(offset as *const u32) }
}

fn write_mcu_sram_word(mmio: &DmaMmio, value: u32) {
    write_mcu_word(mmio, MCI_TOP_REG_MCU_SRAM_OFFSET, value)
}

#[no_mangle]
extern "C" fn main() {
    println!("[cptra] Hello from mcu_hitless_udpate_flow");
    let mut soc_ifc = SocIfc::new(unsafe { SocIfcReg::new() });
    let dma = Dma::default();
    let mmio = &DmaMmio::new(soc_ifc.mci_base_addr().into(), &dma);

    // Set known pattern in MCU SRAM
    write_mcu_sram_word(mmio, u32::from_be_bytes(*b"BFOR"));

    // Allow MCU to access SRAM
    soc_ifc.set_mcu_firmware_ready();

    soc_ifc.flow_status_set_ready_for_mb_processing();

    println!("[cptra] Waiting for MCU to acknowledge firmware");
    while read_mcu_word(mmio, MCI_TOP_REG_MCU_SRAM_OFFSET) != u32::from_be_bytes(*b"CONT") {}
    println!("[cptra] Sending \"Hitless Update\"");

    // Clear FW_EXEC_CTRL to notify MCU it has an update available
    soc_ifc.set_ss_generic_fw_exec_ctrl(&[0; 4]);

    // Wait for MCU reset status to be set
    while read_mcu_word(mmio, MCI_TOP_REG_RESET_STATUS_OFFSET) & 0b1 << 1 == 0 {}

    // Set new known pattern in MCU SRAM
    write_mcu_sram_word(mmio, u32::from_be_bytes(*b"AFTR"));

    // Set reset reason to hitless update
    write_mcu_word(mmio, MCI_TOP_REG_RESET_REASON_OFFSET, FW_HITLESS_UPD_RESET);

    // Notify MCU that hitless update is ready. Also releases MCU from reset in this case.
    soc_ifc.set_mcu_firmware_ready();

    println!("[cptra] Released MCU SRAM to MCU");
    loop {}
}
