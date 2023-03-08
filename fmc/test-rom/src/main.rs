/*++

Licensed under the Apache-2.0 license.

File Name:

    main.rs

Abstract:

    File contains entry point for bare-metal RISCV program

--*/

#![no_std]
#![no_main]

use caliptra_lib::Mailbox;
use caliptra_registers::soc_ifc;
use core::arch::{asm, global_asm};
use core::ptr;

#[macro_use]
mod printer;
use ufmt;

global_asm!(include_str!("start.S"));

/// Firmware Load Command Opcode
const FW_LOAD_CMD_OPCODE: u32 = 0x4657_4C44;

pub fn download_firmware() {
    let soc_ifc = soc_ifc::RegisterBlock::soc_ifc_reg();
    soc_ifc.cptra_flow_status().modify(|w| w.ready_for_fw(true));
    let mut firmware_buffer: [u8; 1024] = [0_u8; 1024];

    loop {
        if let Ok(mut txn) = Mailbox::try_start_recv_txn() {
            match txn.cmd() {
                FW_LOAD_CMD_OPCODE => {
                    let iccm_base_address = 0x40000000_u32;
                    txn.recv_request(&mut firmware_buffer[..]).unwrap();
                    uformatln!("Retrieved F/W from mailbox");
                    let src_ptr = firmware_buffer.as_ptr();
                    let dst_ptr = iccm_base_address as *mut u8;
                    unsafe {
                        ptr::copy_nonoverlapping(src_ptr, dst_ptr, firmware_buffer.len());
                        asm!("li ra, 0x40000000", "ret");
                    }
                }
                _ => assert!(false),
            }
            break;
        }
    }
}

#[no_mangle]
pub extern "C" fn main() {
    uformatln!("Testing FMC");
    download_firmware();
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
