/*++

Licensed under the Apache-2.0 license.

File Name:

    dma_tests.rs

Abstract:

    File contains test cases for DMA driver API

--*/

#![no_std]
#![no_main]

use caliptra_drivers::{memory_layout, Dma, Mailbox};
use caliptra_registers::{axi_dma::AxiDmaReg, ecc::EccReg, mbox::MboxCsr};
use caliptra_test_harness::test_suite;
use core::slice;

// We test that reading from a periph into the fifo works by reading ECC name
fn test_dma_read_from_periph() {
    let mut dma = unsafe { Dma::new(AxiDmaReg::new()) };

    let ecc_regs = unsafe { EccReg::new() };
    let ecc_name = ecc_regs.regs().name().ptr();

    let dword = dma.read_dword(ecc_name as usize).unwrap();
    assert_eq!(dword.to_ne_bytes(), [0x70, 0x63, 0x65, 0x73]); // secp
}

// We test that reading from a periph into the fifo works by reading ECC name
fn test_dma_write_to_periph() {
    let mut dma = unsafe { Dma::new(AxiDmaReg::new()) };

    let ecc_regs = unsafe { EccReg::new() };
    let ecc_iv = ecc_regs.regs().iv().at(0).ptr;

    let data: u32 = 0xdead_beef;

    dma.write_dword(ecc_iv as usize, data).unwrap();
    let dword = dma.read_dword(ecc_iv as usize).unwrap();
    assert_eq!(dword, data);
}

fn test_read_rri_to_mailbox() {
    let mut dma = unsafe { Dma::new(AxiDmaReg::new()) };

    let test_image = [0xab; 512];
    let block_size = 256;

    // TODO use i3c generated regs
    let rri_regs = 0x1003_806c;

    // Get mailbox lock
    let mut mbox_driver = unsafe { Mailbox::new(MboxCsr::new()) };
    let mut txn = mbox_driver.try_start_send_txn().unwrap();
    txn.send_request(0xdead_beef, b"").unwrap();

    dma.transfer_payload_to_mbox(rri_regs, test_image.len() as u32, true, block_size)
        .unwrap();

    let mbox_fifo = unsafe {
        slice::from_raw_parts(
            memory_layout::MBOX_ORG as *const u8,
            memory_layout::MBOX_SIZE as usize,
        )
    };
    assert_eq!(mbox_fifo.get(..test_image.len()).unwrap(), test_image);
}

test_suite! {
    test_dma_read_from_periph,
    test_dma_write_to_periph,
    test_read_rri_to_mailbox,
}
