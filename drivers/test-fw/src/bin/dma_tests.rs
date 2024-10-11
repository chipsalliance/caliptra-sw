/*++

Licensed under the Apache-2.0 license.

File Name:

    dma_tests.rs

Abstract:

    File contains test cases for DMA driver API

--*/

#![no_std]
#![no_main]

use caliptra_drivers::{
    cprintln, Dma, DmaReadTarget, DmaReadTransaction, DmaWriteOrigin, DmaWriteTransaction,
};
use caliptra_registers::{axi_dma::AxiDmaReg, ecc::EccReg, mbox::MboxCsr};
use caliptra_test_harness::test_suite;

fn test_dma_read_sram_to_fifo() {
    let mut dma = unsafe { Dma::new(AxiDmaReg::new()) };

    dma.flush();

    let data: u32 = 0xdead_beef;
    let data_ptr: *const u32 = &data;
    let read_transaction = DmaReadTransaction {
        read_addr: data_ptr as usize,
        fixed_addr: false,
        length: 4,
        target: DmaReadTarget::AhbFifo,
    };

    dma.setup_dma_read(read_transaction);
    dma.do_transaction();

    let mut fifo_data = [0u8; 4];
    dma.dma_read_fifo(&mut fifo_data).unwrap();
    assert_eq!(fifo_data, data.to_ne_bytes());
}

// We test that reading from a periph into the fifo works by reading ECC name
fn test_dma_read_from_periph() {
    let mut dma = unsafe { Dma::new(AxiDmaReg::new()) };

    let ecc_regs = unsafe { EccReg::new() };
    let ecc_name = ecc_regs.regs().name().ptr();

    dma.flush();
    let read_to_fifo = DmaReadTransaction {
        read_addr: ecc_name as usize,
        fixed_addr: false,
        length: 4,
        target: DmaReadTarget::AhbFifo,
    };

    dma.setup_dma_read(read_to_fifo);
    dma.do_transaction();

    let mut fifo_data = [0u8; 4];
    dma.dma_read_fifo(&mut fifo_data).unwrap();
    assert_eq!(fifo_data, [0x70, 0x63, 0x65, 0x73]); // secp
}

// We test that reading from a periph into the fifo works by reading ECC name
fn test_dma_write_to_periph() {
    let mut dma = unsafe { Dma::new(AxiDmaReg::new()) };

    let ecc_regs = unsafe { EccReg::new() };
    let ecc_iv = ecc_regs.regs().iv().at(0).ptr;

    let data: u32 = 0xdead_beef;

    dma.flush();
    let write_from_fifo = DmaWriteTransaction {
        write_addr: ecc_iv as usize,
        fixed_addr: false,
        length: 4,
        origin: DmaWriteOrigin::AhbFifo,
    };

    dma.setup_dma_write(write_from_fifo);
    dma.dma_write_fifo(&data.to_le_bytes()).unwrap();
    dma.do_transaction();

    dma.flush();

    let read_to_fifo = DmaReadTransaction {
        read_addr: ecc_iv as usize,
        fixed_addr: false,
        length: 4,
        target: DmaReadTarget::AhbFifo,
    };

    dma.setup_dma_read(read_to_fifo);
    dma.do_transaction();

    let mut fifo_data = [0u8; 4];
    dma.dma_read_fifo(&mut fifo_data).unwrap();
    assert_eq!(fifo_data, data.to_le_bytes());
}

fn test_read_rri_to_mailbox() {
    let mut dma = unsafe { Dma::new(AxiDmaReg::new()) };

    // TODO use i3c generated regs
    let rri_regs = 0x1003_806c;

    dma.flush();
    // TODO this needs a block size set
    let read_rri_to_mailbox = DmaReadTransaction {
        read_addr: rri_regs,
        fixed_addr: true,
        length: 256,
        target: DmaReadTarget::Mbox,
    };

    dma.setup_dma_read(read_rri_to_mailbox);
    dma.do_transaction();

    let mbox = unsafe { MboxCsr::new() };
    let dlen = mbox.regs().dlen().read();

    // TODO set up
    // assert_eq!(dlen, 256);
}

test_suite! {
    test_dma_read_sram_to_fifo,
    test_dma_read_from_periph,
    test_dma_write_to_periph,
    test_read_rri_to_mailbox,
}
