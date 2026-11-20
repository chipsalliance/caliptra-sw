// Licensed under the Apache-2.0 license

#![no_std]
#![no_main]

use caliptra_drivers::dma::BlockMode;
use caliptra_drivers::{AxiAddr, Dma, DmaReadTarget, DmaReadTransaction, SocIfc};
use caliptra_registers::soc_ifc::SocIfcReg;
use caliptra_test_harness::test_suite;

fn test_checked_words_recover_from_busy_error() {
    let dma = Dma::default();
    let soc_ifc = SocIfc::new(unsafe { SocIfcReg::new() });
    // This address is the emulator's AXI test register.
    let test_addr = AxiAddr::from(0xaa00_u64);
    dma.write_dword(test_addr, 0x1234_5678);

    let enter_busy_error = || {
        // An unmapped AXI read leaves DMA BUSY in its error state.
        dma.setup_dma_read(DmaReadTransaction {
            read_addr: AxiAddr::from(u64::MAX - 3),
            fixed_addr: false,
            length: 4,
            target: DmaReadTarget::AhbFifo,
            aes_mode: false,
            aes_gcm: false,
            block_mode: BlockMode::Other,
        });
        dma.with_dma(|regs| {
            for _ in 0..1000 {
                let status = regs.status0().read();
                if status.error() {
                    assert!(status.busy());
                    return;
                }
            }
            panic!("DMA did not enter the expected busy-error state");
        });
    };

    enter_busy_error();
    assert_eq!(dma.read_dword_checked(test_addr, &soc_ifc), Ok(0x1234_5678));

    enter_busy_error();
    dma.write_dword_checked(test_addr, 0x8765_4321, &soc_ifc)
        .unwrap();
    assert_eq!(dma.read_dword_checked(test_addr, &soc_ifc), Ok(0x8765_4321));
}

test_suite! {
    test_checked_words_recover_from_busy_error,
}
