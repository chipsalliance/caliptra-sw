/*++

Licensed under the Apache-2.0 license.

File Name:

    dma_sha384_tests.rs

Abstract:

    File contains test cases for DMA SHA384 operations

--*/

#![no_std]
#![no_main]

use caliptra_cfi_lib::CfiCounter;
use caliptra_drivers::{
    Array4x16, AxiAddr, Dma, DmaRecovery, Sha2_512_384, Sha2_512_384Acc, ShaAccLockState, SocIfc,
};
use caliptra_registers::sha512::Sha512Reg;
use caliptra_registers::sha512_acc::Sha512AccCsr;
use caliptra_registers::soc_ifc::SocIfcReg;
use caliptra_test_harness::test_suite;

const TEST_DATA_SIZE: usize = 1024; // 1KB of test data
const MCU_SRAM_OFFSET: u64 = 0xc0_0000;

fn test_dma_sha384_mcu_sram() {
    // Init CFI
    CfiCounter::reset(&mut || Ok((0xdeadbeef, 0xdeadbeef, 0xdeadbeef, 0xdeadbeef)));

    let dma = Dma::default();
    {
        let mut digest = Array4x16::default();
        let mut sha_acc = unsafe { Sha2_512_384Acc::new(Sha512AccCsr::new()) };
        let mut op = sha_acc
            .try_start_operation(ShaAccLockState::AssumedLocked)
            .unwrap()
            .unwrap();
        op.digest_512(0, 0, false, &mut digest).unwrap();
    }
    let mut sha_acc = unsafe { Sha2_512_384Acc::new(Sha512AccCsr::new()) };
    let mut sha2_512_384 = unsafe { Sha2_512_384::new(Sha512Reg::new()) };

    let soc_ifc = SocIfc::new(unsafe { SocIfcReg::new() });

    // Generate test data - using a simple pattern for reproducibility
    let mut test_data = [0u32; TEST_DATA_SIZE / 4];
    for (i, word) in test_data.iter_mut().enumerate() {
        *word = (i as u32).wrapping_mul(0x12345678).wrapping_add(0xdeadbeef);
    }

    // Get MCI base address from SocIfc and use DMA to write test data to MCU SRAM
    let mci_base = soc_ifc.mci_base_addr();
    let mcu_sram_addr = AxiAddr::from(mci_base + MCU_SRAM_OFFSET);
    for (i, &word) in test_data.iter().enumerate() {
        let offset = (i * 4) as u64;
        dma.write_dword(mcu_sram_addr + offset, word);
    }

    // Create DMA recovery instance for accessing sha384_mcu_sram
    let caliptra_base = AxiAddr::from(soc_ifc.caliptra_base_axi_addr());
    let recovery_base = AxiAddr::from(soc_ifc.recovery_interface_base_addr());
    let dma_recovery =
        DmaRecovery::new(recovery_base, caliptra_base, AxiAddr::from(mci_base), &dma);

    // Compute SHA384 using DMA's sha384_mcu_sram function
    let dma_digest = dma_recovery
        .sha384_mcu_sram(&mut sha_acc, TEST_DATA_SIZE as u32)
        .expect("DMA SHA384 failed");

    let test_data_bytes =
        unsafe { core::slice::from_raw_parts(test_data.as_ptr() as *const u8, TEST_DATA_SIZE) };

    let regular_digest = sha2_512_384
        .sha384_digest(test_data_bytes)
        .expect("Regular SHA384 failed");

    // Compare the results
    assert_eq!(
        dma_digest, regular_digest,
        "DMA SHA384 result should match regular SHA384 result"
    );
}

fn test_dma_sha384_empty_data() {
    let dma = Dma::default();
    let mut sha_acc = unsafe { Sha2_512_384Acc::new(Sha512AccCsr::new()) };
    let mut sha2_512_384 = unsafe { Sha2_512_384::new(Sha512Reg::new()) };
    let soc_ifc = SocIfc::new(unsafe { SocIfcReg::new() });

    // Test with empty data (0 length)
    let caliptra_base = AxiAddr::from(soc_ifc.caliptra_base_axi_addr());
    let recovery_base = AxiAddr::from(soc_ifc.recovery_interface_base_addr());
    let mci_base = soc_ifc.mci_base_addr();
    let dma_recovery =
        DmaRecovery::new(recovery_base, caliptra_base, AxiAddr::from(mci_base), &dma);

    // Compute SHA384 using DMA's sha384_mcu_sram function with 0 length
    let dma_digest = dma_recovery
        .sha384_mcu_sram(&mut sha_acc, 0)
        .expect("DMA SHA384 with empty data failed");

    // Compute SHA384 using regular SHA384 driver on empty data
    let empty_data: &[u8] = &[];
    let regular_digest = sha2_512_384
        .sha384_digest(empty_data)
        .expect("Regular SHA384 with empty data failed");

    // Compare the results
    assert_eq!(
        dma_digest, regular_digest,
        "DMA SHA384 result for empty data should match regular SHA384 result"
    );
}

fn test_dma_sha384_small_data() {
    let dma = Dma::default();
    let mut sha_acc = unsafe { Sha2_512_384Acc::new(Sha512AccCsr::new()) };
    let mut sha2_512_384 = unsafe { Sha2_512_384::new(Sha512Reg::new()) };
    let soc_ifc = SocIfc::new(unsafe { SocIfcReg::new() });

    // Test with small amount of data (32 bytes)
    const SMALL_DATA_SIZE: usize = 32;
    let mut test_data = [0u32; SMALL_DATA_SIZE / 4];
    for (i, word) in test_data.iter_mut().enumerate() {
        *word = (i as u32 + 1) * 0x11111111;
    }

    // Get MCI base address from SocIfc and use DMA to write test data to MCU SRAM
    let mci_base = soc_ifc.mci_base_addr();
    let mcu_sram_addr = AxiAddr::from(mci_base + MCU_SRAM_OFFSET);
    for (i, &word) in test_data.iter().enumerate() {
        let offset = (i * 4) as u64;
        dma.write_dword(mcu_sram_addr + offset, word);
    }

    let caliptra_base = AxiAddr::from(soc_ifc.caliptra_base_axi_addr());
    let recovery_base = AxiAddr::from(soc_ifc.recovery_interface_base_addr());
    let dma_recovery =
        DmaRecovery::new(recovery_base, caliptra_base, AxiAddr::from(mci_base), &dma);

    // Compute SHA384 using DMA's sha384_mcu_sram function
    let dma_digest = dma_recovery
        .sha384_mcu_sram(&mut sha_acc, SMALL_DATA_SIZE as u32)
        .expect("DMA SHA384 failed");

    // Compute SHA384 using regular SHA384 driver on the same data
    let test_data_bytes =
        unsafe { core::slice::from_raw_parts(test_data.as_ptr() as *const u8, SMALL_DATA_SIZE) };
    let regular_digest = sha2_512_384
        .sha384_digest(test_data_bytes)
        .expect("Regular SHA384 failed");

    // Compare the results
    assert_eq!(
        dma_digest, regular_digest,
        "DMA SHA384 result should match regular SHA384 result for small data"
    );
}

test_suite! {
    test_dma_sha384_mcu_sram,
    test_dma_sha384_empty_data,
    test_dma_sha384_small_data,
}
