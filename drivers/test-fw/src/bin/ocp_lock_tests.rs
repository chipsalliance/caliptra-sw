/*++

Licensed under the Apache-2.0 license.

File Name:

    ocp_lock.rs

Abstract:

    File contains test cases for OCP LOCK.

--*/

#![no_std]
#![no_main]

use core::fmt::Write;

use caliptra_cfi_lib::CfiCounter;
use caliptra_drivers::{
    cprintln, hmac_kdf, Aes, AesKey, Array4x16, AxiAddr, Dma, DmaReadTarget, DmaReadTransaction, Hmac, HmacData, HmacKey, HmacMode, HmacTag, KeyId, KeyReadArgs, KeyUsage, KeyWriteArgs, SocIfc, Trng, Uart
};
use caliptra_kat::CaliptraResult;
use caliptra_registers::{
    aes::AesReg, aes_clp::AesClpReg, csrng::CsrngReg, entropy_src::EntropySrcReg, hmac::HmacReg, soc_ifc::SocIfcReg, soc_ifc_trng::SocIfcTrngReg
};
use caliptra_test_harness::test_suite;

test_suite! {
    test_ocp_lock_enabled,
    test_hek_seed,
    test_populate_mdk,
    // Modified behavior of subsequent tests.
    // Tests before should test "ROM" flows, afterwards they should test "Runtime" flows.
     test_set_ocp_lock_in_progress,
     test_dma,
}

fn test_ocp_lock_enabled() {
    cprintln!("\n\n\n\n =============HELLO HELLO================= \n\n\n\n");
    let soc_ifc = unsafe { SocIfcReg::new() };
    let mut soc_ifc = SocIfc::new(soc_ifc);
    assert!(soc_ifc.ocp_lock_enabled());
}

fn test_set_ocp_lock_in_progress() {
    cprintln!("Testing ocp lock in progress");
    let soc_ifc = unsafe { SocIfcReg::new() };
    let mut soc_ifc = SocIfc::new(soc_ifc);
    soc_ifc.ocp_lock_set_lock_in_progress();
    assert!(soc_ifc.ocp_lock_get_lock_in_progress());
    cprintln!("Testing ocp lock in progress passed");
}

fn test_hek_seed() {
    cprintln!("Testing hek seed");
    let soc_ifc = unsafe { SocIfcReg::new() };
    let mut soc_ifc = SocIfc::new(soc_ifc);

    let fuse_bank = soc_ifc.fuse_bank().ocp_heck_seed();
    // Check hard coded hek seed from test MCU ROM.
    assert_eq!(fuse_bank, [0xABDEu32; 8].into());
    cprintln!("Testing hek passed");
}

fn test_populate_mdk() {
    CfiCounter::reset(&mut || Ok((0xdeadbeef, 0xdeadbeef, 0xdeadbeef, 0xdeadbeef)));
    cprintln!("starting test_populate_mdk");

    let soc_ifc = unsafe { SocIfcReg::new() };
    let mut soc_ifc = SocIfc::new(soc_ifc);
    let mut hmac = unsafe { Hmac::new(HmacReg::new()) };
    let mut trng = unsafe {
        Trng::new(
            CsrngReg::new(),
            EntropySrcReg::new(),
            SocIfcTrngReg::new(),
            &SocIfcReg::new(),
        )
        .unwrap()
    };

    let cdi_slot = HmacKey::Key(KeyReadArgs::new(KeyId::KeyId3));
    populate_slot(&mut hmac, &mut trng, KeyId::KeyId3).unwrap();
    cprintln!("CDI populated");

    let mdk_slot = HmacTag::Key(KeyWriteArgs::from(KeyWriteArgs::new(
        KeyId::KeyId16,
        KeyUsage::default().set_aes_key_en(),
    )));
    cprintln!("Starting KDF");
    hmac_kdf(
        &mut hmac,
        cdi_slot,
        b"OCP_LOCK_MDK",
        None,
        &mut trng,
        mdk_slot,
        HmacMode::Hmac512,
    )
    .unwrap();
    cprintln!("test_populate_mdk passed");
}

fn test_locked_hmac_unlocked() {
    CfiCounter::reset(&mut || Ok((0xdeadbeef, 0xdeadbeef, 0xdeadbeef, 0xdeadbeef)));

    let soc_ifc = unsafe { SocIfcReg::new() };
    let mut soc_ifc = SocIfc::new(soc_ifc);
    let mut hmac = unsafe { Hmac::new(HmacReg::new()) };
    let mut trng = unsafe {
        Trng::new(
            CsrngReg::new(),
            EntropySrcReg::new(),
            SocIfcTrngReg::new(),
            &SocIfcReg::new(),
        )
        .unwrap()
    };

    populate_slot(&mut hmac, &mut trng, KeyId::KeyId6).unwrap();
    // Hmac from Regular KV to OCP LOCK KV should be unlocked.
    assert!(hmac_helper(KeyId::KeyId6, KeyId::KeyId17, &mut hmac, &mut trng).is_ok());
}

fn test_locked_hmac_locked() {
    CfiCounter::reset(&mut || Ok((0xdeadbeef, 0xdeadbeef, 0xdeadbeef, 0xdeadbeef)));

    let soc_ifc = unsafe { SocIfcReg::new() };
    let mut soc_ifc = SocIfc::new(soc_ifc);
    let mut hmac = unsafe { Hmac::new(HmacReg::new()) };
    let mut trng = unsafe {
        Trng::new(
            CsrngReg::new(),
            EntropySrcReg::new(),
            SocIfcTrngReg::new(),
            &SocIfcReg::new(),
        )
        .unwrap()
    };

    populate_slot(&mut hmac, &mut trng, KeyId::KeyId6).unwrap();
    // Hmac from Regular KV to OCP LOCK KV should be locked.
    assert!(hmac_helper(KeyId::KeyId6, KeyId::KeyId17, &mut hmac, &mut trng).is_err());
}

fn populate_slot(hmac: &mut Hmac, trng: &mut Trng, slot: KeyId) -> CaliptraResult<()> {
    hmac.hmac(
        HmacKey::Array4x16(&Array4x16::default()),
        HmacData::from(&[0]),
        trng,
        KeyWriteArgs::new(slot, KeyUsage::default().set_aes_key_en()).into(),
        HmacMode::Hmac512,
    )
}

fn hmac_helper(
    input: KeyId,
    output: KeyId,
    hmac: &mut Hmac,
    trng: &mut Trng,
) -> CaliptraResult<()> {
    hmac.hmac(
        HmacKey::Key(KeyReadArgs::new(input)),
        HmacData::from(&[0]),
        trng,
        KeyWriteArgs::new(output, KeyUsage::default().set_aes_key_en()).into(),
        HmacMode::Hmac512,
    )
}

fn zeroize_axi(dma: &mut Dma, addr: u64, len: usize) {
    for i in (0..len).step_by(4) {
        dma.write_dword((addr + i as u64).into(), 0);
    }
}

fn test_dma() {
    const MCU_SRAM_OFFSET: u64 = 0xc0_0000;
    const MCU_SRAM_SIZE: usize = 32 * 1024;

    cprintln!("Hello world");
    CfiCounter::reset(&mut || Ok((0xdeadbeef, 0xdeadbeef, 0xdeadbeef, 0xdeadbeef)));
    let mut dma = Dma::default();
    let soc = unsafe { SocIfc::new(SocIfcReg::new()) };
    let mut aes = unsafe { Aes::new(AesReg::new(), AesClpReg::new()) };

    let soc_ifc = unsafe { SocIfcReg::new() };
    let mut soc_ifc = SocIfc::new(soc_ifc);

    // Read and decrypt 0s from MCU SRAM to MCU SRAM
    let mcu_base_addr = soc.mci_base_addr() + MCU_SRAM_OFFSET;

    let zeroize_mcu_sram = |dma: &mut Dma| {
        zeroize_axi(dma, mcu_base_addr, MCU_SRAM_SIZE);
    };

    let src = soc.mci_base_addr() + 0xc0_0000;
    let dst = soc.mci_base_addr() + 0xc0_0000;

    zeroize_mcu_sram(&mut dma);

    let data = dma.read_dword(AxiAddr::from(src));
    if data != 0 {
        cprintln!("Have data");
    } else {
        cprintln!("No data");
    }

    cprintln!("Decrypting into KV");
    aes.aes_256_ecb_decrypt_kv(AesKey::KV(KeyReadArgs::new(KeyId::KeyId16)), &[0; 64]).unwrap();
    cprintln!("Done Decrypting into KV");

    let data = dma.read_dword(AxiAddr::from(src));
    if data != 0 {
        cprintln!("Have data");
    } else {
        cprintln!("No data");
    }

    // let mut input = [0u32; 4];
    // cprintln!("Staring read");
    // dma.setup_dma_read(
    //     DmaReadTransaction {
    //         read_addr: src.into(),
    //         fixed_addr: false,
    //         length: 4 as u32,
    //         target: DmaReadTarget::AxiWr(dst.into(), false),
    //         aes_mode: false,
    //         aes_gcm: false,
    //     },
    //     0,
    // );
    // cprintln!("complete");
    // cprintln!("reading fifo");
    // dma.dma_read_fifo(&mut input[..4]);
    // cprintln!("done reading fifo");
    // dma.wait_for_dma_complete();
    // cprintln!("done waiting");
    // dma.flush();
    // cprintln!("flushed");
    //
    // if input != [0u32; 4] {
    //     cprintln!("Input is zeroized");
    // } else {
    //     cprintln!("Input is not zeroized");
    // }
}
