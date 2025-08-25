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
    cprintln, dma::MCU_SRAM_OFFSET, hmac_kdf, Aes, AesKey, Array4x16, AxiAddr, Dma, DmaReadTarget,
    DmaReadTransaction, DmaWriteOrigin, DmaWriteTransaction, Hmac, HmacData, HmacKey, HmacMode,
    HmacTag, KeyId, KeyReadArgs, KeyUsage, KeyWriteArgs, SocIfc, Trng, Uart,
};
use caliptra_kat::CaliptraResult;
use caliptra_registers::{
    aes::AesReg, aes_clp::AesClpReg, csrng::CsrngReg, entropy_src::EntropySrcReg, hmac::HmacReg,
    soc_ifc::SocIfcReg, soc_ifc_trng::SocIfcTrngReg,
};
use caliptra_test_harness::test_suite;

use itertools::Itertools;

// TODO: Use a common definition for this.
const MCU_SRAM_SIZE: usize = 32 * 1024;
const REGULAR_LOCK_KV_RANGE: core::ops::Range<u8> = core::ops::Range { start: 0, end: 16 };
const OCP_LOCK_KV_RANGE: core::ops::Range<u8> = core::ops::Range { start: 16, end: 23 };

test_suite! {
    test_ocp_lock_enabled,
    test_hek_seed,
    test_populate_mdk,
    test_hmac_regular_kv_to_ocp_lock_kv_unlocked,
    // Modifies behavior of subsequent tests.
    // Tests before should test "ROM" flows, afterwards they should test "Runtime" flows.
    test_set_ocp_lock_in_progress,
    test_hmac_regular_kv_to_ocp_lock_kv_locked,
    test_hmac_ocp_lock_kv_to_ocp_lock_kv_unlocked,
    test_decrypt_to_mek_kv,
    test_kv_release,
}

fn test_ocp_lock_enabled() {
    let test_regs = TestRegisters::new();
    assert!(test_regs.soc.ocp_lock_enabled());
}

fn test_set_ocp_lock_in_progress() {
    let mut test_regs = TestRegisters::new();
    test_regs.soc.ocp_lock_set_lock_in_progress();
    assert!(test_regs.soc.ocp_lock_get_lock_in_progress());
}

fn test_hek_seed() {
    let test_regs = TestRegisters::new();
    let fuse_bank = test_regs.soc.fuse_bank().ocp_heck_seed();
    // Check hard coded hek seed from test MCU ROM.
    assert_eq!(fuse_bank, [0xABDEu32; 8].into());
}

fn test_populate_mdk() {
    CfiCounter::reset(&mut || Ok((0xdeadbeef, 0xdeadbeef, 0xdeadbeef, 0xdeadbeef)));
    let mut test_regs = TestRegisters::new();

    let cdi_slot = HmacKey::Key(KeyReadArgs::new(KeyId::KeyId3));
    let mdk_slot = HmacTag::Key(KeyWriteArgs::from(KeyWriteArgs::new(
        KeyId::KeyId16,
        KeyUsage::default().set_aes_key_en(),
    )));

    populate_slot(&mut test_regs.hmac, &mut test_regs.trng, KeyId::KeyId3).unwrap();
    hmac_kdf(
        &mut test_regs.hmac,
        cdi_slot,
        b"OCP_LOCK_MDK", // TODO: Use real label from spec.
        None,
        &mut test_regs.trng,
        mdk_slot,
        HmacMode::Hmac512,
    )
    .unwrap();
}

// Before `ocp_lock_set_lock_in_progress` it's okay to HMAC from regular KV to OCP LOCK KV.
fn test_hmac_regular_kv_to_ocp_lock_kv_unlocked() {
    CfiCounter::reset(&mut || Ok((0xdeadbeef, 0xdeadbeef, 0xdeadbeef, 0xdeadbeef)));
    let mut test_regs = TestRegisters::new();
    cprintln!("test_hmac_regular_kv_to_ocp_lock_kv_unlocked");

    hmac_kv_sequence_check(REGULAR_LOCK_KV_RANGE, OCP_LOCK_KV_RANGE, |res| {
        assert!(res.is_ok())
    });
    cprintln!("test_hmac_regular_kv_to_ocp_lock_kv_unlocked done");
}

// After `ocp_lock_set_lock_in_progress` it's not okay to HMAC from regular KV to OCP LOCK KV.
fn test_hmac_regular_kv_to_ocp_lock_kv_locked() {
    cprintln!("test_hmac_regular_kv_to_ocp_lock_kv_locked");
    CfiCounter::reset(&mut || Ok((0xdeadbeef, 0xdeadbeef, 0xdeadbeef, 0xdeadbeef)));
    let mut test_regs = TestRegisters::new();

    hmac_kv_sequence_check(REGULAR_LOCK_KV_RANGE, OCP_LOCK_KV_RANGE, |res| {
        assert!(res.is_err())
    });
}

fn test_hmac_ocp_lock_kv_to_ocp_lock_kv_unlocked() {
    CfiCounter::reset(&mut || Ok((0xdeadbeef, 0xdeadbeef, 0xdeadbeef, 0xdeadbeef)));
    let mut test_regs = TestRegisters::new();

    populate_slot(&mut test_regs.hmac, &mut test_regs.trng, KeyId::KeyId16).unwrap();
    assert!(hmac_helper(
        KeyId::KeyId16,
        KeyId::KeyId17,
        &mut test_regs.hmac,
        &mut test_regs.trng
    )
    .is_ok());
}

// Checks if MEK can be decrypted to KV.
// NOTE: Must be run after `test_populate_mdk`.
fn test_decrypt_to_mek_kv() {
    CfiCounter::reset(&mut || Ok((0xdeadbeef, 0xdeadbeef, 0xdeadbeef, 0xdeadbeef)));
    let mut test_regs = TestRegisters::new();

    test_regs
        .aes
        .aes_256_ecb_decrypt_kv(AesKey::KV(KeyReadArgs::new(KeyId::KeyId16)), &[0; 64])
        .unwrap();
}

fn test_kv_release() {
    CfiCounter::reset(&mut || Ok((0xdeadbeef, 0xdeadbeef, 0xdeadbeef, 0xdeadbeef)));
    let mut test_regs = TestRegisters::new();

    let mcu_sram_base_addr = test_regs.soc.mci_base_addr() + MCU_SRAM_OFFSET;
    // Zeroize MCU SRAM before test
    zeroize_axi(&mut test_regs.dma, mcu_sram_base_addr, MCU_SRAM_SIZE);

    let fuse_addr = test_regs.soc.ocp_lock_get_key_release_addr();
    let kv_release_size = test_regs.soc.ocp_lock_get_key_size();

    // We expect the MCU TEST ROM to point the OCP LOCK key release to the start of MCU SRAM.
    assert_eq!(mcu_sram_base_addr, fuse_addr);

    // We expect the MCU TEST ROM to set the OCP LOCK key release size to 0x40.
    assert_eq!(0x40, kv_release_size);

    let write_addr = AxiAddr::from(fuse_addr);
    let write_transaction = DmaWriteTransaction {
        write_addr,
        fixed_addr: false,
        length: kv_release_size,
        origin: DmaWriteOrigin::KeyVault,
        aes_mode: false,
        aes_gcm: false,
    };
    test_regs.dma.setup_dma_write(write_transaction, 0);
    test_regs.dma.wait_for_dma_complete();

    let data = test_regs.dma.read_dword(AxiAddr::from(fuse_addr));

    assert_ne!(0, data);
}

fn hmac_kv_sequence_check<T: Iterator<Item = u8>>(
    input_ids: T,
    output_key_ids: T,
    check_result: impl Fn(CaliptraResult<()>) -> (),
) {
    CfiCounter::reset(&mut || Ok((0xdeadbeef, 0xdeadbeef, 0xdeadbeef, 0xdeadbeef)));
    let mut test_regs = TestRegisters::new();

    for (reg_kv, ocp_kv) in REGULAR_LOCK_KV_RANGE
        .into_iter()
        .cartesian_product(OCP_LOCK_KV_RANGE)
    {
        cprintln!("Testing {} and {}", reg_kv, ocp_kv);
        let reg = KeyId::try_from(reg_kv).unwrap();
        let ocp = KeyId::try_from(ocp_kv).unwrap();
        populate_slot(&mut test_regs.hmac, &mut test_regs.trng, reg).unwrap();
        assert!(hmac_helper(
            reg,
            ocp,
            &mut test_regs.hmac,
            &mut test_regs.trng
        )
        .is_ok());
    }
}

fn populate_slot(hmac: &mut Hmac, trng: &mut Trng, slot: KeyId) -> CaliptraResult<()> {
    hmac.hmac(
        HmacKey::Array4x16(&Array4x16::default()),
        HmacData::from(&[0]),
        trng,
        KeyWriteArgs::new(slot, KeyUsage::default().set_hmac_key_en()).into(),
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

struct TestRegisters {
    soc: SocIfc,
    hmac: Hmac,
    aes: Aes,
    trng: Trng,
    dma: Dma,
}

impl TestRegisters {
    fn new() -> Self {
        let soc_ifc = unsafe { SocIfcReg::new() };
        let soc = SocIfc::new(soc_ifc);
        let hmac = unsafe { Hmac::new(HmacReg::new()) };
        let aes = unsafe { Aes::new(AesReg::new(), AesClpReg::new()) };
        let trng = unsafe {
            Trng::new(
                CsrngReg::new(),
                EntropySrcReg::new(),
                SocIfcTrngReg::new(),
                &SocIfcReg::new(),
            )
            .unwrap()
        };
        let dma = Dma::default();

        Self {
            soc,
            hmac,
            aes,
            trng,
            dma,
        }
    }
}
