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

use caliptra_drivers::{
    hmac_kdf, Array4x16, Hmac, HmacData, HmacKey, HmacMode, HmacTag, KeyId, KeyReadArgs, KeyUsage,
    KeyWriteArgs, SocIfc, Trng, Uart,
};
use caliptra_kat::CaliptraResult;
use caliptra_registers::{
    csrng::CsrngReg, entropy_src::EntropySrcReg, hmac::HmacReg, soc_ifc::SocIfcReg,
    soc_ifc_trng::SocIfcTrngReg,
};
use caliptra_test_harness::test_suite;

fn test_ocp_lock_enabled() {
    let soc_ifc = unsafe { SocIfcReg::new() };
    let mut soc_ifc = SocIfc::new(soc_ifc);
    assert!(soc_ifc.ocp_lock_enabled());
}

fn test_populate_mdk() {
    let soc_ifc = unsafe { SocIfcReg::new() };
    let mut soc_ifc = SocIfc::new(soc_ifc);
    assert!(soc_ifc.ocp_lock_enabled());

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

    Uart::new().write_str("Populated CDI Slot").unwrap();

    let mdk_slot = HmacTag::Key(KeyWriteArgs::from(KeyWriteArgs::new(
        KeyId::KeyId16,
        KeyUsage::default().set_aes_key_en(),
    )));
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
    Uart::new().write_str("Populated MDK Slot").unwrap();
}

test_suite! {
    test_ocp_lock_enabled,
    test_populate_mdk,
}

fn populate_slot(hmac: &mut Hmac, trng: &mut Trng, slot: KeyId) -> CaliptraResult<()> {
    hmac.hmac(
        HmacKey::Array4x16(&Array4x16::default()),
        HmacData::from(&[0]),
        trng,
        KeyWriteArgs::new(slot, KeyUsage::default().set_hmac_key_en().set_aes_key_en()).into(),
        HmacMode::Hmac512,
    )
}
