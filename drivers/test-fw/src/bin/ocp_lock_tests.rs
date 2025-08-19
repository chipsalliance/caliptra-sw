/*++

Licensed under the Apache-2.0 license.

File Name:

    ocp_lock.rs

Abstract:

    File contains test cases for OCP LOCK.

--*/

#![no_std]
#![no_main]

use caliptra_drivers::{
    hmac_kdf, Array4x16, Hmac, HmacData, HmacKey, HmacMode, HmacTag, KeyId, KeyReadArgs, KeyUsage,
    KeyWriteArgs, SocIfc, Trng,
};
use caliptra_kat::CaliptraResult;
use caliptra_registers::{
    csrng::CsrngReg, entropy_src::EntropySrcReg, hmac::HmacReg, soc_ifc::SocIfcReg,
    soc_ifc_trng::SocIfcTrngReg,
};
use caliptra_test_harness::test_suite;

fn test_hw_supports_ocp_lock() {
    let soc_ifc = unsafe { SocIfcReg::new() };
    assert!(SocIfc::new(soc_ifc).ocp_lock_enabled());
}

fn test_populate_mdk() {
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

    let cdi_slot = HmacKey::Key(KeyReadArgs::new(KeyId::KeyId6));
    populate_slot(&mut hmac, &mut trng, KeyId::KeyId6).unwrap();
    let mdk_slot = HmacTag::Key(KeyWriteArgs::from(KeyWriteArgs::new(
        KeyId::KeyId16,
        KeyUsage::default().set_hmac_key_en().set_aes_key_en(),
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
}

test_suite! {
    // Can only run one test at a time.
    // test_hw_supports_ocp_lock,
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
