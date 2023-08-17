/*++

Licensed under the Apache-2.0 license.

File Name:

    keyvault_tests.rs

Abstract:

    File contains test cases for booting runtime firmware

--*/

#![no_std]
#![no_main]

use caliptra_common::keyids::{KEY_ID_RT_CDI, KEY_ID_RT_PRIV_KEY};
use caliptra_drivers::{hmac384_kdf, Hmac384, KeyReadArgs, KeyUsage, KeyVault, KeyWriteArgs, Trng};
use caliptra_registers::{
    csrng::CsrngReg, entropy_src::EntropySrcReg, hmac::HmacReg, kv::KvReg, soc_ifc::SocIfcReg,
    soc_ifc_trng::SocIfcTrngReg,
};
use caliptra_test_harness::{runtime_handlers, test_suite};

fn test_derive_ecc_key_from_cdi_in_erased_kv_slot() {
    let mut vault = unsafe { KeyVault::new(KvReg::new()) };
    let mut hmac384 = unsafe { Hmac384::new(HmacReg::new()) };
    let mut trng = unsafe {
        Trng::new(
            CsrngReg::new(),
            EntropySrcReg::new(),
            SocIfcTrngReg::new(),
            &SocIfcReg::new(),
        )
        .unwrap()
    };
    vault.erase_key(KEY_ID_RT_CDI).unwrap();
    hmac384_kdf(
        &mut hmac384,
        KeyReadArgs::new(KEY_ID_RT_CDI).into(),
        b"dice_keygen",
        None,
        &mut trng,
        KeyWriteArgs::new(
            KEY_ID_RT_PRIV_KEY,
            KeyUsage::default()
                .set_hmac_key_en()
                .set_ecc_key_gen_seed_en(),
        )
        .into(),
    )
    .unwrap();
}

test_suite! {
    test_derive_ecc_key_from_cdi_in_erased_kv_slot,
}
