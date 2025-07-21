/*++

Licensed under the Apache-2.0 license.

File Name:

    ocp_lock.rs

Abstract:

    File contains the implementation of the ROM OCP LOCK flow.
--*/

#[cfg(not(feature = "no-cfi"))]
use caliptra_cfi_derive::cfi_impl_fn;
use caliptra_common::{
    cprintln,
    keyids::{
        ocp_lock::{KEY_ID_EPK, KEY_ID_HEK, KEY_ID_MDK, KEY_ID_MEK},
        KEY_ID_ROM_FMC_CDI, KEY_ID_STABLE_IDEV,
    },
};
use caliptra_drivers::{
    hmac_kdf, Aes, AesKey, Array4x16, Array4x8, CaliptraError, CaliptraResult, FuseBank, Hmac,
    HmacData, HmacKey, HmacMode, HmacTag, KeyId, KeyReadArgs, KeyUsage, KeyWriteArgs, SocIfc, Trng,
};

pub struct OcpLockFlow {}

impl OcpLockFlow {
    #[inline(never)]
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    /// Performs the ROM OCP LOCK flow.
    /// TODO(clundin): implement.
    pub fn run(
        soc: &mut SocIfc,
        hmac: &mut Hmac,
        trng: &mut Trng,
        aes: &mut Aes,
    ) -> CaliptraResult<()> {
        cprintln!("[ROM] Starting OCP LOCK Flow");
        if !supports_ocp_lock(soc) {
            return Err(CaliptraError::ROM_OCP_LOCK_HARDWARE_UNSUPPORTED)?;
        }

        // TODO(clundin): Move validation tests into separate binary.
        // Run validation flow to confirm that OCP LOCK works as we expect.
        validation_flow(soc, hmac, trng, aes)?;
        Ok(())
    }
}

/// Checks if ROM supports OCP LOCK.
///
/// ROM needs to be compiled with `ocp-lock` feature and the hardware needs to support OCP
/// LOCK.
///
/// # Arguments
/// * `soc_ifc` - SOC Interface
///
/// # Returns true if OCP lock is supported.
fn supports_ocp_lock(soc_ifc: &SocIfc) -> bool {
    #[cfg(feature = "ocp-lock")]
    {
        if soc_ifc.ocp_lock_enabled() {
            cprintln!("[ROM] OCP LOCK supported in hardware and enabled in ROM");
            return true;
        }
    }

    cprintln!("[ROM] OCP LOCK Disabled");
    false
}

/// Exercises key OCP LOCK HW features.
/// TODO(clundin): We should move this validation into a test binary.
fn validation_flow(
    soc: &mut SocIfc,
    hmac: &mut Hmac,
    trng: &mut Trng,
    aes: &mut Aes,
) -> CaliptraResult<()> {
    cprintln!("[ROM] Starting OCP LOCK Validation");

    if rom_validation_flow(soc, hmac, trng, aes).is_ok() {
        cprintln!("[ROM] ROM OCP LOCK FLOW PASSED");
    } else {
        cprintln!("[ROM] ROM OCP LOCK FLOW FAILED");
    }
    cprintln!("[ROM] LOCKING OCP LOCK");
    soc.ocp_lock_set_lock_in_progress();

    if runtime_validation_flow(hmac, trng).is_ok() {
        cprintln!("[ROM] RUNTIME OCP LOCK FLOW PASSED");
    } else {
        cprintln!("[ROM] RUNTIME OCP LOCK FLOW FAILED");
    }
    Ok(())
}

/// Exercises ROM specific OCP LOCK flows.
fn rom_validation_flow(
    soc: &mut SocIfc,
    hmac: &mut Hmac,
    trng: &mut Trng,
    aes: &mut Aes,
) -> CaliptraResult<()> {
    let fuse_bank = soc.fuse_bank();
    check_hek_seed(&fuse_bank)?;
    check_populate_mdk(hmac, trng)?;
    check_populate_mek_with_aes(aes)?;
    check_populate_mek_with_hmac(hmac, trng)?;

    let hek_seed: [u8; 32] = fuse_bank.ocp_heck_seed().into();
    check_hek(hmac, trng, &hek_seed)?;

    Ok(())
}

/// Exercises Runtime specific OCP LOCK flows.
fn runtime_validation_flow(hmac: &mut Hmac, trng: &mut Trng) -> CaliptraResult<()> {
    check_locked_hmac(hmac, trng)?;
    check_locked_hek(hmac, trng)?;
    check_hmac_ocp_kv_to_ocp_kv_lock_mode(hmac, trng)?;
    check_hmac_regular_kv_to_ocp_kv_lock_mode(hmac, trng)?;
    Ok(())
}

/// Checks that the HEK seed fuse is set.
/// TODO(clundin): Set the fuses in MCU to confirm everything is hooked up.
fn check_hek_seed(fuse_bank: &FuseBank) -> CaliptraResult<()> {
    cprintln!("[ROM] OCP LOCK: Checking HEK seed");
    let hek_seed = fuse_bank.ocp_heck_seed();

    if hek_seed == Array4x8::default() {
        cprintln!("[ROM] HEK seed is zeroized");
    } else {
        cprintln!("[ROM] HEK seed is not zeroized");
    }

    cprintln!("[ROM] OCP LOCK: Checking HEK seed PASSED");
    Ok(())
}

fn check_populate_mdk(hmac: &mut Hmac, trng: &mut Trng) -> CaliptraResult<()> {
    cprintln!("[ROM] OCP LOCK: Checking check_populate_mdk");
    //TODO(clundin): Double check `KEY_ID_ROM_FMC_CDI` == IDEV ID CDI.
    let cdi_slot = HmacKey::Key(KeyReadArgs::new(KEY_ID_ROM_FMC_CDI));
    let mdk_slot = HmacTag::Key(
        KeyWriteArgs::new(
            KEY_ID_MDK,
            KeyUsage::default().set_hmac_key_en().set_aes_key_en(),
        )
        .into(),
    );
    hmac_kdf(
        hmac,
        cdi_slot,
        b"OCP_LOCK_MDK",
        None,
        trng,
        mdk_slot,
        HmacMode::Hmac512,
    )?;
    cprintln!("[ROM] OCP LOCK: check_populate_mdk PASSED");
    Ok(())
}

// Check that we can populate MEK slot with AES ECB Decryption.
fn check_populate_mek_with_aes(aes: &mut Aes) -> CaliptraResult<()> {
    cprintln!("[ROM] check_populate_mek_with_aes");
    aes.aes_256_ecb_decrypt_kv(AesKey::KV(KeyReadArgs::new(KEY_ID_MDK)), &[0; 64])?;
    cprintln!("[ROM] check_populate_mek_with_aes PASSED");
    Ok(())
}

// Check that we can populate MEK slot with HMAC.
fn check_populate_mek_with_hmac(hmac: &mut Hmac, trng: &mut Trng) -> CaliptraResult<()> {
    cprintln!("[ROM] check_populate_mek_with_hmac");
    // Using the EPK slot. Any OCP LOCK slot will work.
    populate_slot(hmac, trng, KEY_ID_EPK)?;

    hmac.hmac(
        HmacKey::Key(KeyReadArgs::new(KEY_ID_EPK)),
        HmacData::from(&[0]),
        trng,
        KeyWriteArgs::new(
            KEY_ID_MEK,
            KeyUsage::default().set_hmac_key_en().set_aes_key_en(),
        )
        .into(),
        HmacMode::Hmac512,
    )?;

    cprintln!("[ROM] check_populate_mek_with_hmac PASSED");
    Ok(())
}

/// We should no longer be able to write from a non-KV to a LOCK KV.
fn check_locked_hmac(hmac: &mut Hmac, trng: &mut Trng) -> CaliptraResult<()> {
    cprintln!("[ROM] check_locked_hmac");

    // It should no longer be possible to perform an HMAC for non-OCP KV => OCP KV.
    // Assumes `KEY_ID_ROM_FMC_CDI` has been populated.
    let res = hmac.hmac(
        HmacKey::Key(KeyReadArgs::new(KEY_ID_ROM_FMC_CDI)),
        HmacData::from(&[0]),
        trng,
        KeyWriteArgs::new(
            KEY_ID_EPK,
            KeyUsage::default().set_hmac_key_en().set_aes_key_en(),
        )
        .into(),
        HmacMode::Hmac512,
    );

    match res {
        Ok(_) => {
            cprintln!("[ROM] check_locked_hmac FAILED")
        }
        Err(e) => {
            cprintln!("[ROM] Result is: 0x{:x}", u32::from(e));
            cprintln!("[ROM] check_locked_hmac PASSED");
        }
    }
    // TODO: We want these checks to fail.
    Ok(())
}

/// We should still be able to write from a HEK to a LOCK KV.
fn check_locked_hek(hmac: &mut Hmac, trng: &mut Trng) -> CaliptraResult<()> {
    cprintln!("[ROM] check_locked_hek");

    // Assumes `KEY_ID_HEK` has been populated.
    hmac.hmac(
        HmacKey::Key(KeyReadArgs::new(KEY_ID_HEK)),
        HmacData::from(&[0]),
        trng,
        KeyWriteArgs::new(
            KEY_ID_EPK,
            KeyUsage::default().set_hmac_key_en().set_aes_key_en(),
        )
        .into(),
        HmacMode::Hmac512,
    )?;

    cprintln!("[ROM] check_locked_hek PASSED");
    Ok(())
}

fn check_hek(hmac: &mut Hmac, trng: &mut Trng, hek_seed: &[u8]) -> CaliptraResult<()> {
    cprintln!("[ROM] check_populate_hek");

    let hek_slot = HmacTag::Key(
        KeyWriteArgs::new(
            KEY_ID_HEK,
            KeyUsage::default().set_hmac_key_en().set_aes_key_en(),
        )
        .into(),
    );
    let idev_slot = HmacKey::Key(KeyReadArgs::new(KEY_ID_STABLE_IDEV));
    hmac_kdf(
        hmac,
        idev_slot,
        b"OCP_LOCK_HEK",
        Some(hek_seed),
        trng,
        hek_slot,
        HmacMode::Hmac512,
    )?;

    cprintln!("[ROM] check_populate_hek PASSED");
    Ok(())
}

// Check that HMAC with HEK => LOCK_KV still works after LOCK mode is set.
fn check_hmac_ocp_kv_to_ocp_kv_lock_mode(hmac: &mut Hmac, trng: &mut Trng) -> CaliptraResult<()> {
    cprintln!("[ROM] Checking HEK to OCP KV HMAC after LOCK mode enabled");
    // Assertion:
    // After ROM enables LOCK mode, it should still be possible to do HMAC(key=HEK, dest=LOCK_KV)
    let hek_slot = HmacKey::Key(KeyReadArgs::new(KEY_ID_HEK));
    // EPK was arbitrarily chosen as a LOCK KV without any special conditions.
    let mdk_slot = HmacTag::Key(KeyWriteArgs::new(KEY_ID_EPK, KeyUsage::default()));
    let res = hmac.hmac(
        hek_slot,
        HmacData::Slice(&[0; 32]),
        trng,
        mdk_slot,
        HmacMode::Hmac512,
    );

    match res {
        Ok(res) => {
            cprintln!("[ROM] check_hmac_ocp_kv_to_ocp_kv_lock_mode PASSED");
            Ok(res)
        }
        Err(e) => {
            cprintln!("[ROM] check_hmac_ocp_kv_to_ocp_kv_lock_mode FAILED");
            Err(e)
        }
    }
}

// Check that regular KV to OCP KV fails after LOCK mode is set.
fn check_hmac_regular_kv_to_ocp_kv_lock_mode(
    hmac: &mut Hmac,
    trng: &mut Trng,
) -> CaliptraResult<()> {
    cprintln!("[ROM] Checking Regular to OCP KV HMAC after LOCK mode enabled");
    // Assertion:
    // After ROM enables LOCK mode, it should not be possible to do HMAC(key=REGULAR_KV, dest=LOCK_KV)
    let regular_kv = HmacKey::Key(KeyReadArgs::new(KEY_ID_ROM_FMC_CDI));
    // EPK was arbitrarily chosen as a LOCK KV without any special conditions.
    let lock_kv = HmacTag::Key(KeyWriteArgs::new(KEY_ID_EPK, KeyUsage::default()));
    let res = hmac.hmac(
        regular_kv,
        HmacData::Slice(&[0; 32]),
        trng,
        lock_kv,
        HmacMode::Hmac512,
    );

    match res {
        Ok(_) => {
            cprintln!("[ROM] check_hmac_regular_kv_to_ocp_kv_lock_mode FAILED");
            Err(CaliptraError::RUNTIME_INTERNAL) // TODO(clundin): Add OCP failure mode error code.
        }
        Err(_) => {
            cprintln!("[ROM] check_hmac_regular_kv_to_ocp_kv_lock_mode PASSED");
            Ok(())
        }
    }
}

/// Helper function, populate slot with constant seed for testing.
fn populate_slot(hmac: &mut Hmac, trng: &mut Trng, slot: KeyId) -> CaliptraResult<()> {
    hmac.hmac(
        HmacKey::Array4x16(&Array4x16::default()),
        HmacData::from(&[0]),
        trng,
        KeyWriteArgs::new(slot, KeyUsage::default().set_hmac_key_en().set_aes_key_en()).into(),
        HmacMode::Hmac512,
    )
}
