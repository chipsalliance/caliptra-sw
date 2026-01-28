// Licensed under the Apache-2.0 license

use caliptra_api::mailbox::{
    OcpLockReportHekMetadataReq, OcpLockReportHekMetadataResp, OcpLockReportHekMetadataRespFlags,
};
use caliptra_cfi_lib::{cfi_assert, cfi_assert_bool, cfi_launder};
use caliptra_common::{
    crypto::Crypto,
    keyids::{
        ocp_lock::{KEY_ID_HEK, KEY_ID_MDK},
        KEY_ID_ROM_FMC_CDI,
    },
};
use caliptra_drivers::{
    Array4x8, CaliptraResult, HekSeedState, HmacMode, KeyUsage, KeyVault, Lifecycle,
    PersistentData, SocIfc,
};

use crate::rom_env::RomEnv;

use zerocopy::IntoBytes;

/// Run the OCP LOCK Cold Reset flow
///
/// # Arguments
///
/// * `env` - ROM Environment
pub fn ocp_lock_cold_reset_flow(env: &mut RomEnv) -> CaliptraResult<()> {
    if cfi_launder(!env.soc_ifc.ocp_lock_enabled()) {
        return Ok(());
    } else {
        cfi_assert!(env.soc_ifc.ocp_lock_enabled())
    }
    derive_hek(env)?;
    derive_mdk(env)?;
    Ok(())
}

/// Derive OCP LOCK HEK
///
/// NOTE: The HEK _may_ be disabled once MCU has reported the HEK seed state.
///
/// # Arguments
///
/// * `env` - ROM Environment
fn derive_hek(env: &mut RomEnv) -> CaliptraResult<()> {
    let hek_seed = env.soc_ifc.fuse_bank().ocp_hek_seed();
    Crypto::hmac_kdf(
        &mut env.hmac,
        &mut env.trng,
        KEY_ID_ROM_FMC_CDI,
        b"ocp_lock_hek",
        Some(hek_seed.as_bytes()),
        KEY_ID_HEK,
        HmacMode::Hmac512,
        KeyUsage::default().set_hmac_key_en(),
    )?;
    Ok(())
}

/// Derive OCP LOCK MDK
///
/// # Arguments
///
/// * `env` - ROM Environment
fn derive_mdk(env: &mut RomEnv) -> CaliptraResult<()> {
    Crypto::hmac_kdf(
        &mut env.hmac,
        &mut env.trng,
        KEY_ID_ROM_FMC_CDI,
        b"ocp_lock_mdk",
        None,
        KEY_ID_MDK,
        HmacMode::Hmac512,
        KeyUsage::default().set_aes_key_en(),
    )?;
    Ok(())
}

/// Handle `ReportHekMetadataReq` command from MCU.
///
/// Returns:
///  True if the HEK is available. False otherwise.
pub fn handle_report_hek_metadata(
    lifecycle_state: Lifecycle,
    pdata: &mut PersistentData,
    req: &OcpLockReportHekMetadataReq,
    hek_seed: &Array4x8,
) -> CaliptraResult<OcpLockReportHekMetadataResp> {
    let hek_seed_state = HekSeedState::try_from(req.seed_state)?;
    let hek_available = hek_seed_state.hek_is_available(lifecycle_state, hek_seed);

    pdata.rom.ocp_lock_metadata.hek_available = hek_available;
    pdata.rom.ocp_lock_metadata.total_hek_seed_slots = req.total_slots;
    pdata.rom.ocp_lock_metadata.active_hek_seed_slots = req.active_slots;
    pdata.rom.ocp_lock_metadata.hek_seed_state = req.seed_state;

    let mut resp = OcpLockReportHekMetadataResp::default();
    resp.flags.set(
        OcpLockReportHekMetadataRespFlags::HEK_AVAILABLE,
        hek_available,
    );
    Ok(resp)
}

/// Check HEK availability. Must always be called before moving to next boot stage.
///
/// HEK can only be marked available if MCU has called `REPORT_HEK_METADATA`.
///
/// If HEK is available, NOP
/// If HEK is unavailable, erase HEK.
fn zeroize_hek_if_needed(pdata: &mut PersistentData, kv: &mut KeyVault) -> CaliptraResult<()> {
    if cfi_launder(pdata.rom.ocp_lock_metadata.hek_available) {
        return Ok(());
    } else {
        cfi_assert!(!pdata.rom.ocp_lock_metadata.hek_available)
    }
    // HEK seed is not available, erase the HEK.
    kv.erase_key(KEY_ID_HEK)
}

/// Write locks OCP LOCK HEK & MDK Key Vault slots
///
/// This should be called on reset to prevent later stages from writing to the HEK & MDK slots.
pub fn wr_lock_keyvault(kv: &mut KeyVault) {
    kv.set_key_write_lock(KEY_ID_HEK);
    kv.set_key_write_lock(KEY_ID_MDK);
}

/// Completes the OCP LOCK flow after a cold reset.
///
/// Checks the HEK seed state. Sets LOCK in Progress.
pub fn complete_ocp_lock_flow(
    soc_ifc: &mut SocIfc,
    pdata: &mut PersistentData,
    kv: &mut KeyVault,
) -> CaliptraResult<()> {
    // Check that ROM has reported the HEK seed's state.
    // We must always do this on a cold reset after processing FW commands.
    zeroize_hek_if_needed(pdata, kv)?;
    wr_lock_keyvault(kv);

    // We have completed the OCP LOCK ROM cold reset flow. Set LOCK in progress to enable OCP
    // LOCK mode in hardware.
    soc_ifc.ocp_lock_set_lock_in_progress();
    Ok(())
}
