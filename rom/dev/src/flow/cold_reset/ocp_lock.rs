// Licensed under the Apache-2.0 license

use caliptra_api::mailbox::{
    ReportHekMetadataReq, ReportHekMetadataResp, ReportHekMetadataRespFlags,
};
use caliptra_cfi_lib::{cfi_assert, cfi_assert_bool, cfi_launder};
use caliptra_common::keyids::ocp_lock::KEY_ID_HEK;
use caliptra_drivers::{CaliptraResult, HekSeedState, KeyVault, Lifecycle, PersistentData, SocIfc};

/// Handle `ReportHekMetadataReq` command from MCU.
///
/// Returns:
///  True if the HEK is available. False otherwise.
pub fn handle_report_hek_metadata(
    lifecycle_state: Lifecycle,
    pdata: &mut PersistentData,
    req: &ReportHekMetadataReq,
) -> CaliptraResult<ReportHekMetadataResp> {
    let hek_seed_state = HekSeedState::try_from(req.seed_state)?;
    let hek_available = hek_seed_state.hek_is_available(lifecycle_state);

    pdata.ocp_lock_metadata.hek_available = hek_available;
    pdata.ocp_lock_metadata.total_hek_seed_slots = req.total_slots;
    pdata.ocp_lock_metadata.active_hek_seed_slots = req.active_slots;
    pdata.ocp_lock_metadata.hek_seed_state = req.seed_state;

    let mut resp = ReportHekMetadataResp::default();
    resp.flags
        .set(ReportHekMetadataRespFlags::HEK_AVAILABLE, hek_available);
    Ok(resp)
}

/// Check HEK availability. Must always be called before moving to next boot stage.
///
/// HEK can only be marked available if MCU has called `REPORT_HEK_METADATA`.
///
/// If HEK is available, NOP
/// If HEK is unavailable, erase HEK.
fn zeroize_hek_if_needed(pdata: &mut PersistentData, kv: &mut KeyVault) -> CaliptraResult<()> {
    if cfi_launder(pdata.ocp_lock_metadata.hek_available) {
        kv.set_key_write_lock(KEY_ID_HEK);
        return Ok(());
    } else {
        cfi_assert!(!pdata.ocp_lock_metadata.hek_available)
    }
    // HEK seed is not available, erase the HEK.
    kv.erase_key(KEY_ID_HEK)
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
    // We have completed the OCP LOCK ROM cold reset flow. Set LOCK in progress to enable OCP
    // LOCK mode in hardware.
    soc_ifc.ocp_lock_set_lock_in_progress();
    Ok(())
}
