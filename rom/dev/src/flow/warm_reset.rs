/*++

Licensed under the Apache-2.0 license.

File Name:

    warm_reset.rs

Abstract:

    File contains the implementation of warm reset flow.

--*/
use crate::{cprintln, rom_env::RomEnv};
use caliptra_common::FirmwareHandoffTable;
use caliptra_common::RomBootStatus::*;
use caliptra_drivers::{report_boot_status, DataVault, WarmResetEntry48, WarmResetEntry4};
use caliptra_error::{CaliptraError, CaliptraResult};
use caliptra_image_types::ImageManifest;
use zerocopy::{AsBytes, FromBytes};

/// Warm Reset Flow
pub struct WarmResetFlow {}

impl WarmResetFlow {
    /// Execute warm reset flow
    ///
    /// # Arguments
    ///
    /// * `env` - ROM Environment
    #[inline(never)]
    pub fn run(env: &mut RomEnv) -> CaliptraResult<FirmwareHandoffTable> {
        cprintln!("[warm-reset] ++");
        report_boot_status(WarmResetStarted.into());

        // Retrieve the old FHT from DCCM
        let fht = FirmwareHandoffTable::try_load()
            .ok_or(CaliptraError::ROM_WARM_RESET_READ_FHT_FAILURE)?;

        // Load the manifest from DCCM
        let manifest = Self::load_manifest(fht.manifest_load_addr)?;
        report_boot_status(WarmResetLoadManifestComplete.into());

        // Fill the data vault with information from manifest
        Self::populate_data_vault(&mut env.data_vault, &manifest, fht.manifest_load_addr);

        cprintln!("[warm-reset] --");
        report_boot_status(WarmResetComplete.into());
        Ok(fht)
    }

    /// Load the manifest
    ///
    /// # Arguments
    ///
    /// * `manifest_load_addr` - DCCM address of manifest
    ///
    /// # Returns
    ///
    /// * `Manifest` - Caliptra Image Bundle Manifest
    fn load_manifest(manifest_load_addr: u32) -> CaliptraResult<ImageManifest> {
        let slice = unsafe {
            let ptr = manifest_load_addr as *mut u32;
            core::slice::from_raw_parts_mut(ptr, core::mem::size_of::<ImageManifest>() / 4)
        };

        ImageManifest::read_from(slice.as_bytes())
            .ok_or(CaliptraError::ROM_WARM_RESET_FLOW_MANIFEST_READ_FAILURE)
    }

    /// Populate data vault entries that were cleared on warm reset
    ///
    /// # Arguments
    ///
    /// * `data_vault`    - Data Vault to be populated
    /// * `manifest`      - ImageManifest
    /// * `manifest_addr` - Manifest address
    fn populate_data_vault(data_vault: &mut DataVault, manifest: &ImageManifest, manifest_addr: u32) {
        data_vault.write_warm_reset_entry48(WarmResetEntry48::RtTci, &manifest.runtime.digest.into());

        data_vault.write_warm_reset_entry4(WarmResetEntry4::RtSvn, manifest.runtime.svn);

        data_vault.write_warm_reset_entry4(WarmResetEntry4::RtLoadAddr, manifest.runtime.load_addr);

        data_vault.write_warm_reset_entry4(WarmResetEntry4::RtEntryPoint, manifest.runtime.entry_point);

        data_vault.write_warm_reset_entry4(WarmResetEntry4::ManifestAddr, manifest_addr);
    }
}
