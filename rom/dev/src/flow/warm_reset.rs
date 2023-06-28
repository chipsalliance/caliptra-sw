/*++

Licensed under the Apache-2.0 license.

File Name:

    warm_reset.rs

Abstract:

    File contains the implementation of warm reset flow.

--*/
use crate::{cprintln, rom_env::RomEnv};
use caliptra_common::FirmwareHandoffTable;
use caliptra_drivers::{CaliptraResult, DataVault, WarmResetEntry4, WarmResetEntry48};
use caliptra_error::CaliptraError;
use caliptra_image_types::ImageManifest;
use zerocopy::{AsBytes, FromBytes};

/// Warm Reset Flow
pub struct WarmResetFlow {}

impl WarmResetFlow {
    /// Execute update reset flow
    ///
    /// # Arguments
    ///
    /// * `env` - ROM Environment
    #[inline(never)]
    pub fn run(env: &mut RomEnv) -> CaliptraResult<Option<FirmwareHandoffTable>> {
        cprintln!("[warm-reset] ++");

        // [TODO] Remove this when RTL bug is fixed.
        // Currently, RTL unlocks and clears the warm reset registers
        // (NONSTICKY_DATA_VAULT_ENTRY/NonStickyLockableScratchReg/NonStickyGenericScratchReg)
        // instead of simply unlocking them. As a result, FMC cannot get the RT load address and offset on a Warm Reset.
        // Following issue is filed to fix the RTL:
        // https://github.com/chipsalliance/caliptra-rtl/issues/161
        // Retrieve the old FHT from the DCCM.
        let fht = FirmwareHandoffTable::try_load()
            .ok_or(CaliptraError::ROM_WARM_RESET_READ_FHT_FAILURE)?;

        // Load the manifest from DCCM
        let manifest = Self::load_manifest(fht.manifest_load_addr)?;

        // Fill the data vault with information from manifest
        Self::populate_data_vault(&mut env.data_vault, &manifest, fht.manifest_load_addr);

        cprintln!("[warm-reset] --");

        Ok(None)
    }

    fn load_manifest(manifest_load_addr: u32) -> CaliptraResult<ImageManifest> {
        let slice = unsafe {
            let ptr = manifest_load_addr as *mut u32;
            core::slice::from_raw_parts_mut(ptr, core::mem::size_of::<ImageManifest>() / 4)
        };

        ImageManifest::read_from(slice.as_bytes())
            .ok_or(CaliptraError::ROM_WARM_RESET_FLOW_MANIFEST_READ_FAILURE)
    }

    fn populate_data_vault(
        data_vault: &mut DataVault,
        manifest: &ImageManifest,
        manifest_addr: u32,
    ) {
        data_vault
            .write_warm_reset_entry48(WarmResetEntry48::RtTci, &manifest.runtime.digest.into());

        data_vault.write_warm_reset_entry4(WarmResetEntry4::RtSvn, manifest.runtime.svn);

        data_vault.write_warm_reset_entry4(WarmResetEntry4::RtLoadAddr, manifest.runtime.load_addr);

        data_vault
            .write_warm_reset_entry4(WarmResetEntry4::RtEntryPoint, manifest.runtime.entry_point);

        data_vault.write_warm_reset_entry4(WarmResetEntry4::ManifestAddr, manifest_addr);
    }
}
