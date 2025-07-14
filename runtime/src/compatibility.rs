/*++

Licensed under the Apache-2.0 license.

File Name:

    compatibility.rs

Abstract:

    File contains compatibility functions to to check if the runtime is
    compatible with FMC.

--*/

use caliptra_common::{cprint, FirmwareHandoffTable};
use caliptra_image_types::ImageManifest;

// From the official documentation:
// "The Major and Minor version numbers of the Firmware Handoff Table.
// All FHT versions with the same Major version number must remain backward compatible.""
pub fn is_fmc_compatible(fht: &FirmwareHandoffTable, manifest: &ImageManifest) -> bool {
    cprint!(
        "[rt] FHT major: {}, Manifest FMC version: {}\n",
        fht.fht_major_ver,
        manifest.fmc.version
    );
    u32::from(fht.fht_major_ver) == manifest.fmc.version
}

#[test]
fn test_is_fmc_compatible() {
    let mut fht = FirmwareHandoffTable::default();
    let mut manifest = ImageManifest::default();

    fht.fht_major_ver = 1;
    fht.fht_minor_ver = 0;
    manifest.fmc.version = 1;

    assert!(is_fmc_compatible(&fht, &manifest));

    // change minor version should not affect compatibility
    fht.fht_minor_ver = 1;
    assert!(is_fmc_compatible(&fht, &manifest));

    fht.fht_minor_ver = 0xff;
    assert!(is_fmc_compatible(&fht, &manifest));

    fht.fht_major_ver = 2;
    assert!(!is_fmc_compatible(&fht, &manifest));
}
