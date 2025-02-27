/*++

Licensed under the Apache-2.0 license.

File Name:

    compatibility.rs

Abstract:

    File contains compatibility functions to to check if the runtime is
    compatible with FMC.

--*/

use caliptra_builder::version::RUNTIME_VERSION_MAJOR;
use caliptra_common::FirmwareHandoffTable;

pub fn is_fmc_compatible(fht: &FirmwareHandoffTable) -> bool {
    fht.fht_major_ver == RUNTIME_VERSION_MAJOR
}

#[test]
fn test_is_fmc_compatible() {
    let mut fht = FirmwareHandoffTable::default();
    fht.fht_major_ver = 1;
    fht.fht_minor_ver = 0;
    assert_eq!(is_fmc_compatible(&fht), true);

    // change minor version should not affect compatibility
    fht.fht_minor_ver = 1;
    assert_eq!(is_fmc_compatible(&fht), true);

    fht.fht_minor_ver = 0xff;
    assert_eq!(is_fmc_compatible(&fht), true);

    fht.fht_major_ver = 2;
    assert_eq!(is_fmc_compatible(&fht), false);
}
