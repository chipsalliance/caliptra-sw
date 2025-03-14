/*++

Licensed under the Apache-2.0 license.

File Name:

    pmp.rs

Abstract:

    PMP support routine for locking the DataVault.

--*/
use riscv::register::{Permission, Range, pmpaddr0, pmpaddr1, pmpaddr2, pmpaddr3, pmpcfg0};

/// Lock the DataVault region using PMP configuration.
///
/// # Arguments
/// * `base_address` - Base address of the region
/// * `region_size` - Size of the region
/// * `cold_reset_region` - True if the region is for Cold Reset, false for Warm Reset
///
/// Note: If a PMP entry is locked, writes to the configuration register and
/// associated address registers are ignored.
///
pub fn lock_datavault_region(base_address: usize, region_size: usize, cold_reset_region: bool) {
    unsafe {
        // Calculate the end address of the region
        let end_address = base_address + region_size;

        // PMP address register encodes Bits 33:2 of a 34-bit physical address.
        let base_address = base_address >> 2;
        let end_address = end_address >> 2;

        let index: usize = if cold_reset_region {
            // Use pmp1cfg for Cold Reset region.
            pmpaddr0::write(base_address);
            pmpaddr1::write(end_address);
            1
        } else {
            // Use pmp3cfg for Warm Reset region.
            pmpaddr2::write(base_address);
            pmpaddr3::write(end_address);
            3
        };

        // Set the PMP configuration.
        pmpcfg0::set_pmp(index, Range::TOR, Permission::R, true);
    }
}
