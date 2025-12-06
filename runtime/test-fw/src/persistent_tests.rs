// Licensed under the Apache-2.0 license

#![no_std]
#![no_main]

use caliptra_common::handle_fatal_error;
use caliptra_drivers::{PersistentData, PersistentDataAccessor};
use caliptra_registers::soc_ifc::SocIfcReg;
use caliptra_runtime::Drivers;
use caliptra_test_harness::{runtime_handlers, test_suite};

fn test_persistent_data_layout() {
    let mut drivers = unsafe {
        Drivers::new_from_registers().unwrap_or_else(|e| {
            handle_fatal_error(e.into());
        })
    };
    // Set this to signal we're in runtime
    drivers.soc_ifc.assert_ready_for_runtime();

    PersistentData::assert_matches_layout();
}

fn test_read_write() {
    {
        let mut accessor = unsafe { PersistentDataAccessor::new() };
        accessor.get_mut().rom.fht.fht_marker = 0xfe9cd1c0;
    }
    {
        let accessor = unsafe { PersistentDataAccessor::new() };
        assert_eq!(accessor.get().rom.fht.fht_marker, 0xfe9cd1c0);
    }
}

test_suite! {
    test_persistent_data_layout,
    test_read_write,
}
