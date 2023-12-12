// Licensed under the Apache-2.0 license

#![no_std]
#![no_main]

use caliptra_drivers::{PersistentData, PersistentDataAccessor};
use caliptra_test_harness::{runtime_handlers, test_suite};

fn test_persistent_data_layout() {
    PersistentData::assert_matches_layout();
}

fn test_read_write() {
    {
        let mut accessor = unsafe { PersistentDataAccessor::new() };
        accessor.get_mut().fht.fht_marker = 0xfe9cd1c0;
    }
    {
        let accessor = unsafe { PersistentDataAccessor::new() };
        assert_eq!(accessor.get().fht.fht_marker, 0xfe9cd1c0);
    }
}

test_suite! {
    test_persistent_data_layout,
    test_read_write,
}
