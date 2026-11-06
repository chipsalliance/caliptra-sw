// Licensed under the Apache-2.0 license

use caliptra_emu_bus::{Bus, BusError};
use caliptra_emu_periph::{CaliptraRootBus, CaliptraRootBusArgs, DbgSocUnlockLevelCb};
use caliptra_emu_types::RvSize;
use std::{cell::RefCell, rc::Rc};

const LEVEL: u32 = 0x3003_05c8;

fn exercise_unlock_level(registered: bool) {
    let calls = Rc::new(RefCell::new(Vec::new()));
    let captured = calls.clone();
    let mut bus = CaliptraRootBus::new(CaliptraRootBusArgs {
        dbg_soc_unlock_level_cb: if registered {
            DbgSocUnlockLevelCb::new(move |index, value| captured.borrow_mut().push((index, value)))
        } else {
            Default::default()
        },
        ..Default::default()
    });
    let mut external = bus.soc_reg.external_regs();
    let debug_locked = bus.soc_reg.is_debug_locked();
    let mut expected = Vec::new();
    let mut levels = [0; 2];
    assert!(calls.borrow().is_empty());
    for index in 0..2 {
        assert_eq!(bus.read(RvSize::Word, LEVEL + index * 4), Ok(0));
    }

    for (index, value) in [
        (0, 0),
        (1, 0),
        (1, 0x8000_0000),
        (1, 0x8000_0000),
        (0, 0x1234_5678),
        (0, 0x1234_5678),
        (1, u32::MAX),
        (0, 0),
        (1, 0),
    ] {
        // Exercise writes through both bus interfaces to both entries.
        bus.write(RvSize::Word, LEVEL + index as u32 * 4, value)
            .unwrap();
        if registered && levels[index] != value {
            expected.push((index, value));
        }
        levels[index] = value;
        assert_eq!(*calls.borrow(), expected);
        external
            .write(RvSize::Word, 0x5c8 + index as u32 * 4, value ^ 1)
            .unwrap();
        levels[index] = value ^ 1;
        if registered {
            expected.push((index, value ^ 1));
        }
        assert_eq!(*calls.borrow(), expected);
        external
            .write(RvSize::Word, 0x5c8 + index as u32 * 4, value ^ 1)
            .unwrap();
        assert_eq!(*calls.borrow(), expected);
        for (entry, stored) in levels.iter().enumerate() {
            assert_eq!(
                bus.read(RvSize::Word, LEVEL + entry as u32 * 4),
                Ok(*stored)
            );
            assert_eq!(
                external.read(RvSize::Word, 0x5c8 + entry as u32 * 4),
                Ok(*stored)
            );
        }
    }

    for index in 0..2 {
        let address = LEVEL + index * 4;
        for size in [RvSize::Byte, RvSize::HalfWord] {
            assert_eq!(bus.write(size, address, 0), Err(BusError::StoreAccessFault));
            assert_eq!(
                external.write(size, 0x5c8 + index * 4, 0),
                Err(BusError::StoreAccessFault)
            );
            assert_eq!(bus.read(size, address), Err(BusError::LoadAccessFault));
            assert_eq!(
                external.read(size, 0x5c8 + index * 4),
                Err(BusError::LoadAccessFault)
            );
        }
        for offset in 1..4 {
            assert!(bus.write(RvSize::Word, address + offset, 0).is_err());
            assert!(bus.read(RvSize::Word, address + offset).is_err());
        }
    }
    assert_eq!(*calls.borrow(), expected);
    assert_eq!(bus.soc_reg.is_debug_locked(), debug_locked);
    for address in [0x3003_05c0, 0x3003_05c4, 0x3003_05d0] {
        assert_eq!(bus.read(RvSize::Word, address), Ok(0));
    }
    bus.soc_reg.warm_reset();
    bus.soc_reg.update_reset();
    external.warm_reset();
    external.update_reset();
    assert_eq!(*calls.borrow(), expected);
    for (index, value) in levels.into_iter().enumerate() {
        let address = LEVEL + index as u32 * 4;
        assert_eq!(bus.read(RvSize::Word, address), Ok(value));
        bus.write(RvSize::Word, address, value).unwrap();
        assert_eq!(*calls.borrow(), expected);
        bus.write(RvSize::Word, address, value ^ 1).unwrap();
        if registered {
            expected.push((index, value ^ 1));
        }
        assert_eq!(*calls.borrow(), expected);
        assert_eq!(
            external.read(RvSize::Word, 0x5c8 + index as u32 * 4),
            Ok(value ^ 1)
        );
    }
}

#[test]
fn default_callback_preserves_both_entries() {
    exercise_unlock_level(false);
}

#[test]
fn callback_observes_changes_to_both_entries() {
    exercise_unlock_level(true);
}
