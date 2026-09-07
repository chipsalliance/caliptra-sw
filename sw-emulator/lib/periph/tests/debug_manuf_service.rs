// Licensed under the Apache-2.0 license

use caliptra_emu_bus::{Bus, BusError};
use caliptra_emu_periph::{CaliptraRootBus, CaliptraRootBusArgs, DbgManufServiceCb};
use caliptra_emu_types::RvSize;
use std::{cell::RefCell, rc::Rc};

const RESPONSE: u32 = 0x3003_05c4;

fn exercise_response(registered: bool) {
    let calls = Rc::new(RefCell::new(Vec::new()));
    let captured = calls.clone();
    let mut bus = CaliptraRootBus::new(CaliptraRootBusArgs {
        dbg_manuf_service_cb: if registered {
            DbgManufServiceCb::new(move |value| captured.borrow_mut().push(value))
        } else {
            Default::default()
        },
        ..Default::default()
    });
    let mut external = bus.soc_reg.external_regs();
    let debug_locked = bus.soc_reg.is_debug_locked();
    let mut expected = Vec::new();
    assert!(calls.borrow().is_empty());
    assert_eq!(bus.read(RvSize::Word, RESPONSE), Ok(0));

    // Include every other defined field, reserved bits, repeated writes, and
    // both edges of the success bit. Bit 3 is production success, not manufacturing.
    let values = [
        0,
        2,
        4,
        8,
        16,
        32,
        64,
        128,
        256,
        0xffff_fffe,
        0xffff_ffff,
        0xffff_ffff,
        1,
        3,
        2,
        0,
        1,
    ];
    let mut previous = 0;
    for (index, value) in values.into_iter().enumerate() {
        if index % 2 == 0 {
            bus.write(RvSize::Word, RESPONSE, value).unwrap();
        } else {
            external.write(RvSize::Word, 0x5c4, value).unwrap();
        }
        if registered && (previous ^ value) & 1 != 0 {
            expected.push(value);
        }
        assert_eq!(*calls.borrow(), expected);
        assert_eq!(bus.read(RvSize::Word, RESPONSE), Ok(value));
        assert_eq!(external.read(RvSize::Word, 0x5c4), Ok(value));
        previous = value;
    }

    for size in [RvSize::Byte, RvSize::HalfWord] {
        assert_eq!(
            bus.write(size, RESPONSE, 0),
            Err(BusError::StoreAccessFault)
        );
        assert_eq!(
            external.write(size, 0x5c4, 0),
            Err(BusError::StoreAccessFault)
        );
        assert_eq!(bus.read(size, RESPONSE), Err(BusError::LoadAccessFault));
        assert_eq!(external.read(size, 0x5c4), Err(BusError::LoadAccessFault));
    }
    for offset in 1..4 {
        assert!(bus.write(RvSize::Word, RESPONSE + offset, 0).is_err());
        assert!(bus.read(RvSize::Word, RESPONSE + offset).is_err());
    }
    assert_eq!(bus.read(RvSize::Word, RESPONSE), Ok(1));
    assert_eq!(*calls.borrow(), expected);
    assert_eq!(bus.soc_reg.is_debug_locked(), debug_locked);
    for address in [0x3003_05c0, 0x3003_05c8, 0x3003_05cc] {
        assert_eq!(bus.read(RvSize::Word, address), Ok(0));
    }

    // Preserve the emulator's existing reset domains: neither reset clears this
    // register, and neither should manufacture a callback notification.
    bus.soc_reg.warm_reset();
    bus.soc_reg.update_reset();
    external.warm_reset();
    external.update_reset();
    assert_eq!(bus.read(RvSize::Word, RESPONSE), Ok(1));
    assert_eq!(*calls.borrow(), expected);
    bus.write(RvSize::Word, RESPONSE, 1).unwrap();
    assert_eq!(*calls.borrow(), expected);
    bus.write(RvSize::Word, RESPONSE, 0).unwrap();
    if registered {
        expected.push(0);
    }
    assert_eq!(*calls.borrow(), expected);
    assert_eq!(external.read(RvSize::Word, 0x5c4), Ok(0));
}

#[test]
fn default_callback_preserves_register_semantics() {
    exercise_response(false);
}

#[test]
fn callback_observes_only_manufacturing_success_transitions() {
    exercise_response(true);
}
