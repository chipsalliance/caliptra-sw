/*++

Licensed under the Apache-2.0 license.

File Name:

    dummy_peripheral.rs

Abstract:

    File contains non-functional dummy peripheral that is
    used for NMI generation.

--*/
use caliptra_emu_bus::Clock;
use caliptra_emu_bus::Timer;
use caliptra_emu_bus::TimerAction;
use caliptra_emu_bus::{Bus, BusError};
use caliptra_emu_types::{RvAddr, RvData, RvSize};

pub struct DummyPeripheral {
    timer: Timer,
}

impl DummyPeripheral {
    pub fn new(clock: &Clock) -> Self {
        Self {
            timer: clock.timer(),
        }
    }

    pub fn nmi_invalid_read(&mut self) {
        let nmi_invalid_read_delay: u64 = 0x0;
        const NMI_INVALID_READ: u32 = 0x0000_00f1;

        self.timer.schedule_action_in(
            nmi_invalid_read_delay,
            TimerAction::Nmi {
                mcause: NMI_INVALID_READ,
            },
        );
    }

    pub fn nmi_invalid_write(&mut self) {
        let nmi_invalid_write_delay: u64 = 0x0;
        const NMI_INVALID_WRITE: u32 = 0x0000_00f2;

        self.timer.schedule_action_in(
            nmi_invalid_write_delay,
            TimerAction::Nmi {
                mcause: NMI_INVALID_WRITE,
            },
        );
    }
}

impl Bus for DummyPeripheral {
    fn read(&mut self, _size: RvSize, _addr: RvAddr) -> Result<RvData, BusError> {
        //shouldn't read from the DummyPeripheral
        Err(BusError::LoadAccessFault)
    }

    fn write(&mut self, _size: RvSize, _addr: RvAddr, _val: RvData) -> Result<(), BusError> {
        //shouldn't write to the DummyPeripheral
        Err(BusError::StoreAccessFault)
    }

    fn poll(&mut self) {}
}
