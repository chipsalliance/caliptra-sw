/*++

Licensed under the Apache-2.0 license.

File Name:

    iccm.rs

Abstract:

    File contains ICCM Implementation

--*/
use caliptra_emu_bus::Bus;
use caliptra_emu_bus::BusError;
use caliptra_emu_bus::BusError::StoreAccessFault;
use caliptra_emu_bus::Clock;
use caliptra_emu_bus::Ram;
use caliptra_emu_bus::Timer;
use caliptra_emu_bus::TimerAction;
use caliptra_emu_types::RvAddr;
use caliptra_emu_types::RvData;
use caliptra_emu_types::RvSize;
use std::cell::Cell;
use std::{cell::RefCell, rc::Rc};

#[derive(Clone)]
pub struct Iccm {
    iccm: Rc<IccmImpl>,
}
const ICCM_SIZE_BYTES: usize = 128 * 1024;

impl Iccm {
    pub fn lock(&mut self) {
        self.iccm.locked.set(true);
    }

    pub fn unlock(&mut self) {
        self.iccm.locked.set(false);
    }

    pub fn new(clock: &Clock) -> Self {
        Self {
            iccm: Rc::new(IccmImpl::new(clock)),
        }
    }

    pub fn ram(&self) -> &RefCell<Ram> {
        &self.iccm.ram
    }
}

struct IccmImpl {
    ram: RefCell<Ram>,
    locked: Cell<bool>,
    timer: Timer,
}

impl IccmImpl {
    pub fn new(clock: &Clock) -> Self {
        Self {
            ram: RefCell::new(Ram::new(vec![0; ICCM_SIZE_BYTES])),
            locked: Cell::new(false),
            timer: clock.timer(),
        }
    }
}

impl Bus for Iccm {
    /// Read data of specified size from given address
    fn read(&mut self, size: RvSize, addr: RvAddr) -> Result<RvData, BusError> {
        self.iccm.ram.borrow_mut().read(size, addr)
    }

    /// Write data of specified size to given address
    fn write(&mut self, size: RvSize, addr: RvAddr, val: RvData) -> Result<(), BusError> {
        // NMIs don't fire immediately; a couple instructions is a fairly typicaly delay on VeeR.
        const NMI_DELAY: u64 = 2;

        // From RISC-V_VeeR_EL2_PRM.pdf
        const NMI_CAUSE_DBUS_STORE_ERROR: u32 = 0xf000_0000;

        if size != RvSize::Word || (addr & 0x3) != 0 {
            self.iccm.timer.schedule_action_in(
                NMI_DELAY,
                TimerAction::Nmi {
                    mcause: NMI_CAUSE_DBUS_STORE_ERROR,
                },
            );
            return Ok(());
        }
        if self.iccm.locked.get() {
            return Err(StoreAccessFault);
        }
        self.iccm.ram.borrow_mut().write(size, addr, val)
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    fn next_action(clock: &Clock) -> Option<TimerAction> {
        let mut actions = clock.increment(4);
        match actions.len() {
            0 => None,
            1 => actions.drain().next(),
            _ => panic!("More than one action scheduled; unexpected"),
        }
    }

    #[test]
    fn test_unlocked_write() {
        let clock = Clock::new();
        let mut iccm = Iccm::new(&clock);
        for word_offset in (0u32..ICCM_SIZE_BYTES as u32).step_by(4) {
            assert_eq!(iccm.read(RvSize::Word, word_offset).unwrap(), 0);
            assert_eq!(
                iccm.write(RvSize::Word, word_offset, u32::MAX).ok(),
                Some(())
            );
            assert_eq!(iccm.read(RvSize::Word, word_offset).ok(), Some(u32::MAX));
        }
        assert_eq!(next_action(&clock), None);
    }

    #[test]
    fn test_locked_write() {
        let clock = Clock::new();
        let mut iccm = Iccm::new(&clock);
        iccm.lock();
        for word_offset in (0u32..ICCM_SIZE_BYTES as u32).step_by(4) {
            assert_eq!(iccm.read(RvSize::Word, word_offset).unwrap(), 0);
            assert_eq!(
                iccm.write(RvSize::Word, word_offset, u32::MAX).err(),
                Some(BusError::StoreAccessFault)
            );
        }
        assert_eq!(next_action(&clock), None);
    }

    #[test]
    fn test_byte_write() {
        let clock = Clock::new();
        let mut iccm = Iccm::new(&clock);
        assert_eq!(iccm.write(RvSize::Byte, 0, 42), Ok(()));
        assert_eq!(
            next_action(&clock),
            Some(TimerAction::Nmi {
                mcause: 0xf000_0000
            })
        );
    }
}
