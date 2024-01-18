// Licensed under the Apache-2.0 license

use std::cell::{Cell, RefCell};
use std::rc::Rc;

use caliptra_emu_bus::{
    Bus, BusError, Clock, ReadWriteRegister, ReadWriteRegisterArray, Register, Timer, TimerAction,
};
use caliptra_emu_derive::Bus;
use caliptra_emu_types::{RvAddr, RvData, RvSize};
use tock_registers::interfaces::Readable;
use tock_registers::register_bitfields;

const MAX_PRIORITY: u8 = 15;

#[derive(Clone)]
pub struct Pic {
    pic: Rc<PicImpl>,
}
impl Pic {
    pub fn new() -> Pic {
        Pic {
            pic: Rc::new(PicImpl::new()),
        }
    }
    pub fn register_irq(&self, id: u8) -> Irq {
        Irq {
            id,
            pic: self.pic.clone(),
        }
    }
    pub fn mmio_regs(&self, clock: &Clock) -> PicMmioRegisters {
        PicMmioRegisters {
            pic: self.pic.clone(),
            timer: clock.timer(),
        }
    }

    pub fn highest_priority_irq(&self, prithresh: u8) -> Option<u8> {
        self.pic.highest_priority_irq(prithresh)
    }
}
impl Default for Pic {
    fn default() -> Self {
        Pic::new()
    }
}

fn irq_id_from_addr(addr: u32) -> u8 {
    u8::try_from((addr & 0x7f) / 4).unwrap()
}
pub struct PicMmioRegisters {
    pic: Rc<PicImpl>,
    timer: Timer,
}
impl PicMmioRegisters {
    const MEIPL_OFFSET: RvAddr = 0x0000;
    const MEIPL_MIN: RvAddr = Self::MEIPL_OFFSET + 4;
    const MEIPL_MAX: RvAddr = Self::MEIPL_OFFSET + 31 * 4;

    #[allow(dead_code)]
    const MEIP_OFFSET: RvAddr = 0x1000;

    const MEIE_OFFSET: RvAddr = 0x2000;
    const MEIE_MIN: RvAddr = Self::MEIE_OFFSET + 4;
    const MEIE_MAX: RvAddr = Self::MEIE_OFFSET + 31 * 4;

    const MPICCFG_OFFSET: RvAddr = 0x3000;

    const MEIGWCTRL_OFFSET: RvAddr = 0x4000;
    const MEIGWCTRL_MIN: RvAddr = Self::MEIGWCTRL_OFFSET + 4;
    const MEIGWCTRL_MAX: RvAddr = Self::MEIGWCTRL_OFFSET + 31 * 4;

    const MEIGWCLR_OFFSET: RvAddr = 0x5000;
    const MEIGWCLR_MIN: RvAddr = Self::MEIGWCLR_OFFSET + 4;
    const MEIGWCLR_MAX: RvAddr = Self::MEIGWCLR_OFFSET + 31 * 4;

    pub fn register_irq(&self, id: u8) -> Irq {
        Irq {
            id,
            pic: self.pic.clone(),
        }
    }
}
impl Bus for PicMmioRegisters {
    fn read(&mut self, size: RvSize, addr: RvAddr) -> Result<RvData, BusError> {
        match addr {
            // The first element of each register array is invalid. (S=1..31)
            Self::MEIPL_OFFSET
            | Self::MEIE_OFFSET
            | Self::MEIGWCTRL_OFFSET
            | Self::MEIGWCLR_OFFSET => Err(BusError::LoadAccessFault),
            Self::MEIGWCLR_MIN..=Self::MEIGWCLR_MAX => Ok(0),
            _ => self.pic.regs.borrow_mut().read(size, addr),
        }
    }

    fn write(&mut self, size: RvSize, addr: RvAddr, val: RvData) -> Result<(), BusError> {
        match addr {
            // The first element of each register array is invalid. (S=1..31)
            Self::MEIPL_OFFSET
            | Self::MEIE_OFFSET
            | Self::MEIGWCTRL_OFFSET
            | Self::MEIGWCLR_OFFSET => Err(BusError::StoreAccessFault),

            Self::MEIGWCTRL_MIN..=Self::MEIGWCTRL_MAX => {
                self.pic.regs.borrow_mut().write(size, addr, val)?;
                self.pic.refresh_gateway(irq_id_from_addr(addr));
                Ok(())
            }

            // meigwclrS: External Interrupt Gateway Clear Register
            Self::MEIGWCLR_MIN..=Self::MEIGWCLR_MAX => {
                let id = irq_id_from_addr(addr);
                // Any write to this register will clear the pending bit in the gateway
                self.pic.gw_pending_ff.set(id, false);
                self.pic.refresh_gateway(id);
                Ok(())
            }
            Self::MEIPL_MIN..=Self::MEIPL_MAX | Self::MPICCFG_OFFSET => {
                self.pic.regs.borrow_mut().write(size, addr, val)?;
                self.pic.refresh_order();
                Ok(())
            }
            Self::MEIE_MIN..=Self::MEIE_MAX => {
                let mut regs = self.pic.regs.borrow_mut();
                regs.write(size, addr, val)?;
                self.pic.refresh_enabled(&regs, irq_id_from_addr(addr));

                Ok(())
            }
            _ => {
                self.pic.regs.borrow_mut().write(size, addr, val)?;
                Ok(())
            }
        }
    }

    fn poll(&mut self) {
        const EXT_INT_DELAY: u64 = 2;
        if let Some(irq) = self.pic.highest_priority_irq(MAX_PRIORITY - 1) {
            self.pic.irq_set_level(irq, false);
            self.timer.schedule_action_in(
                EXT_INT_DELAY,
                TimerAction::ExtInt {
                    irq,
                    can_wake: true,
                },
            );
        } else if let Some(irq) = self.pic.highest_priority_irq(0) {
            self.pic.irq_set_level(irq, false);
            self.timer.schedule_action_in(
                EXT_INT_DELAY,
                TimerAction::ExtInt {
                    irq,
                    can_wake: true,
                },
            );
        }
    }
}

pub struct Irq {
    /// The interrupt source id. A number between 1 and 31.
    id: u8,
    pic: Rc<PicImpl>,
}
impl Irq {
    pub fn id(&self) -> u8 {
        self.id
    }

    /// Set the level of the interrupt line (logic high or low). Whether logic
    /// high means interrupt-firing or interrupt-not-firing depends on the
    /// meigwctrl register's polarity field.
    pub fn set_level(&self, is_high: bool) {
        self.pic.irq_set_level(self.id, is_high);
    }
}

register_bitfields! [
    u32,

    Meipl [
        PRIORITY OFFSET(0) NUMBITS(4) [],
    ],

    Mpiccfg [
        PRIORITY_ORDER OFFSET(0) NUMBITS(1) [
            Standard = 0,
            Reverse = 1,
        ],
    ],

    Meie [
        INTEN OFFSET(0) NUMBITS(1) [],
    ],

    Meigwctrl [
        POLARITY OFFSET(0) NUMBITS(1) [
            ActiveHigh = 0,
            ActiveLow = 1,
        ],
        TYPE OFFSET(1) NUMBITS(1) [
            LevelTriggered = 0,
            EdgeTriggered = 1,
        ],
    ],
];

#[derive(Bus)]
struct PicImplRegs {
    // External interrupt priority level register. Irq id #1 starts at
    // meipl[1] (address 0x0004); meipl[0] is reserved.
    #[peripheral(offset = 0x0000, mask = 0x0fff)]
    meipl: ReadWriteRegisterArray<u32, 32, Meipl::Register>,

    // External Interrupt Pending. Irq id #1 starts at meip[1]; meip[0] is
    // reserved.
    #[register(offset = 0x1000)]
    meip: Bits32,

    // External Interrupt Enabled. Irq id #1 starts at meie[1] (address 0x2004);
    // meie[0] is reserved.
    #[peripheral(offset = 0x2000, mask = 0x0fff)]
    meie: ReadWriteRegisterArray<u32, 32, Meie::Register>,

    #[register(offset = 0x3000)]
    mpiccfg: ReadWriteRegister<u32, Mpiccfg::Register>,

    // External Interrupt Gateway Configuration. Irq id #1 starts at
    // meigwctrl[1] (address 0x4004); meigwctrl[0] is reserved.
    #[peripheral(offset = 0x4000, mask = 0x0fff)]
    meigwctrl: ReadWriteRegisterArray<u32, 32, Meigwctrl::Register>,
}
impl PicImplRegs {
    fn new() -> Self {
        Self {
            meipl: ReadWriteRegisterArray::new(0x0000_0000),
            meip: Bits32::new(),
            meie: ReadWriteRegisterArray::new(0x0000_0000),
            mpiccfg: ReadWriteRegister::new(0x0000_0000),
            meigwctrl: ReadWriteRegisterArray::new(0x0000_0000),
        }
    }
}

struct Bits32 {
    bits: Cell<u32>,
}
impl Bits32 {
    fn new() -> Self {
        Self { bits: Cell::new(0) }
    }
    fn all_bits_cleared(&self) -> bool {
        self.bits.get() == 0
    }
    fn first_set_index(&self) -> Option<u8> {
        if self.all_bits_cleared() {
            None
        } else {
            Some(self.bits.get().trailing_zeros() as u8)
        }
    }
    fn get(&self, idx: u8) -> bool {
        (self.bits.get() & (1 << idx)) != 0
    }
    fn set(&self, idx: u8, val: bool) {
        let mask = 1 << idx;
        if val {
            self.bits.set(self.bits.get() | mask);
        } else {
            self.bits.set(self.bits.get() & !mask);
        }
    }
}
impl Register for Bits32 {
    const SIZE: usize = 4;

    fn read(&self, _size: RvSize) -> Result<RvData, BusError> {
        Ok(self.bits.get())
    }

    fn write(&mut self, size: RvSize, val: RvData) -> Result<(), BusError> {
        if size != RvSize::Word {
            return Err(BusError::StoreAccessFault);
        }
        self.bits.set(val);
        Ok(())
    }
}

#[derive(Clone, Copy, Default, Eq, Ord, PartialEq, PartialOrd)]
struct IrqPriority {
    // The priority, xored such that the highest priority is always 0
    priority_xored: u8,
    id: u8,
}

struct PicImpl {
    regs: RefCell<PicImplRegs>,

    // levels.get(2) is true if the most recent call to Irq #2's set_level() was
    // high, false if it was low.
    irq_levels: Bits32,

    gw_pending_ff: Bits32,

    /// priority_order[0] is the id/priority of the highest priority Irq,
    /// priority_order[31] is the id/priority of the lowest priority Irq.
    priority_order: Cell<[IrqPriority; 32]>,

    /// id_to_order[1] is the index of Irq #1 in self.priority_order. For example,
    /// if Irq #1 is pending, `self.ordered_irq_pending.get(self.id_to_order[1])` will be true.
    id_to_order: Cell<[u8; 32]>,

    /// ordered_irq_pending.get(0) is true if the highest priority interrupt is
    /// pending and enabled. ordered_irq_pending.get(31) is true if the lowest priority
    /// interrupt is pending and enabled. Look at self.priority_order
    /// to determine their ids.
    ordered_irq_pending: Bits32,

    // The value to xor a priority threshold with before comparing it with
    // IrqPriority::priority_xored
    priority_xor: Cell<u8>,
}
impl PicImpl {
    fn new() -> Self {
        let result = Self {
            regs: RefCell::new(PicImplRegs::new()),

            irq_levels: Bits32::new(),
            gw_pending_ff: Bits32::new(),

            priority_order: Cell::new([IrqPriority::default(); 32]),
            id_to_order: Cell::new([0u8; 32]),
            ordered_irq_pending: Bits32::new(),
            priority_xor: Cell::new(0),
        };
        result.refresh_order();
        result
    }
    fn highest_priority_irq(&self, prithresh: u8) -> Option<u8> {
        assert!(prithresh <= MAX_PRIORITY);
        match self.ordered_irq_pending.first_set_index() {
            Some(idx) => {
                let firing_irq = self.priority_order.get()[usize::from(idx)];
                if firing_irq.priority_xored < prithresh ^ self.priority_xor.get() {
                    Some(firing_irq.id)
                } else {
                    None
                }
            }
            None => None,
        }
    }
    fn irq_set_level(&self, id: u8, mut is_high: bool) {
        let regs = self.regs.borrow();

        self.irq_levels.set(id, is_high);
        let ctrl = regs.meigwctrl[id.into()];
        is_high ^= ctrl.is_set(Meigwctrl::POLARITY);

        if is_high {
            self.gw_pending_ff.set(id, true);
        }

        if ctrl.matches_all(Meigwctrl::TYPE::EdgeTriggered) {
            is_high = self.gw_pending_ff.get(id)
        }
        regs.meip.set(id, is_high);
        self.set_ordered_irq_pending(&regs, id, is_high);
    }
    fn set_ordered_irq_pending(&self, regs: &PicImplRegs, id: u8, is_pending: bool) {
        let enabled = regs.meie[usize::from(id)].is_set(Meie::INTEN);
        self.ordered_irq_pending.set(
            self.id_to_order.get()[usize::from(id)],
            enabled && is_pending,
        );
    }
    fn refresh_gateway(&self, id: u8) {
        self.irq_set_level(id, self.irq_levels.get(id));
    }
    fn refresh_enabled(&self, regs: &PicImplRegs, id: u8) {
        self.set_ordered_irq_pending(regs, id, regs.meip.get(id));
    }
    fn refresh_order(&self) {
        let regs = self.regs.borrow();
        let priority_xor = if regs
            .mpiccfg
            .reg
            .matches_all(Mpiccfg::PRIORITY_ORDER::Reverse)
        {
            0x00
        } else {
            0x0f
        };
        let mut priorities: [IrqPriority; 32] = std::array::from_fn(|i| {
            if i == 0 {
                IrqPriority::default()
            } else {
                IrqPriority {
                    priority_xored: (regs.meipl[i].read(Meipl::PRIORITY) as u8) ^ priority_xor,
                    id: i as u8,
                }
            }
        });
        priorities.sort();
        // priorities is now sorted with the highest priority Irqs at the front
        let mut id_to_order = [0u8; 32];
        for (index, p) in priorities.iter().enumerate() {
            id_to_order[usize::from(p.id)] = u8::try_from(index).unwrap();
        }
        self.priority_xor.set(priority_xor);
        self.priority_order.set(priorities);
        self.id_to_order.set(id_to_order);
        for i in 0..32u8 {
            self.refresh_enabled(&regs, i);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_interrupt_priority_order() {
        let pic = Pic::new();
        let mut regs = pic.mmio_regs(&Clock::new());

        // Register some IRQs; typically these would be given to various peripherals that
        // want to raise IRQ signals
        let irq1 = pic.register_irq(1);
        let irq2 = pic.register_irq(2);
        let irq3 = pic.register_irq(3);

        assert_eq!(pic.highest_priority_irq(0), None);

        // drive irq1 and irq2 lines high
        irq1.set_level(true);
        irq2.set_level(true);

        // No IRQs have been enabled
        assert_eq!(pic.highest_priority_irq(0), None);

        // enable irq2
        regs.write(RvSize::Word, PicMmioRegisters::MEIE_OFFSET + 2 * 4, 1)
            .unwrap();
        assert_eq!(pic.highest_priority_irq(0), None);

        // enable irq1
        regs.write(RvSize::Word, PicMmioRegisters::MEIE_OFFSET + 4, 1)
            .unwrap();
        assert_eq!(pic.highest_priority_irq(0), None);

        // Set the priority of irq2 from 0 to 1 (0 was disabled)
        regs.write(RvSize::Word, PicMmioRegisters::MEIPL_OFFSET + 2 * 4, 1)
            .unwrap();
        // irq2 is the highest priority firing interrupt
        assert_eq!(pic.highest_priority_irq(0), Some(2));

        // Set the priority of irq1 from 0 to 1 (0 was disabled)
        regs.write(RvSize::Word, PicMmioRegisters::MEIPL_OFFSET + 4, 1)
            .unwrap();
        // When two pending irqs have the same priority, the one with the lower id wins.
        assert_eq!(pic.highest_priority_irq(0), Some(1));

        // Reverse priorities (0 is the highest)
        regs.write(RvSize::Word, PicMmioRegisters::MPICCFG_OFFSET, 1)
            .unwrap();
        assert_eq!(pic.highest_priority_irq(15), Some(1));

        // Go back to normal priority order (15 is the highest)
        regs.write(RvSize::Word, PicMmioRegisters::MPICCFG_OFFSET, 0)
            .unwrap();
        assert_eq!(pic.highest_priority_irq(0), Some(1));

        // raise priority of irq2 to 2
        regs.write(RvSize::Word, PicMmioRegisters::MEIPL_OFFSET + 2 * 4, 2)
            .unwrap();
        assert_eq!(pic.highest_priority_irq(0), Some(2));

        // Reverse priorities (0 is the highest)
        regs.write(RvSize::Word, PicMmioRegisters::MPICCFG_OFFSET, 1)
            .unwrap();
        assert_eq!(pic.highest_priority_irq(15), Some(1));

        // Go back to normal priority order (15 is the highest)
        regs.write(RvSize::Word, PicMmioRegisters::MPICCFG_OFFSET, 0)
            .unwrap();
        assert_eq!(pic.highest_priority_irq(0), Some(2));

        // raise priority of irq1 to 2
        regs.write(RvSize::Word, PicMmioRegisters::MEIPL_OFFSET + 4, 2)
            .unwrap();
        assert_eq!(pic.highest_priority_irq(0), Some(1));

        // raise priority of irq3 to 15 (even though it is not firing yet)
        regs.write(RvSize::Word, PicMmioRegisters::MEIPL_OFFSET + 3 * 4, 15)
            .unwrap();
        assert_eq!(pic.highest_priority_irq(0), Some(1));

        // enable irq3 (but the signal isn't high yet)
        regs.write(RvSize::Word, PicMmioRegisters::MEIE_OFFSET + 3 * 4, 1)
            .unwrap();
        assert_eq!(pic.highest_priority_irq(0), Some(1));

        // set irq3 high
        irq3.set_level(true);
        assert_eq!(pic.highest_priority_irq(0), Some(3));
        assert_eq!(pic.highest_priority_irq(14), Some(3));
        assert_eq!(pic.highest_priority_irq(15), None);

        irq3.set_level(false);
        assert_eq!(pic.highest_priority_irq(0), Some(1));
        assert_eq!(pic.highest_priority_irq(1), Some(1));
        assert_eq!(pic.highest_priority_irq(2), None);

        irq1.set_level(false);
        assert_eq!(pic.highest_priority_irq(0), Some(2));
        assert_eq!(pic.highest_priority_irq(1), Some(2));
        assert_eq!(pic.highest_priority_irq(2), None);

        irq2.set_level(false);
        assert_eq!(pic.highest_priority_irq(0), None);
    }
}
