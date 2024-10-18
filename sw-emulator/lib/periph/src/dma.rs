/*++

Licensed under the Apache-2.0 license.

File Name:

dma.rs

Abstract:

File contains DMA peripheral implementation.

--*/

use caliptra_emu_bus::{
    Bus, BusError, Clock, ReadOnlyRegister, ReadWriteRegister, Timer, TimerAction,
    WriteOnlyRegister,
};
use caliptra_emu_derive::Bus;
use caliptra_emu_types::{RvAddr, RvData, RvSize};
use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;
use tock_registers::interfaces::{ReadWriteable, Readable, Writeable};
use tock_registers::register_bitfields;

use crate::CaliptraRootBus;

#[derive(Clone)]
pub struct Dma {
    regs: Rc<RefCell<DmaRegs>>,
}

impl Dma {
    pub fn new(clock: &Clock) -> Self {
        Self {
            regs: Rc::new(RefCell::new(DmaRegs::new(clock))),
        }
    }

    pub fn do_dma_handling(&mut self, root_bus: &mut CaliptraRootBus) {
        self.regs.borrow_mut().do_dma_handling(root_bus)
    }
}

impl Bus for Dma {
    /// Read data of specified size from given address
    fn read(&mut self, size: RvSize, addr: RvAddr) -> Result<RvData, BusError> {
        self.regs.borrow_mut().read(size, addr)
    }

    /// Write data of specified size to given address
    fn write(&mut self, size: RvSize, addr: RvAddr, val: RvData) -> Result<(), BusError> {
        self.regs.borrow_mut().write(size, addr, val)
    }
}

register_bitfields! [
    u32,

    /// Capabilities
    Capabilites [
        MAX_FIFO_DEPTH OFFSET(0) NUMBITS(12) [], // TODO?
    ],

    /// Control
    Control [
        GO OFFSET(0) NUMBITS(1) [],
        FLUSH OFFSET(1) NUMBITS(1) [],
        READ_ROUTE OFFSET(16) NUMBITS(2) [
            DISABLE = 0b00,
            MAILBOX = 0b01,
            AHB_FIFO = 0b10,
            AXI_WR = 0b11,
        ],
        READ_ADDR_FIXED OFFSET(20) NUMBITS(1) [],
        WRITE_ROUTE OFFSET(24) NUMBITS(2) [
            DISABLE = 0b00,
            MAILBOX = 0b01,
            AHB_FIFO = 0b10,
            AXI_WR = 0b11,
        ],
        WRITE_ADDR_FIXED OFFSET(28) NUMBITS(1) [],
    ],

    /// Status 0
    Status0 [
        BUSY OFFSET(0) NUMBITS(1) [], // 0 = ready to accept transfer request, 1 = operation in progress
        ERROR OFFSET(1) NUMBITS(1) [],
        FIFO_DEPTH OFFSET(4) NUMBITS(12) [],
        DMA_FSM_PRESENT_STATE OFFSET(16) NUMBITS(2) [
            IDLE = 0b00,
            WAIT_DATA = 0b01,
            DONE = 0b10,
            ERROR = 0b11,
        ]
    ],

    /// Block Size
    BlockSize [
        BLOCK_SIZE OFFSET(0) NUMBITS(12) [],
    ],
];

#[derive(Bus)]
pub struct DmaRegs {
    /// ID
    #[register(offset = 0x0000_0000)]
    name: ReadOnlyRegister<u32>,

    /// Capabilities
    #[register(offset = 0x0000_0004)]
    capabilities: ReadOnlyRegister<u32>,

    /// Control
    #[register(offset = 0x0000_0008, write_fn = on_write_control)]
    control: ReadWriteRegister<u32, Control::Register>,

    /// Status 0
    #[register(offset = 0x0000_000c)]
    status0: ReadOnlyRegister<u32, Status0::Register>,

    /// Status 1: Reports remaining byte count that must be sent to destination.
    #[register(offset = 0x0000_0010)]
    status1: ReadOnlyRegister<u32>,

    /// Source Address Low
    #[register(offset = 0x0000_0014)]
    src_addr_l: ReadWriteRegister<u32>,

    /// Source Address High
    #[register(offset = 0x0000_0018)]
    src_addr_h: ReadWriteRegister<u32>,

    /// Destination Address Low
    #[register(offset = 0x0000_001c)]
    dest_addr_l: ReadWriteRegister<u32>,

    /// Destination Address High
    #[register(offset = 0x0000_0020)]
    dest_addr_h: ReadWriteRegister<u32>,

    /// Byte count
    #[register(offset = 0x0000_0024)]
    byte_count: ReadWriteRegister<u32>,

    /// Block size
    #[register(offset = 0x0000_0028)]
    block_size: ReadWriteRegister<u32, BlockSize::Register>,

    /// Write Data
    #[register(offset = 0x0000_002c, write_fn = on_write_data)]
    write_data: WriteOnlyRegister<u32>,

    /// Read Data
    #[register(offset = 0x0000_0030, read_fn = on_read_data)]
    read_data: ReadOnlyRegister<u32>,

    // TODO interrupt block
    /// Timer
    timer: Timer,

    /// FIFO
    fifo: VecDeque<u8>,
}

impl DmaRegs {
    const NAME: u32 = 0x6776_8068; // CLPD

    const RRI_BASE: u32 = 0x1003_8000; // TODO
    const RRI_FIFO_OFFSET: u32 = 0x6c;

    const FIFO_SIZE: usize = 0x1000;

    const DMA_CLOCKS_PER_WORD: u64 = 4;

    pub fn new(clock: &Clock) -> Self {
        Self {
            name: ReadOnlyRegister::new(Self::NAME),
            capabilities: ReadOnlyRegister::new(Self::FIFO_SIZE as u32 - 1), // MAX FIFO DEPTH
            control: ReadWriteRegister::new(0),
            status0: ReadOnlyRegister::new(0),
            status1: ReadOnlyRegister::new(0),
            src_addr_l: ReadWriteRegister::new(0),
            src_addr_h: ReadWriteRegister::new(0),
            dest_addr_l: ReadWriteRegister::new(0),
            dest_addr_h: ReadWriteRegister::new(0),
            byte_count: ReadWriteRegister::new(0),
            block_size: ReadWriteRegister::new(0),
            write_data: WriteOnlyRegister::new(0),
            read_data: ReadOnlyRegister::new(0),
            timer: Timer::new(clock),
            fifo: VecDeque::with_capacity(Self::FIFO_SIZE),
        }
    }

    pub fn on_write_control(&mut self, size: RvSize, val: RvData) -> Result<(), BusError> {
        // Write have to be words
        if size != RvSize::Word {
            Err(BusError::StoreAccessFault)?
        }

        self.control.reg.set(val);

        // TODO not clear if this should clear
        if self.control.reg.is_set(Control::FLUSH) {
            self.fifo.clear();
            self.status0.reg.write(Status0::DMA_FSM_PRESENT_STATE::IDLE);
            self.control.reg.set(0);
        }

        if self.control.reg.is_set(Control::GO) {
            if self.status0.reg.read(Status0::DMA_FSM_PRESENT_STATE)
                == Status0::DMA_FSM_PRESENT_STATE::WAIT_DATA.value
            {
                // TODO write interrupt field
                todo!();
            }

            self.timer.schedule_action_in(
                Self::DMA_CLOCKS_PER_WORD * self.byte_count.reg.get() as u64,
                TimerAction::DmaAction,
            );
            self.status0
                .reg
                .write(Status0::BUSY::SET + Status0::DMA_FSM_PRESENT_STATE::WAIT_DATA);
        }

        Ok(())
    }

    pub fn on_write_data(&mut self, size: RvSize, val: RvData) -> Result<(), BusError> {
        let bytes = &val.to_le_bytes();
        bytes[..size as usize]
            .iter()
            .for_each(|b| self.fifo.push_back(*b));
        Ok(())
    }

    pub fn on_read_data(&mut self, size: RvSize) -> Result<RvData, BusError> {
        let range = 0..size as usize;
        let bytes: RvData = range.fold(0, |mut acc, b| {
            acc |= (self.fifo.pop_front().unwrap_or(
                // self.status0
                //     .reg
                //     .write(Status0::DMA_FSM_PRESENT_STATE::ERROR);
                // TODO write status in interrupt
                0,
            ) as RvData)
                << (8 * b);
            acc
        });
        Ok(bytes)
    }

    fn write_to_mailbox(&mut self, data: Vec<u8>, root_bus: &mut CaliptraRootBus) {
        let mailbox = &mut root_bus.mailbox;
        let mailbox_regs = &mut mailbox.mailbox_regs();
        let mut mailbox_regs = mailbox_regs.borrow_mut();
        // TODO does the CMD matter?
        mailbox_regs.write_cmd(RvSize::Word, 0xdeadbeef).unwrap();
        mailbox_regs
            .write_dlen(RvSize::Word, self.byte_count.reg.get())
            .unwrap();

        //        assert_eq!(data.len(), self.byte_count.reg.get() as usize);

        data.chunks(RvSize::Word as usize).for_each(|c| {
            mailbox_regs
                .write_din(RvSize::Word, u32::from_le_bytes(c.try_into().unwrap()))
                .unwrap()
        });
    }

    pub fn do_dma_handling(&mut self, root_bus: &mut CaliptraRootBus) {
        // DMA reads
        let read_addr_fixed = self.control.reg.is_set(Control::READ_ADDR_FIXED);
        let read_addr = self.src_addr_l.reg.get();
        assert_eq!(self.src_addr_h.reg.get(), 0); // 32bit
        let read_data =
                // Special case for putting stuff image in the mailbox from recovery register interface
                if read_addr == Self::RRI_BASE + Self::RRI_FIFO_OFFSET && read_addr_fixed {
                    if let Some(data) = root_bus.recovery.cms_data.clone() {
                        (*data).clone()
                    } else {
                        vec![]
                    }
                } else {
                    let range = read_addr..read_addr + self.byte_count.reg.get();
                    range
                        .step_by(RvSize::Word as usize)
                        .flat_map(|offset| {
                            let read_offset = if read_addr_fixed { read_addr } else { offset };
                            root_bus
                                .read(RvSize::Word, read_offset)
                                .unwrap()
                                .to_le_bytes()
                        }).collect()
                };
        match self.control.reg.read_as_enum(Control::READ_ROUTE) {
            Some(Control::READ_ROUTE::Value::MAILBOX) => {
                self.write_to_mailbox(read_data, root_bus);
            }
            Some(Control::READ_ROUTE::Value::AHB_FIFO) => {
                if self.fifo.len() + read_data.len() > Self::FIFO_SIZE {
                    self.status0
                        .reg
                        .write(Status0::DMA_FSM_PRESENT_STATE::ERROR);
                    read_data[..Self::FIFO_SIZE - self.fifo.len()]
                        .iter()
                        .for_each(|b| self.fifo.push_back(*b));
                } else {
                    read_data.iter().for_each(|b| self.fifo.push_back(*b));
                }
                self.status0
                    .reg
                    .modify(Status0::FIFO_DEPTH.val(self.fifo.len() as u32));
            }
            Some(Control::READ_ROUTE::Value::AXI_WR) => {
                todo!()
            }
            _ => {}
        }

        // DMA writes
        let write_addr_fixed = self.control.reg.is_set(Control::WRITE_ADDR_FIXED);
        let write_addr = self.dest_addr_l.reg.get();
        assert_eq!(self.dest_addr_h.reg.get(), 0); // 32bit
        match self.control.reg.read_as_enum(Control::WRITE_ROUTE) {
            Some(Control::WRITE_ROUTE::Value::MAILBOX) => todo!(),
            Some(Control::WRITE_ROUTE::Value::AHB_FIFO) => {
                let to_send = self
                    .fifo
                    .drain(0..self.byte_count.reg.get() as usize)
                    .collect::<Vec<u8>>();

                to_send.chunks(4).enumerate().for_each(|(i, b)| {
                    let word = u32::from_le_bytes(b.try_into().unwrap());
                    let addr = if write_addr_fixed {
                        0
                    } else {
                        write_addr + 4 * i as u32
                    };
                    root_bus
                        .write(RvSize::Word, addr as RvAddr, word as RvData)
                        .unwrap();
                });
            }
            Some(Control::WRITE_ROUTE::Value::AXI_WR) => todo!(),

            _ => {}
        }

        self.status0
            .reg
            .modify(Status0::BUSY::CLEAR + Status0::DMA_FSM_PRESENT_STATE::DONE);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NAME_OFFSET: u32 = 0;
    const NAME_VAL: u32 = 0x6776_8068;
    const CAPABILITIES_OFFSET: u32 = 4;

    #[test]
    fn test_name() {
        let clock = Clock::new();
        let mut dma = Dma::new(&clock);

        let name = dma.read(RvSize::Word, NAME_OFFSET).unwrap();
        assert_eq!(name, NAME_VAL);
    }

    #[test]
    fn test_capabilities() {
        let clock = Clock::new();
        let mut dma = Dma::new(&clock);

        let capabilities = dma.read(RvSize::Word, CAPABILITIES_OFFSET).unwrap();
        assert_eq!(capabilities, 0xfff);
    }
}
