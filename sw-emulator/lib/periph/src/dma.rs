/*++

Licensed under the Apache-2.0 license.

File Name:

dma.rs

Abstract:

File contains DMA peripheral implementation.

--*/

use crate::MailboxRam;
use caliptra_emu_bus::{
    ActionHandle, Bus, BusError, Clock, ReadOnlyRegister, ReadWriteRegister, Timer,
    WriteOnlyRegister,
};
use caliptra_emu_derive::Bus;
use caliptra_emu_types::{RvAddr, RvData, RvSize};
use std::borrow::BorrowMut;
use std::collections::VecDeque;
use tock_registers::interfaces::{ReadWriteable, Readable, Writeable};
use tock_registers::register_bitfields;

pub mod axi_root_bus;
use axi_root_bus::{AxiAddr, AxiRootBus};

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
            AXI_RD = 0b11,
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
#[poll_fn(poll)]
pub struct Dma {
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
    #[register(offset = 0x0000_000c, read_fn = on_read_status0)]
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

    /// Operation complete callback
    op_complete_action: Option<ActionHandle>,

    /// FIFO
    fifo: VecDeque<u8>,

    /// Axi Bus
    pub axi: AxiRootBus,

    /// Mailbox
    mailbox: MailboxRam,
}

struct ReadXfer {
    pub src: AxiAddr,
    pub fixed: bool,
    pub len: usize,
}

struct WriteXfer {
    pub dest: AxiAddr,
    pub fixed: bool,
    pub len: usize,
}

impl Dma {
    const NAME: u32 = 0x6776_8068; // CLPD

    const FIFO_SIZE: usize = 0x1000;

    // [TODO][CAP2] DMA transactions need to be a multiple of this
    const AXI_DATA_WIDTH: usize = 4;

    const DMA_CLOCKS_PER_WORD: u64 = 4;

    pub fn new(clock: &Clock, mailbox: MailboxRam) -> Self {
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
            op_complete_action: None,
            fifo: VecDeque::with_capacity(Self::FIFO_SIZE),
            axi: AxiRootBus::new(),
            mailbox,
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

            self.op_complete_action = Some(
                self.timer
                    .schedule_poll_in(Self::DMA_CLOCKS_PER_WORD * self.byte_count.reg.get() as u64),
            );
            self.status0
                .reg
                .write(Status0::BUSY::SET + Status0::DMA_FSM_PRESENT_STATE::WAIT_DATA);
        }

        Ok(())
    }

    fn on_read_status0(&mut self, size: RvSize) -> Result<RvData, BusError> {
        if size != RvSize::Word {
            Err(BusError::LoadAccessFault)?
        }

        let status0 = ReadWriteRegister::new(self.status0.reg.get());
        status0
            .reg
            .modify(Status0::FIFO_DEPTH.val(self.fifo.len() as u32));
        Ok(status0.reg.get())
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

    fn read_xfer(&self) -> ReadXfer {
        assert!(self.byte_count.reg.get() % Self::AXI_DATA_WIDTH as u32 == 0);
        ReadXfer {
            src: ((self.src_addr_h.reg.get() as u64) << 32) | self.src_addr_l.reg.get() as u64,
            fixed: self.control.reg.is_set(Control::READ_ADDR_FIXED),
            len: self.byte_count.reg.get() as usize,
        }
    }

    fn write_xfer(&self) -> WriteXfer {
        assert!(self.byte_count.reg.get() % Self::AXI_DATA_WIDTH as u32 == 0);
        WriteXfer {
            dest: ((self.dest_addr_h.reg.get() as u64) << 32) | self.dest_addr_l.reg.get() as u64,
            fixed: self.control.reg.is_set(Control::WRITE_ADDR_FIXED),
            len: self.byte_count.reg.get() as usize,
        }
    }

    fn axi_to_mailbox(&mut self) {
        let xfer = self.read_xfer();
        let mbox_ram = self.mailbox.borrow_mut();

        for i in (0..xfer.len).step_by(Self::AXI_DATA_WIDTH) {
            let addr = xfer.src + if xfer.fixed { 0 } else { i as AxiAddr };
            let data = self.axi.read(Self::AXI_DATA_WIDTH.into(), addr).unwrap();
            mbox_ram
                .write(Self::AXI_DATA_WIDTH.into(), i as RvAddr, data as RvData)
                .unwrap();
        }
    }

    fn axi_to_fifo(&mut self) {
        let xfer = self.read_xfer();

        for i in (0..xfer.len).step_by(Self::AXI_DATA_WIDTH) {
            let addr = xfer.src + if xfer.fixed { 0 } else { i as AxiAddr };
            let cur_fifo_depth = self.status0.reg.read(Status0::FIFO_DEPTH);
            if cur_fifo_depth + 4 >= Self::FIFO_SIZE as u32 {
                self.status0.reg.write(Status0::ERROR::SET);
                // TODO set interrupt bits
                return;
            }
            let data = self.axi.read(Self::AXI_DATA_WIDTH.into(), addr).unwrap();
            let data_bytes = data.to_le_bytes();
            data_bytes[..Self::AXI_DATA_WIDTH]
                .iter()
                .for_each(|b| self.fifo.push_back(*b));
        }
    }

    fn axi_to_axi(&mut self) {
        let read_xfer = self.read_xfer();
        let write_xfer = self.write_xfer();

        for i in (0..read_xfer.len).step_by(Self::AXI_DATA_WIDTH) {
            let src = read_xfer.src + if read_xfer.fixed { 0 } else { i as AxiAddr };
            let dest = write_xfer.dest + if write_xfer.fixed { 0 } else { i as AxiAddr };
            let data = self.axi.read(Self::AXI_DATA_WIDTH.into(), src).unwrap();
            self.axi
                .write(Self::AXI_DATA_WIDTH.into(), dest, data)
                .unwrap();
        }
    }

    fn mailbox_to_axi(&mut self) {
        let xfer = self.write_xfer();
        let mbox_ram = self.mailbox.borrow_mut();

        for i in (0..xfer.len).step_by(Self::AXI_DATA_WIDTH) {
            let addr = xfer.dest + if xfer.fixed { 0 } else { i as AxiAddr };
            let data = mbox_ram
                .read(Self::AXI_DATA_WIDTH.into(), i as RvAddr)
                .unwrap();
            self.axi
                .write(Self::AXI_DATA_WIDTH.into(), addr, data)
                .unwrap();
        }
    }

    fn fifo_to_axi(&mut self) {
        let xfer = self.write_xfer();
        for i in (0..xfer.len).step_by(Self::AXI_DATA_WIDTH) {
            let addr = xfer.dest + if xfer.fixed { 0 } else { i as AxiAddr };
            let data = {
                let mut bytes = [0u8; Self::AXI_DATA_WIDTH];
                for byte in bytes.iter_mut() {
                    match self.fifo.pop_front() {
                        Some(b) => {
                            *byte = b;
                        }
                        None => {
                            self.status0.reg.write(Status0::ERROR::SET);
                            // TODO set interrupt bits
                            return;
                        }
                    }
                }
                u32::from_le_bytes(bytes)
            };
            self.axi
                .write(Self::AXI_DATA_WIDTH.into(), addr, data)
                .unwrap();
        }
    }

    fn op_complete(&mut self) {
        let read_target = self.control.reg.read_as_enum(Control::READ_ROUTE).unwrap();
        let write_origin = self.control.reg.read_as_enum(Control::WRITE_ROUTE).unwrap();

        match (read_target, write_origin) {
            (Control::READ_ROUTE::Value::MAILBOX, Control::WRITE_ROUTE::Value::DISABLE) => {
                self.axi_to_mailbox()
            }
            (Control::READ_ROUTE::Value::AHB_FIFO, Control::WRITE_ROUTE::Value::DISABLE) => {
                self.axi_to_fifo()
            }
            (Control::READ_ROUTE::Value::AXI_WR, Control::WRITE_ROUTE::Value::AXI_RD) => {
                self.axi_to_axi()
            }
            (Control::READ_ROUTE::Value::DISABLE, Control::WRITE_ROUTE::Value::MAILBOX) => {
                self.mailbox_to_axi()
            }
            (Control::READ_ROUTE::Value::DISABLE, Control::WRITE_ROUTE::Value::AHB_FIFO) => {
                self.fifo_to_axi()
            }
            (_, _) => panic!("Invalid read/write DMA combination"),
        }

        self.status0
            .reg
            .modify(Status0::BUSY::CLEAR + Status0::DMA_FSM_PRESENT_STATE::DONE);
    }

    fn poll(&mut self) {
        if self.timer.fired(&mut self.op_complete_action) {
            self.op_complete();
        }
    }
}

#[cfg(test)]
mod tests {
    use tock_registers::registers::InMemoryRegister;

    use super::*;

    const AXI_TEST_OFFSET: AxiAddr = 0xaa00;

    const CTRL_OFFSET: RvAddr = 0x8;
    const STATUS0_OFFSET: RvAddr = 0xc;
    const SRC_ADDR_L_OFFSET: RvAddr = 0x14;
    const SRC_ADDR_H_OFFSET: RvAddr = 0x18;
    const DST_ADDR_L_OFFSET: RvAddr = 0x1c;
    const DST_ADDR_H_OFFSET: RvAddr = 0x20;
    const BYTE_COUNT_OFFSET: RvAddr = 0x24;
    const WRITE_DATA_OFFSET: RvAddr = 0x2c;
    const READ_DATA_OFFSET: RvAddr = 0x30;

    fn dma_read_u32(dma: &mut Dma, clock: &Clock, addr: AxiAddr) -> u32 {
        let ctrl = InMemoryRegister::<u32, Control::Register>::new(0);
        ctrl.modify(Control::FLUSH::SET);
        dma.write(RvSize::Word, CTRL_OFFSET, ctrl.get()).unwrap();

        let ctrl = InMemoryRegister::<u32, Control::Register>::new(0);
        ctrl.modify(Control::READ_ROUTE::AHB_FIFO);
        dma.write(RvSize::Word, CTRL_OFFSET, ctrl.get()).unwrap();

        dma.write(RvSize::Word, SRC_ADDR_L_OFFSET, addr as RvAddr)
            .unwrap();
        dma.write(RvSize::Word, SRC_ADDR_H_OFFSET, (addr >> 32) as RvAddr)
            .unwrap();

        dma.write(RvSize::Word, BYTE_COUNT_OFFSET, Dma::AXI_DATA_WIDTH as u32)
            .unwrap();

        // Launch transaction
        ctrl.modify(Control::GO::SET);
        dma.write(RvSize::Word, CTRL_OFFSET, ctrl.get()).unwrap();

        while {
            let status0 = dma.read(RvSize::Word, STATUS0_OFFSET).unwrap();
            let status0 = InMemoryRegister::<u32, Status0::Register>::new(status0);
            status0.is_set(Status0::BUSY)
        } {
            clock.increment_and_process_timer_actions(1, dma);
        }

        dma.read(RvSize::Word, READ_DATA_OFFSET).unwrap()
    }

    fn dma_write_u32(dma: &mut Dma, clock: &Clock, addr: AxiAddr, data: RvData) {
        let ctrl = InMemoryRegister::<u32, Control::Register>::new(0);
        ctrl.modify(Control::FLUSH::SET);
        dma.write(RvSize::Word, CTRL_OFFSET, ctrl.get()).unwrap();

        dma.write(RvSize::Word, WRITE_DATA_OFFSET, data).unwrap();

        dma.write(RvSize::Word, DST_ADDR_L_OFFSET, addr as RvAddr)
            .unwrap();
        dma.write(RvSize::Word, DST_ADDR_H_OFFSET, (addr >> 32) as RvAddr)
            .unwrap();

        let ctrl = InMemoryRegister::<u32, Control::Register>::new(0);
        ctrl.modify(Control::WRITE_ROUTE::AHB_FIFO);
        dma.write(RvSize::Word, CTRL_OFFSET, ctrl.get()).unwrap();

        dma.write(RvSize::Word, BYTE_COUNT_OFFSET, Dma::AXI_DATA_WIDTH as u32)
            .unwrap();

        // Launch transaction
        ctrl.modify(Control::GO::SET);
        dma.write(RvSize::Word, CTRL_OFFSET, ctrl.get()).unwrap();

        while {
            let status0 = dma.read(RvSize::Word, STATUS0_OFFSET).unwrap();
            let status0 = InMemoryRegister::<u32, Status0::Register>::new(status0);
            status0.is_set(Status0::BUSY)
        } {
            clock.increment_and_process_timer_actions(1, dma);
        }
    }

    #[test]
    fn test_dma_fifo_read_write() {
        let clock = Clock::new();
        let mbox_ram = MailboxRam::new();
        let mut dma = Dma::new(&clock, mbox_ram);

        assert_eq!(dma_read_u32(&mut dma, &clock, AXI_TEST_OFFSET), 0xaabbccdd); // Initial test value
        let test_value = 0xdeadbeef;
        dma_write_u32(&mut dma, &clock, AXI_TEST_OFFSET, test_value);
        assert_eq!(dma_read_u32(&mut dma, &clock, AXI_TEST_OFFSET), test_value);
    }
}
