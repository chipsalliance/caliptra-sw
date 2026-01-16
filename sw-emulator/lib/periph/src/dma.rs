/*++

Licensed under the Apache-2.0 license.

File Name:

dma.rs

Abstract:

File contains DMA peripheral implementation.

--*/

use crate::helpers::words_from_bytes_le;
use crate::{mci::Mci, Aes, MailboxRam, Sha512Accelerator, SocRegistersInternal};
use caliptra_emu_bus::{
    ActionHandle, Bus, BusError, Clock, Event, ReadOnlyRegister, ReadWriteRegister, Timer,
    WriteOnlyRegister,
};
use caliptra_emu_derive::Bus;
use caliptra_emu_types::{RvAddr, RvData, RvSize};
use std::borrow::BorrowMut;
use std::collections::VecDeque;
use std::rc::Rc;
use std::sync::mpsc;
use tock_registers::interfaces::{ReadWriteable, Readable, Writeable};
use tock_registers::register_bitfields;

pub mod axi_root_bus;
use axi_root_bus::{AxiAddr, AxiRootBus};
pub mod encryption_engine;
pub mod otp_fc;
pub mod recovery;

const RECOVERY_STATUS_OFFSET: u64 = 0x40;
const AWATING_RECOVERY_IMAGE: u32 = 0x1;

/// The number of CPU clock cycles it takes to receive the payload from the DMA.
const PAYLOAD_AVAILABLE_OP_TICKS: u64 = 1000;

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
        AES_MODE_EN OFFSET(2) NUMBITS(1) [],
        AES_GCM_MODE OFFSET(3) NUMBITS(1) [],
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
        RESERVED OFFSET(2) NUMBITS(2) [],
        FIFO_DEPTH OFFSET(4) NUMBITS(12) [],
        DMA_FSM_PRESENT_STATE OFFSET(16) NUMBITS(2) [
            IDLE = 0b00,
            WAIT_DATA = 0b01,
            DONE = 0b10,
            ERROR = 0b11,
        ],
        PAYLOAD_AVAILABLE OFFSET(18) NUMBITS(1) [],
        IMAGE_ACTIVATED OFFSET(19) NUMBITS(1) [],
        RESERVED2 OFFSET(20) NUMBITS(12) [],
    ],

    /// Block Size
    BlockSize [
        BLOCK_SIZE OFFSET(0) NUMBITS(12) [],
    ],
];

#[derive(Bus)]
#[poll_fn(poll)]
#[incoming_event_fn(incoming_event)]
#[register_outgoing_events_fn(register_outgoing_events)]
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

    /// Payload available callback
    op_payload_available_action: Option<ActionHandle>,

    /// FIFO
    fifo: VecDeque<u32>,

    /// Axi Bus
    pub axi: AxiRootBus,

    /// Mailbox
    mailbox: MailboxRam,

    /// AES peripheral
    aes: Aes,

    // Ongoing DMA operations
    pending_axi_to_axi: Option<WriteXfer>,
    pending_axi_to_fifo: bool,
    pending_axi_to_mailbox: bool,

    // If true, the recovery interface in the MCU will be used,
    // otherwise, the local recovery interface is used.
    use_mcu_recovery_interface: bool,
}

#[derive(Debug)]
struct ReadXfer {
    pub src: AxiAddr,
    pub fixed: bool,
    pub len: usize,
}

#[derive(Debug)]

struct WriteXfer {
    pub dest: AxiAddr,
    pub fixed: bool,
    pub len: usize,
}

impl Dma {
    const NAME: u32 = 0x6776_8068; // CLPD

    const FIFO_SIZE: usize = 0x400;

    // [TODO][CAP2] DMA transactions need to be a multiple of this
    const AXI_DATA_WIDTH: usize = 4;

    // How many cycles it takes for a DMA transfer, per word
    const DMA_CYCLES_PER_WORD: u64 = 1;
    // Minimum number of cycles for a DMA transfer.
    const DMA_CYCLES_MIN: u64 = 16;

    #[allow(clippy::too_many_arguments)]
    pub fn new(
        clock: &Clock,
        mailbox: MailboxRam,
        soc_reg: SocRegistersInternal,
        sha512_acc: Sha512Accelerator,
        mci: Mci,
        aes: Aes,
        test_sram: Option<&[u8]>,
        use_mcu_recovery_interface: bool,
    ) -> Self {
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
            op_payload_available_action: None,
            fifo: VecDeque::with_capacity(Self::FIFO_SIZE),
            axi: AxiRootBus::new(
                soc_reg,
                sha512_acc,
                mci,
                test_sram,
                use_mcu_recovery_interface,
            ),
            mailbox,
            aes,
            pending_axi_to_axi: None,
            pending_axi_to_fifo: false,
            pending_axi_to_mailbox: false,
            use_mcu_recovery_interface,
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

        if self.control.reg.is_set(Control::GO) && self.op_complete_action.is_none() {
            if self.status0.reg.read(Status0::DMA_FSM_PRESENT_STATE)
                == Status0::DMA_FSM_PRESENT_STATE::WAIT_DATA.value
            {
                // TODO write interrupt field
                todo!();
            }

            self.op_complete_action = Some(
                self.timer.schedule_poll_in(
                    (Self::DMA_CYCLES_PER_WORD * self.byte_count.reg.get() as u64 / 4)
                        .max(Self::DMA_CYCLES_MIN),
                ),
            );
            self.status0
                .reg
                .write(Status0::BUSY::SET + Status0::DMA_FSM_PRESENT_STATE::WAIT_DATA);
        }

        // clear the go and flush bits
        self.control
            .reg
            .modify(Control::GO::CLEAR + Control::FLUSH::CLEAR);

        Ok(())
    }

    fn on_read_status0(&mut self, size: RvSize) -> Result<RvData, BusError> {
        if size != RvSize::Word {
            Err(BusError::LoadAccessFault)?
        }

        let status0 = ReadWriteRegister::new(self.status0.reg.get());
        status0.reg.modify(
            Status0::FIFO_DEPTH.val((self.fifo.len() as u32 * 4).min(Status0::FIFO_DEPTH.mask)), // don't overflow bitfield
        );

        if self.use_mcu_recovery_interface {
            self.axi.send_get_recovery_indirect_fifo_status();
            if self.axi.get_recovery_indirect_fifo_status() != 0 {
                status0.reg.modify(Status0::PAYLOAD_AVAILABLE::SET);
            } else {
                status0.reg.modify(Status0::PAYLOAD_AVAILABLE::CLEAR);
            }
        }

        Ok(status0.reg.get())
    }

    pub fn on_write_data(&mut self, size: RvSize, val: RvData) -> Result<(), BusError> {
        match size {
            RvSize::Word => {
                self.fifo.push_back(val);
                Ok(())
            }
            _ => Err(BusError::StoreAccessFault),
        }
    }

    pub fn on_read_data(&mut self, size: RvSize) -> Result<RvData, BusError> {
        match size {
            // TODO write status in interrupt if empty
            RvSize::Word => Ok(self.fifo.pop_front().unwrap_or(0)),
            _ => Err(BusError::LoadAccessFault),
        }
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

    // Returns true if this completed immediately.
    fn axi_to_mailbox(&mut self) -> bool {
        let xfer = self.read_xfer();

        // check if we have to do the read async
        if self.axi.must_schedule(xfer.src) {
            self.pending_axi_to_mailbox = true;
            self.timer.schedule_poll_in(1);
            self.axi.schedule_read(xfer.src, xfer.len as u32).unwrap();
            return false;
        }

        let block = self.read_axi_block(xfer);
        self.write_mailbox(&block);
        true
    }

    fn write_mailbox(&mut self, block: &[u32]) {
        let mbox_ram = self.mailbox.borrow_mut();
        for i in (0..block.len() * 4).step_by(Self::AXI_DATA_WIDTH) {
            let data = block[i / 4];
            mbox_ram
                .write(Self::AXI_DATA_WIDTH.into(), i as RvAddr, data as RvData)
                .unwrap();
        }
    }

    // Returns true if this completed immediately.
    fn axi_to_fifo(&mut self) -> bool {
        let xfer = self.read_xfer();

        // check if we have to do the read async
        if self.axi.must_schedule(xfer.src) {
            self.pending_axi_to_fifo = true;
            self.timer.schedule_poll_in(1);
            self.axi.schedule_read(xfer.src, xfer.len as u32).unwrap();
            return false;
        }

        let block = self.read_axi_block(xfer);
        self.write_fifo_block(&block);
        true
    }

    fn write_fifo_block(&mut self, block: &[u32]) {
        for i in (0..block.len() * 4).step_by(Self::AXI_DATA_WIDTH) {
            let cur_fifo_depth = self.status0.reg.read(Status0::FIFO_DEPTH);
            if cur_fifo_depth >= Self::FIFO_SIZE as u32 {
                self.status0.reg.write(Status0::ERROR::SET);
                // TODO set interrupt bits
                return;
            }
            self.fifo.push_back(block[i / 4]);
        }
    }

    // Returns true if this completed immediately.
    fn axi_to_axi(&mut self) -> bool {
        let read_xfer = self.read_xfer();
        let write_xfer = self.write_xfer();

        // check if we have to do the read async
        if self.axi.must_schedule(read_xfer.src) {
            self.pending_axi_to_axi = Some(write_xfer);
            self.timer.schedule_poll_in(1);
            self.axi
                .schedule_read(read_xfer.src, read_xfer.len as u32)
                .unwrap();
            return false;
        }
        let data = self.read_axi_block(read_xfer);
        self.write_axi_block(&data, write_xfer);
        true
    }

    fn read_axi_block(&mut self, read_xfer: ReadXfer) -> Vec<u32> {
        let mut block = vec![];
        for i in (0..read_xfer.len).step_by(Self::AXI_DATA_WIDTH) {
            let src = read_xfer.src + if read_xfer.fixed { 0 } else { i as AxiAddr };
            let data = self.axi.read(Self::AXI_DATA_WIDTH.into(), src).unwrap();
            block.push(data);
        }
        block
    }

    fn write_axi_block(&mut self, block: &[u32], write_xfer: WriteXfer) {
        let block = if self.control.reg.is_set(Control::AES_MODE_EN) {
            self.encrypt_block(block)
        } else {
            block.to_vec()
        };

        for i in (0..write_xfer.len).step_by(Self::AXI_DATA_WIDTH) {
            let dest = write_xfer.dest + if write_xfer.fixed { 0 } else { i as AxiAddr };
            let data = block[i / 4];
            self.axi
                .write(Self::AXI_DATA_WIDTH.into(), dest, data)
                .unwrap();
        }
    }

    fn encrypt_block(&mut self, block: &[u32]) -> Vec<u32> {
        // Process each 16-byte block
        block.chunks(4).fold(Vec::new(), |mut acc, chunk| {
            let data = chunk
                .iter()
                .enumerate()
                .fold([0u8; 16], |mut acc, (i, &word)| {
                    let bytes = word.to_le_bytes();
                    acc[i * 4..][..4].copy_from_slice(&bytes);
                    acc
                });

            let encrypted_data = self.aes.process_block(&data);
            let encrypted_data_words = words_from_bytes_le(&encrypted_data);

            acc.extend_from_slice(&encrypted_data_words[..chunk.len()]);
            acc
        })
    }

    // Returns true if this completed immediately.
    fn mailbox_to_axi(&mut self) -> bool {
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
        true
    }

    // Returns true if this completed immediately.
    fn fifo_to_axi(&mut self) -> bool {
        let xfer = self.write_xfer();

        for i in (0..xfer.len).step_by(Self::AXI_DATA_WIDTH) {
            let addr = xfer.dest + if xfer.fixed { 0 } else { i as AxiAddr };
            let data = match self.fifo.pop_front() {
                Some(b) => b,
                None => {
                    self.status0.reg.write(Status0::ERROR::SET);
                    // TODO set interrupt bits
                    return true;
                }
            };
            self.axi
                .write(Self::AXI_DATA_WIDTH.into(), addr, data)
                .unwrap();

            if !self.use_mcu_recovery_interface {
                // Check if FW is indicating that it is ready to receive the recovery image.
                if ((addr & RECOVERY_STATUS_OFFSET) == RECOVERY_STATUS_OFFSET)
                    && ((data & AWATING_RECOVERY_IMAGE) == AWATING_RECOVERY_IMAGE)
                {
                    self.status0.reg.modify(Status0::PAYLOAD_AVAILABLE::CLEAR);
                    // Schedule the timer to indicate that the payload is available
                    self.op_payload_available_action =
                        Some(self.timer.schedule_poll_in(PAYLOAD_AVAILABLE_OP_TICKS));
                }
            }
        }
        true
    }

    fn op_complete(&mut self) {
        let read_target = self.control.reg.read_as_enum(Control::READ_ROUTE).unwrap();
        let write_origin = self.control.reg.read_as_enum(Control::WRITE_ROUTE).unwrap();

        let complete = match (read_target, write_origin) {
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
        };

        if complete {
            self.set_status_complete();
        }
    }

    fn set_status_complete(&mut self) {
        self.status0
            .reg
            .modify(Status0::BUSY::CLEAR + Status0::DMA_FSM_PRESENT_STATE::DONE);
    }

    fn poll(&mut self) {
        if self.timer.fired(&mut self.op_complete_action) {
            self.op_complete();
        }
        if self.timer.fired(&mut self.op_payload_available_action) {
            self.status0.reg.modify(Status0::PAYLOAD_AVAILABLE::SET);
        }
        if let Some(dma_data) = self.axi.dma_result.take() {
            if let Some(write_xfer) = self.pending_axi_to_axi.take() {
                self.write_axi_block(&dma_data, write_xfer);
                self.set_status_complete();
            } else if self.pending_axi_to_fifo {
                self.write_fifo_block(&dma_data);
                self.set_status_complete();
                self.pending_axi_to_fifo = false;
            } else if self.pending_axi_to_mailbox {
                self.write_mailbox(&dma_data);
                self.set_status_complete();
                self.pending_axi_to_mailbox = false;
            }
        } else if self.pending_axi_to_axi.is_some()
            || self.pending_axi_to_fifo
            || self.pending_axi_to_mailbox
        {
            // check again next cycle
            self.timer.schedule_poll_in(1);
        }
    }

    fn incoming_event(&mut self, event: Rc<Event>) {
        self.axi.incoming_event(event);
    }

    fn register_outgoing_events(&mut self, sender: mpsc::Sender<Event>) {
        self.axi.register_outgoing_events(sender);
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::rc::Rc;

    use tock_registers::registers::InMemoryRegister;

    use crate::{aes_clp::AesKeyReleaseOp, CaliptraRootBusArgs, Iccm, MailboxInternal};

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
        let clock = Rc::new(Clock::new());
        let mbox_ram = MailboxRam::default();
        let iccm = Iccm::new(&clock);
        let args = CaliptraRootBusArgs {
            clock: clock.clone(),
            ..CaliptraRootBusArgs::default()
        };
        let mailbox_internal = MailboxInternal::new(&clock, mbox_ram.clone());
        let mci = Mci::new(vec![]);
        let soc_reg = SocRegistersInternal::new(mailbox_internal, iccm, mci.clone(), args);
        let aes_key = Rc::new(RefCell::new(None));
        let aes = crate::Aes::new(aes_key, Rc::new(RefCell::new(AesKeyReleaseOp::default())));
        let mut dma = Dma::new(
            &clock,
            mbox_ram.clone(),
            soc_reg,
            Sha512Accelerator::new(&clock, mbox_ram.clone()),
            mci.clone(),
            aes,
            None,
            false,
        );

        assert_eq!(
            dma_read_u32(&mut dma, &clock.clone(), AXI_TEST_OFFSET),
            0xaabbccdd
        ); // Initial test value
        let test_value = 0xdeadbeef;
        dma_write_u32(&mut dma, &clock, AXI_TEST_OFFSET, test_value);
        assert_eq!(
            dma_read_u32(&mut dma, &clock.clone(), AXI_TEST_OFFSET),
            test_value
        );
    }
}
