/*++

Licensed under the Apache-2.0 license.

File Name:

    mailbox.rs

Abstract:

    File contains MAILBOX implementation

--*/
use smlang::statemachine;

use caliptra_emu_bus::{Bus, Ram};
use caliptra_emu_bus::{BusError, ReadOnlyRegister, ReadWriteRegister, WriteOnlyRegister};
use caliptra_emu_derive::Bus;
use caliptra_emu_types::{RvAddr, RvData, RvSize};
use std::{cell::RefCell, rc::Rc};
use tock_registers::interfaces::{ReadWriteable, Readable, Writeable};
use tock_registers::register_bitfields;
use tock_registers::registers::InMemoryRegister;

/// Maximum mailbox capacity.
const MAX_MAILBOX_CAPACITY_BYTES: usize = 128 << 10;

register_bitfields! [
    u32,

    /// Control Register Fields
    Status [
        STATUS OFFSET(0) NUMBITS(4) [
            CMD_BUSY = 0x0,
            DATA_READY = 0x1,
            CMD_COMPLETE = 0x2,
            CMD_FAILURE = 0x3,
        ],
        ECC_SINGLE_ERROR OFFSET(4) NUMBITS(1) [],
        ECC_DOUBLE_ERROR OFFSET(5) NUMBITS(1) [],
        MBOX_FSM_PS OFFSET(6) NUMBITS(3) [
            MBOX_IDLE = 0x0,
            MBOX_RDY_FOR_CMD = 0x1,
            MBOX_RDY_FOR_DLEN = 0x3,
            MBOX_RDY_FOR_DATA = 0x2,
            MBOX_EXECUTE_UC = 0x6,
            MBOX_EXECUTE_SOC = 0x4,
        ],
        SOC_HAS_LOCK OFFSET(9) NUMBITS(1) [],
        RSVD OFFSET(10) NUMBITS(22) [],
    ],

];

#[derive(Clone)]
pub struct MailboxRam {
    ram: Rc<RefCell<Ram>>,
}

impl MailboxRam {
    pub fn new() -> Self {
        Self {
            ram: Rc::new(RefCell::new(Ram::new(vec![
                0u8;
                MAX_MAILBOX_CAPACITY_BYTES
            ]))),
        }
    }
}

impl Bus for MailboxRam {
    /// Read data of specified size from given address
    fn read(&mut self, size: RvSize, addr: RvAddr) -> Result<RvData, BusError> {
        self.ram.borrow_mut().read(size, addr)
    }

    /// Write data of specified size to given address
    fn write(&mut self, size: RvSize, addr: RvAddr, val: RvData) -> Result<(), BusError> {
        self.ram.borrow_mut().write(size, addr, val)?;
        Ok(())
    }
}
impl Default for MailboxRam {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone)]
pub struct Mailbox {
    regs: Rc<RefCell<MailboxRegs>>,
}

impl Mailbox {
    const OFFSET_LOCK: RvAddr = 0x00;
    const OFFSET_CMD: RvAddr = 0x08;
    const OFFSET_DLEN: RvAddr = 0x0C;
    const OFFSET_DATAIN: RvAddr = 0x10;
    const OFFSET_DATAOUT: RvAddr = 0x14;
    const OFFSET_EXECUTE: RvAddr = 0x18;
    const OFFSET_STATUS: RvAddr = 0x1C;

    pub fn new(ram: MailboxRam) -> Self {
        Self {
            regs: Rc::new(RefCell::new(MailboxRegs::new(ram))),
        }
    }

    pub fn read_dlen(&mut self) -> Result<u32, BusError> {
        self.regs.borrow_mut().read(RvSize::Word, Self::OFFSET_DLEN)
    }

    pub fn write_dlen(&mut self, dlen: u32) -> Result<(), BusError> {
        self.regs
            .borrow_mut()
            .write(RvSize::Word, Self::OFFSET_DLEN, dlen)
    }

    pub fn read_cmd(&mut self) -> Result<u32, BusError> {
        self.regs.borrow_mut().read(RvSize::Word, Self::OFFSET_CMD)
    }

    pub fn write_cmd(&mut self, cmd: u32) -> Result<(), BusError> {
        self.regs
            .borrow_mut()
            .write(RvSize::Word, Self::OFFSET_CMD, cmd)
    }

    pub fn read_datain(&mut self) -> Result<u32, BusError> {
        self.regs
            .borrow_mut()
            .read(RvSize::Word, Self::OFFSET_DATAIN)
    }

    pub fn write_datain(&mut self, val: u32) -> Result<(), BusError> {
        self.regs
            .borrow_mut()
            .write(RvSize::Word, Self::OFFSET_DATAIN, val)
    }

    pub fn read_dataout(&mut self) -> Result<u32, BusError> {
        self.regs
            .borrow_mut()
            .read(RvSize::Word, Self::OFFSET_DATAOUT)
    }

    pub fn write_dataout(&mut self, val: u32) -> Result<(), BusError> {
        self.regs
            .borrow_mut()
            .write(RvSize::Word, Self::OFFSET_DATAOUT, val)
    }

    pub fn try_acquire_lock(&mut self) -> bool {
        let result = self.regs.borrow_mut().read(RvSize::Word, Self::OFFSET_LOCK);
        matches!(result, Ok(0))
    }

    pub fn is_locked(&mut self) -> bool {
        self.regs.borrow().state_machine.context().locked == 1
    }

    pub fn read_execute(&mut self) -> Result<u32, BusError> {
        self.regs
            .borrow_mut()
            .read(RvSize::Word, Self::OFFSET_EXECUTE)
    }

    pub fn write_execute(&mut self, val: u32) -> Result<(), BusError> {
        self.regs
            .borrow_mut()
            .write(RvSize::Word, Self::OFFSET_EXECUTE, val)?;
        Ok(())
    }

    pub fn is_status_data_ready(&mut self) -> bool {
        self.match_status(Status::STATUS::DATA_READY.value)
    }

    pub fn is_status_cmd_complete(&mut self) -> bool {
        self.match_status(Status::STATUS::CMD_COMPLETE.value)
    }

    fn match_status(&mut self, status: u32) -> bool {
        let val = self
            .regs
            .borrow_mut()
            .read(RvSize::Word, Self::OFFSET_STATUS)
            .unwrap();
        let reg = InMemoryRegister::<u32, Status::Register>::new(val);
        reg.read(Status::STATUS) == status
    }

    fn set_status(&mut self, status_in: u32) -> Result<(), BusError> {
        let status = self
            .regs
            .borrow_mut()
            .read(RvSize::Word, Self::OFFSET_STATUS)
            .unwrap();

        let status_reg: ReadWriteRegister<u32, Status::Register> = ReadWriteRegister::new(status);
        status_reg.reg.modify(Status::STATUS.val(status_in));

        self.regs
            .borrow_mut()
            .write(RvSize::Word, Self::OFFSET_STATUS, status_reg.reg.get())?;
        Ok(())
    }

    pub fn set_status_cmd_complete(&mut self) -> Result<(), BusError> {
        self.set_status(Status::STATUS::CMD_COMPLETE.value)
    }

    pub fn set_status_data_ready(&mut self) -> Result<(), BusError> {
        self.set_status(Status::STATUS::DATA_READY.value)
    }
}

impl Bus for Mailbox {
    /// Read data of specified size from given address
    fn read(&mut self, size: RvSize, addr: RvAddr) -> Result<RvData, BusError> {
        self.regs.borrow_mut().read(size, addr)
    }

    /// Write data of specified size to given address
    fn write(&mut self, size: RvSize, addr: RvAddr, val: RvData) -> Result<(), BusError> {
        self.regs.borrow_mut().write(size, addr, val)
    }
}

/// Mailbox Peripheral
#[derive(Bus)]
pub struct MailboxRegs {
    /// MBOX_LOCK register
    #[register(offset = 0x0000_0000, read_fn = read_lock)]
    lock: ReadOnlyRegister<u32>,

    /// MBOX_USER register
    #[register(offset = 0x0000_0004, read_fn = read_user)]
    user: ReadOnlyRegister<u32>,

    /// MBOX_CMD register
    #[register(offset = 0x0000_0008, write_fn = write_cmd, read_fn = read_cmd)]
    _cmd: ReadWriteRegister<u32>,

    /// MBOX_DLEN register
    #[register(offset = 0x0000_000c, write_fn = write_dlen, read_fn = read_dlen)]
    _dlen: ReadWriteRegister<u32>,

    /// MBOX_DATAIN register
    #[register(offset = 0x0000_0010, write_fn = write_din)]
    data_in: WriteOnlyRegister<u32>,

    /// MBOX_DATAOUT register
    #[register(offset = 0x0000_0014, read_fn = read_dout)]
    data_out: ReadOnlyRegister<u32>,

    /// MBOX_EXECUTE register
    #[register(offset = 0x0000_0018, write_fn = write_ex)]
    execute: ReadWriteRegister<u32>,

    /// MBOX_STATUS register
    #[register(offset = 0x0000_001c, write_fn = write_status, read_fn = read_status)]
    _status: ReadWriteRegister<u32>,

    /// State Machine
    state_machine: StateMachine<Context>,
}

impl MailboxRegs {
    /// LOCK Register Value
    const LOCK_VAL: RvData = 0x0;
    const USER_VAL: RvData = 0x0;
    const CMD_VAL: RvData = 0x0;
    const DLEN_VAL: RvData = 0x0;
    const DATA_IN_VAL: RvData = 0x0;
    const DATA_OUT_VAL: RvData = 0x0;
    const EXEC_VAL: RvData = 0x0;
    const STATUS_VAL: RvData = 0x0;

    /// Create a new instance of Mailbox registers
    pub fn new(ram: MailboxRam) -> Self {
        Self {
            lock: ReadOnlyRegister::new(Self::LOCK_VAL),
            user: ReadOnlyRegister::new(Self::USER_VAL),
            _cmd: ReadWriteRegister::new(Self::CMD_VAL),
            _dlen: ReadWriteRegister::new(Self::DLEN_VAL),
            data_in: WriteOnlyRegister::new(Self::DATA_IN_VAL),
            data_out: ReadOnlyRegister::new(Self::DATA_OUT_VAL),
            execute: ReadWriteRegister::new(Self::EXEC_VAL),
            _status: ReadWriteRegister::new(Self::STATUS_VAL),
            state_machine: StateMachine::new(Context::new(ram)),
        }
    }

    // Todo: Implement read_lock callback fn
    pub fn read_lock(&mut self, _size: RvSize) -> Result<u32, BusError> {
        if self
            .state_machine
            .process_event(Events::RdLock(Owner(0)))
            .is_ok()
        {
            Ok(0)
        } else {
            Ok(1)
        }
    }

    // Todo: Implement read_user callback fn
    pub fn read_user(&self, _size: RvSize) -> Result<u32, BusError> {
        Ok(self.state_machine.context.user)
    }

    // Todo: Implement write cmd callback fn
    pub fn write_cmd(&mut self, _size: RvSize, val: RvData) -> Result<(), BusError> {
        let _ = self.state_machine.process_event(Events::CmdWrite(Cmd(val)));
        Ok(())
    }

    // Todo: Implement read cmd callback fn
    pub fn read_cmd(&self, _size: RvSize) -> Result<u32, BusError> {
        Ok(self.state_machine.context.cmd)
    }

    // Todo: Implement write dlen callback fn
    pub fn write_dlen(&mut self, _size: RvSize, val: RvData) -> Result<(), BusError> {
        let _ = self
            .state_machine
            .process_event(Events::DlenWrite(DataLength(val)));
        Ok(())
    }

    // Todo: Implement read dlen callback fn
    pub fn read_dlen(&self, _size: RvSize) -> Result<u32, BusError> {
        Ok(self.state_machine.context.dlen)
    }

    // Todo: Implement write din callback fn
    pub fn write_din(&mut self, _size: RvSize, val: RvData) -> Result<(), BusError> {
        let _ = self
            .state_machine
            .process_event(Events::DataWrite(DataIn(val)));
        Ok(())
    }

    // Todo: Implement read dout callback fn
    pub fn read_dout(&mut self, _size: RvSize) -> Result<u32, BusError> {
        let mb = &mut self.state_machine;
        let _ = mb.process_event(Events::DataRead);
        Ok(mb.context.data_out)
    }

    // Todo: Implement write ex callback fn
    pub fn write_ex(&mut self, _size: RvSize, val: RvData) -> Result<(), BusError> {
        let _ = self.state_machine.process_event(Events::ExecWr);
        self.execute.reg.set(val);
        Ok(())
    }

    // Todo: Implement write status callback fn
    pub fn write_status(&mut self, _size: RvSize, val: RvData) -> Result<(), BusError> {
        self.state_machine.context.status = val;
        Ok(())
    }

    // Todo: Implement read status callback fn
    pub fn read_status(&self, _size: RvSize) -> Result<u32, BusError> {
        Ok(self.state_machine.context.status)
    }
}

#[derive(PartialEq)]
/// Data length
pub struct DataLength(pub u32);

#[derive(PartialEq)]
/// Data In
pub struct DataIn(pub u32);

#[derive(PartialEq)]
/// Data length
pub struct Owner(pub u32);

#[derive(PartialEq)]
/// Data length
pub struct Cmd(pub u32);

statemachine! {
    transitions: {
        // CurrentState Event [guard] / action = NextState
        *Idle + RdLock(Owner) [is_not_locked] / lock = RdyForCmd,
        RdyForCmd  + CmdWrite(Cmd) / set_cmd = RdyForDlen,
        RdyForDlen + DlenWrite(DataLength) / init_dlen = RdyForData,
        RdyForData + DataWrite(DataIn) / enqueue = RdyForData,
        RdyForData + ExecWr = Exec,
        Exec + DataRead / dequeue = Exec,
        Exec + ExecWr [is_locked] / unlock = Idle
    }
}

/// State machine extended variables.
pub struct Context {
    /// lock state
    pub locked: u32,
    /// Who acquired the lock.
    pub user: u32,
    /// Execute flag
    pub exec: bool,
    /// number of data elements
    pub dlen: u32,
    /// Fifo storage
    pub ring_buffer: RingBuffer,
    /// Mailbox Status
    status: u32,
    /// Command
    pub cmd: u32,
    // data_out
    data_out: u32,
}

impl Context {
    fn new(ram: MailboxRam) -> Self {
        Self {
            locked: 0,
            user: 0,
            exec: false,
            dlen: 0,
            status: 0,
            ring_buffer: RingBuffer::new(ram),
            cmd: 0,
            data_out: 0,
        }
    }
}

impl StateMachineContext for Context {
    // guards
    fn is_not_locked(&mut self, _user: &Owner) -> Result<(), ()> {
        if self.locked == 1 {
            // no transition
            Err(())
        } else {
            Ok(())
        }
    }
    fn is_locked(&mut self) -> Result<(), ()> {
        if self.locked != 0 {
            Ok(())
        } else {
            // no transition
            Err(())
        }
    }
    // actions
    fn init_dlen(&mut self, data_len: &DataLength) {
        self.dlen = data_len.0;
    }

    fn set_cmd(&mut self, cmd: &Cmd) {
        self.cmd = cmd.0;
    }

    fn lock(&mut self, user: &Owner) {
        self.ring_buffer.reset();
        self.locked = 1;
        self.user = user.0;
    }
    fn unlock(&mut self) {
        self.locked = 0;
    }
    fn dequeue(&mut self) {
        self.data_out = self.ring_buffer.dequeue();
    }

    fn enqueue(&mut self, data_in: &DataIn) {
        self.ring_buffer.enqueue(data_in.0);
    }
}

pub struct RingBuffer {
    capacity: usize,
    read_index: usize,
    write_index: usize,
    mailbox_ram: MailboxRam,
}

impl RingBuffer {
    pub fn new(ram: MailboxRam) -> Self {
        let ram_size = ram.ram.borrow().data().len();
        RingBuffer {
            capacity: ram_size,
            read_index: 0,
            write_index: 0,
            mailbox_ram: ram,
        }
    }
    pub fn enqueue(&mut self, element: u32) {
        // On buffer full condition, ignore the write.
        if self.write_index < self.capacity {
            self.mailbox_ram
                .write(RvSize::Word, self.write_index as u32, element)
                .unwrap();
            self.write_index += RvSize::Word as usize;
        }
    }
    pub fn dequeue(&mut self) -> u32 {
        // On buffer empty condition, return 0.
        let mut element = 0;
        if self.read_index < self.capacity {
            element = self
                .mailbox_ram
                .read(RvSize::Word, self.read_index as u32)
                .unwrap();

            self.read_index += RvSize::Word as usize;
        }
        element
    }
    pub fn reset(&mut self) {
        self.read_index = 0;
        self.write_index = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use caliptra_emu_bus::Bus;
    use caliptra_emu_types::RvAddr;

    const OFFSET_USER: RvAddr = 0x04;

    #[test]
    fn test_send_receive() {
        // Acquire lock
        let mut mb = Mailbox::new(MailboxRam::new());
        assert_eq!(mb.read(RvSize::Word, Mailbox::OFFSET_LOCK).unwrap(), 0);
        // Confirm it is locked
        let lock = mb.read(RvSize::Word, Mailbox::OFFSET_LOCK).unwrap();
        assert_eq!(lock, 1);

        let user = mb.read(RvSize::Word, OFFSET_USER).unwrap();
        assert_eq!(user, 0);

        // Write command
        assert_eq!(
            mb.write(RvSize::Word, Mailbox::OFFSET_CMD, 0x55).ok(),
            Some(())
        );
        // Confirm it is locked
        assert_eq!(mb.regs.borrow().state_machine.context.locked, 1);

        // Write dlen
        assert_eq!(
            mb.write(RvSize::Word, Mailbox::OFFSET_DLEN, 16).ok(),
            Some(())
        );
        // Confirm it is locked
        assert_eq!(mb.regs.borrow().state_machine.context.locked, 1);

        for data_in in 1..17 {
            // Write datain
            assert_eq!(
                mb.write(RvSize::Word, Mailbox::OFFSET_DATAIN, data_in).ok(),
                Some(())
            );
            // Confirm it is locked
            assert_eq!(mb.regs.borrow().state_machine.context.locked, 1);
        }
        assert_eq!(
            mb.write(
                RvSize::Word,
                Mailbox::OFFSET_STATUS,
                Status::STATUS::DATA_READY.value
            )
            .ok(),
            Some(())
        );

        // Write exec
        assert_eq!(
            mb.write(RvSize::Word, Mailbox::OFFSET_EXECUTE, 0x55).ok(),
            Some(())
        );
        // Confirm it is locked
        assert_eq!(mb.regs.borrow().state_machine.context.locked, 1);

        assert!(matches!(
            mb.regs.borrow().state_machine.state(),
            States::Exec
        ));

        let status = mb.read(RvSize::Word, Mailbox::OFFSET_STATUS).unwrap();
        assert_eq!(status, Status::STATUS::DATA_READY.value);

        let cmd = mb.read(RvSize::Word, Mailbox::OFFSET_CMD).unwrap();
        assert_eq!(cmd, 0x55);

        let dlen = mb.read(RvSize::Word, Mailbox::OFFSET_DLEN).unwrap();
        assert_eq!(dlen, 16);

        for data_in in 1..17 {
            // Read dataout
            let data_out = mb.read(RvSize::Word, Mailbox::OFFSET_DATAOUT).unwrap();
            // compare with queued data.
            assert_eq!(data_in, data_out);
        }
        assert_eq!(
            mb.write(
                RvSize::Word,
                Mailbox::OFFSET_STATUS,
                Status::STATUS::CMD_COMPLETE.value
            )
            .ok(),
            Some(())
        );

        // Receiver resets exec register
        assert_eq!(
            mb.write(RvSize::Word, Mailbox::OFFSET_EXECUTE, 0).ok(),
            Some(())
        );
        // Confirm it is unlocked
        assert_eq!(mb.regs.borrow().state_machine.context.locked, 0);

        assert!(matches!(
            mb.regs.borrow().state_machine.state(),
            States::Idle
        ));
    }

    #[test]
    fn test_sm_init() {
        let mb = Mailbox::new(MailboxRam::new());
        assert!(matches!(
            mb.regs.borrow().state_machine.state(),
            States::Idle
        ));
        assert_eq!(mb.regs.borrow().state_machine.context().locked, 0);
    }

    #[test]
    fn test_sm_lock() {
        let mb = Mailbox::new(MailboxRam::new());
        assert_eq!(mb.regs.borrow().state_machine.context().locked, 0);
        assert_eq!(mb.regs.borrow().state_machine.context().dlen, 0);

        let _ = mb
            .regs
            .borrow_mut()
            .state_machine
            .process_event(Events::RdLock(Owner(0)));
        assert!(matches!(
            mb.regs.borrow().state_machine.state(),
            States::RdyForCmd
        ));
        assert_eq!(mb.regs.borrow().state_machine.context().locked, 1);

        let _ = mb
            .regs
            .borrow_mut()
            .state_machine
            .process_event(Events::CmdWrite(Cmd(0x55)));
        assert!(matches!(
            mb.regs.borrow().state_machine.state(),
            States::RdyForDlen
        ));

        let _ = mb
            .regs
            .borrow_mut()
            .state_machine
            .process_event(Events::DlenWrite(DataLength(0x55)));
        assert!(matches!(
            mb.regs.borrow().state_machine.state(),
            States::RdyForData
        ));

        let _ = mb
            .regs
            .borrow_mut()
            .state_machine
            .process_event(Events::ExecWr);
        assert!(matches!(
            mb.regs.borrow().state_machine.state(),
            States::Exec
        ));

        let _ = mb
            .regs
            .borrow_mut()
            .state_machine
            .process_event(Events::ExecWr);
        assert!(matches!(
            mb.regs.borrow().state_machine.state(),
            States::Idle
        ));
        assert_eq!(mb.regs.borrow().state_machine.context().locked, 0);
    }

    #[test]
    fn test_send_receive_max_limit() {
        // Acquire lock
        let mut mb = Mailbox::new(MailboxRam::new());
        assert_eq!(mb.read(RvSize::Word, Mailbox::OFFSET_LOCK).unwrap(), 0);
        // Confirm it is locked
        let lock = mb.read(RvSize::Word, Mailbox::OFFSET_LOCK).unwrap();
        assert_eq!(lock, 1);

        let user = mb.read(RvSize::Word, OFFSET_USER).unwrap();
        assert_eq!(user, 0);

        // Write command
        assert_eq!(
            mb.write(RvSize::Word, Mailbox::OFFSET_CMD, 0x55).ok(),
            Some(())
        );

        // Write dlen
        assert_eq!(
            mb.write(
                RvSize::Word,
                Mailbox::OFFSET_DLEN,
                (MAX_MAILBOX_CAPACITY_BYTES + 4) as u32
            )
            .ok(),
            Some(())
        );

        for data_in in (0..MAX_MAILBOX_CAPACITY_BYTES).step_by(4) {
            // Write datain
            assert_eq!(
                mb.write(RvSize::Word, Mailbox::OFFSET_DATAIN, data_in as u32)
                    .ok(),
                Some(())
            );
        }

        // Write an additional DWORD. This should be a no-op.
        assert_eq!(
            mb.write(RvSize::Word, Mailbox::OFFSET_DATAIN, 0xDEADBEEF)
                .ok(),
            Some(())
        );

        assert_eq!(
            mb.write(
                RvSize::Word,
                Mailbox::OFFSET_STATUS,
                Status::STATUS::DATA_READY.value
            )
            .ok(),
            Some(())
        );

        // Write exec
        assert_eq!(
            mb.write(RvSize::Word, Mailbox::OFFSET_EXECUTE, 0x55).ok(),
            Some(())
        );

        assert!(matches!(
            mb.regs.borrow().state_machine.state(),
            States::Exec
        ));

        let status = mb.read(RvSize::Word, Mailbox::OFFSET_STATUS).unwrap();
        assert_eq!(status, Status::STATUS::DATA_READY.value);

        let cmd = mb.read(RvSize::Word, Mailbox::OFFSET_CMD).unwrap();
        assert_eq!(cmd, 0x55);

        let dlen = mb.read(RvSize::Word, Mailbox::OFFSET_DLEN).unwrap();
        assert_eq!(dlen, (MAX_MAILBOX_CAPACITY_BYTES + 4) as u32);

        for data_in in (0..MAX_MAILBOX_CAPACITY_BYTES).step_by(4) {
            // Read dataout
            let data_out = mb.read(RvSize::Word, Mailbox::OFFSET_DATAOUT).unwrap();
            // compare with queued data.
            assert_eq!(data_in as u32, data_out);
        }

        // Read an additional DWORD. This should return 0.
        assert_eq!(mb.read(RvSize::Word, Mailbox::OFFSET_DATAOUT).unwrap(), 0);

        assert_eq!(
            mb.write(
                RvSize::Word,
                Mailbox::OFFSET_STATUS,
                Status::STATUS::CMD_COMPLETE.value
            )
            .ok(),
            Some(())
        );

        // Receiver resets exec register
        assert_eq!(
            mb.write(RvSize::Word, Mailbox::OFFSET_EXECUTE, 0).ok(),
            Some(())
        );
        // Confirm it is unlocked
        assert_eq!(mb.regs.borrow().state_machine.context.locked, 0);

        assert!(matches!(
            mb.regs.borrow().state_machine.state(),
            States::Idle
        ));
    }
}
