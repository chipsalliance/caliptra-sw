/*++

Licensed under the Apache-2.0 license.

File Name:

    mailbox.rs

Abstract:

    File contains MAILBOX implementation

--*/
use smlang::statemachine;

use caliptra_emu_bus::Bus;
use caliptra_emu_bus::{BusError, ReadOnlyRegister, ReadWriteRegister, WriteOnlyRegister};
use caliptra_emu_derive::Bus;
use caliptra_emu_types::{RvAddr, RvData, RvSize};
use std::{cell::RefCell, rc::Rc};

/// Maximum mailbox capacity in DWORDS.
const MAX_MAILBOX_CAPACITY: usize = (128 << 10) >> 2;

#[derive(Clone)]
pub struct Mailbox {
    regs: Rc<RefCell<MailboxRegs>>,
}

impl Mailbox {
    pub fn new() -> Self {
        Self {
            regs: Rc::new(RefCell::new(MailboxRegs::new())),
        }
    }

    // Private interface to the mailbox buffer
    pub fn read_data(
        &self,
        read_word_offset: usize,
        read_word_count: usize,
    ) -> Result<Box<[u32]>, BusError> {
        let mut vec = vec![0; read_word_count];
        if read_word_offset >= MAX_MAILBOX_CAPACITY
            || (read_word_offset + read_word_count) > MAX_MAILBOX_CAPACITY
        {
            Err(BusError::LoadAccessFault)?
        }

        vec.copy_from_slice(
            &self.regs.borrow().state_machine.context.ring_buffer.buffer
                [read_word_offset..(read_word_offset + read_word_count)],
        );

        Ok(vec.into_boxed_slice())
    }

    pub fn write_data(&self, write_word_offset: usize, data: &[u32]) -> Result<(), BusError> {
        if write_word_offset >= MAX_MAILBOX_CAPACITY
            || (write_word_offset + data.len()) > MAX_MAILBOX_CAPACITY
        {
            Err(BusError::StoreAccessFault)?
        }

        self.regs
            .borrow_mut()
            .state_machine
            .context
            .ring_buffer
            .buffer[write_word_offset..(write_word_offset + data.len())]
            .copy_from_slice(data);

        Ok(())
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
    execute: WriteOnlyRegister<u32>,

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
    pub fn new() -> Self {
        Self {
            lock: ReadOnlyRegister::new(Self::LOCK_VAL),
            user: ReadOnlyRegister::new(Self::USER_VAL),
            _cmd: ReadWriteRegister::new(Self::CMD_VAL),
            _dlen: ReadWriteRegister::new(Self::DLEN_VAL),
            data_in: WriteOnlyRegister::new(Self::DATA_IN_VAL),
            data_out: ReadOnlyRegister::new(Self::DATA_OUT_VAL),
            execute: WriteOnlyRegister::new(Self::EXEC_VAL),
            _status: ReadWriteRegister::new(Self::STATUS_VAL),
            state_machine: StateMachine::new(Context::new(MAX_MAILBOX_CAPACITY)),
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
    pub fn write_ex(&mut self, _size: RvSize, _val: RvData) -> Result<(), BusError> {
        let _ = self.state_machine.process_event(Events::ExecWr);
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
    /// mailbox memory capacity
    pub mem_size: usize,
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
    fn new(mem_size: usize) -> Self {
        Self {
            locked: 0,
            user: 0,
            exec: false,
            dlen: 0,
            mem_size: mem_size,
            status: 0,
            ring_buffer: RingBuffer::new(mem_size),
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
    buffer: Vec<u32>,
    capacity: usize,
    read_index: usize,
    write_index: usize,
}

impl RingBuffer {
    pub fn new(capacity: usize) -> Self {
        RingBuffer {
            buffer: vec![0; capacity],
            capacity,
            read_index: 0,
            write_index: 0,
        }
    }
    pub fn enqueue(&mut self, element: u32) {
        // there is no buffer full condition in mailbox h/w
        self.buffer[self.write_index] = element;
        self.write_index = (self.write_index + 1) & (self.capacity - 1);
    }
    pub fn dequeue(&mut self) -> u32 {
        // there is no buffer empty condition in mailbox h/w
        let element = self.buffer[self.read_index];
        self.read_index = (self.read_index + 1) & (self.capacity - 1);
        element
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use caliptra_emu_bus::Bus;
    use caliptra_emu_types::RvAddr;

    const OFFSET_LOCK: RvAddr = 0x00;
    const OFFSET_USER: RvAddr = 0x04;
    const OFFSET_CMD: RvAddr = 0x08;
    const OFFSET_DLEN: RvAddr = 0x0C;
    const OFFSET_DATAIN: RvAddr = 0x10;
    const OFFSET_DATAOUT: RvAddr = 0x14;
    const OFFSET_EXECUTE: RvAddr = 0x18;
    const OFFSET_STATUS: RvAddr = 0x1C;

    const STATUS_DATA_READY: u32 = 0x01;
    const STATUS_CMD_COMPLETE: u32 = 0x02;

    #[test]
    fn test_send_receive() {
        // Acquire lock
        let mut mb = Mailbox::new();
        assert_eq!(mb.read(RvSize::Word, OFFSET_LOCK).unwrap(), 0);
        // Confirm it is locked
        let lock = mb.read(RvSize::Word, OFFSET_LOCK).unwrap();
        assert_eq!(lock, 1);

        let user = mb.read(RvSize::Word, OFFSET_USER).unwrap();
        assert_eq!(user, 0);

        // Write command
        assert_eq!(mb.write(RvSize::Word, OFFSET_CMD, 0x55).ok(), Some(()));
        // Confirm it is locked
        assert_eq!(mb.regs.borrow().state_machine.context.locked, 1);

        // Write dlen
        assert_eq!(mb.write(RvSize::Word, OFFSET_DLEN, 16).ok(), Some(()));
        // Confirm it is locked
        assert_eq!(mb.regs.borrow().state_machine.context.locked, 1);

        for data_in in 1..17 {
            // Write datain
            assert_eq!(
                mb.write(RvSize::Word, OFFSET_DATAIN, data_in).ok(),
                Some(())
            );
            // Confirm it is locked
            assert_eq!(mb.regs.borrow().state_machine.context.locked, 1);
        }
        assert_eq!(
            mb.write(RvSize::Word, OFFSET_STATUS, STATUS_DATA_READY)
                .ok(),
            Some(())
        );

        // Write exec
        assert_eq!(mb.write(RvSize::Word, OFFSET_EXECUTE, 0x55).ok(), Some(()));
        // Confirm it is locked
        assert_eq!(mb.regs.borrow().state_machine.context.locked, 1);

        assert!(matches!(
            mb.regs.borrow().state_machine.state(),
            States::Exec
        ));

        let status = mb.read(RvSize::Word, OFFSET_STATUS).unwrap();
        assert_eq!(status, STATUS_DATA_READY);

        let cmd = mb.read(RvSize::Word, OFFSET_CMD).unwrap();
        assert_eq!(cmd, 0x55);

        let dlen = mb.read(RvSize::Word, OFFSET_DLEN).unwrap();
        assert_eq!(dlen, 16);

        for data_in in 1..17 {
            // Read dataout
            let data_out = mb.read(RvSize::Word, OFFSET_DATAOUT).unwrap();
            // compare with queued data.
            assert_eq!(data_in, data_out);
        }
        assert_eq!(
            mb.write(RvSize::Word, OFFSET_STATUS, STATUS_CMD_COMPLETE)
                .ok(),
            Some(())
        );

        // Receiver resets exec register
        assert_eq!(mb.write(RvSize::Word, OFFSET_EXECUTE, 0).ok(), Some(()));
        // Confirm it is unlocked
        assert_eq!(mb.regs.borrow().state_machine.context.locked, 0);

        assert!(matches!(
            mb.regs.borrow().state_machine.state(),
            States::Idle
        ));
    }

    #[test]
    fn test_sm_init() {
        let mb = Mailbox::new();
        assert!(matches!(
            mb.regs.borrow().state_machine.state(),
            States::Idle
        ));
        assert_eq!(mb.regs.borrow().state_machine.context().locked, 0);
    }

    #[test]
    fn test_sm_lock() {
        let mb = Mailbox::new();
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
    fn test_private_read_write() {
        let mb = Mailbox::new();

        let zero_data: [u32; MAX_MAILBOX_CAPACITY] = [0u32; MAX_MAILBOX_CAPACITY];
        let data: [u32; 12] = [
            0xc908585a, 0x486c3b3d, 0x8bbe50eb, 0x7d2eb8a0, 0x3aa04e3d, 0x8bde2c31, 0xa8a2a1e3,
            0x349dc21c, 0xbbe6c90a, 0xe2f74912, 0x8884b622, 0xbb72b4c5,
        ];

        // Write to the mailbox.
        assert_eq!(mb.write_data(0, &data[..]).ok(), Some(()));

        // Read from the mailbox.
        let read_data = mb.read_data(0, data.len()).unwrap();
        assert_eq!(data, *read_data);

        assert_eq!(mb.write_data(0, &zero_data[..]).ok(), Some(()));
        assert_eq!(mb.read_data(0, zero_data.len()).is_ok(), true);
    }

    #[test]
    fn test_private_read_write_fail() {
        let mb = Mailbox::new();

        let zero_size_buf: [u32; 0] = [0u32; 0];
        let data: [u32; MAX_MAILBOX_CAPACITY + 1] = [0u32; MAX_MAILBOX_CAPACITY + 1];

        // Write to the mailbox.
        assert_eq!(
            mb.write_data(0, &data[..]).err(),
            Some(BusError::StoreAccessFault)
        );

        assert_eq!(
            mb.write_data(1, &data[0..MAX_MAILBOX_CAPACITY]).err(),
            Some(BusError::StoreAccessFault)
        );

        assert_eq!(
            mb.write_data(MAX_MAILBOX_CAPACITY, &zero_size_buf[..])
                .err(),
            Some(BusError::StoreAccessFault)
        );

        assert_eq!(
            mb.write_data(MAX_MAILBOX_CAPACITY, &data[0..1]).err(),
            Some(BusError::StoreAccessFault)
        );

        // Read from the mailbox.
        assert_eq!(
            mb.read_data(0, MAX_MAILBOX_CAPACITY + 1).err(),
            Some(BusError::LoadAccessFault)
        );

        assert_eq!(
            mb.read_data(1, MAX_MAILBOX_CAPACITY).err(),
            Some(BusError::LoadAccessFault)
        );

        assert_eq!(
            mb.read_data(MAX_MAILBOX_CAPACITY, 0).err(),
            Some(BusError::LoadAccessFault)
        );

        assert_eq!(
            mb.read_data(MAX_MAILBOX_CAPACITY, 1).err(),
            Some(BusError::LoadAccessFault)
        );
    }
}
