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
use tock_registers::registers::InMemoryRegister;
use tock_registers::{register_bitfields, LocalRegisterCopy};

/// Maximum mailbox capacity.
const MAX_MAILBOX_CAPACITY_BYTES: usize = 128 << 10;
const OFFSET_LOCK: RvAddr = 0x00;
const OFFSET_CMD: RvAddr = 0x08;
const OFFSET_DLEN: RvAddr = 0x0C;
const OFFSET_DATAIN: RvAddr = 0x10;
const OFFSET_DATAOUT: RvAddr = 0x14;
const OFFSET_EXECUTE: RvAddr = 0x18;
const OFFSET_STATUS: RvAddr = 0x1C;

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

type StatusRegister = LocalRegisterCopy<u32, Status::Register>;

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

pub type Soc2CaliptraMailboxRegs = Rc<RefCell<MailboxRegs>>;
pub fn soc2caliptra_mailbox_regs(sram: MailboxRam) -> Soc2CaliptraMailboxRegs {
    Rc::new(RefCell::new(MailboxRegs::new(sram)))
}

#[derive(Clone)]
pub struct MailboxExternal {
    regs: Soc2CaliptraMailboxRegs,
}

impl MailboxExternal {
    pub fn new(regs: Soc2CaliptraMailboxRegs) -> Self {
        Self { regs }
    }
    pub fn read_dlen(&mut self) -> Result<u32, BusError> {
        self.regs.borrow_mut().request(MailboxRequester::Soc);
        self.regs.borrow_mut().read(RvSize::Word, OFFSET_DLEN)
    }

    pub fn write_dlen(&mut self, dlen: u32) -> Result<(), BusError> {
        self.regs.borrow_mut().request(MailboxRequester::Soc);
        self.regs
            .borrow_mut()
            .write(RvSize::Word, OFFSET_DLEN, dlen)
    }

    pub fn read_cmd(&mut self) -> Result<u32, BusError> {
        self.regs.borrow_mut().request(MailboxRequester::Soc);
        self.regs.borrow_mut().read(RvSize::Word, OFFSET_CMD)
    }

    pub fn write_cmd(&mut self, cmd: u32) -> Result<(), BusError> {
        self.regs.borrow_mut().request(MailboxRequester::Soc);
        self.regs.borrow_mut().write(RvSize::Word, OFFSET_CMD, cmd)
    }

    pub fn read_datain(&mut self) -> Result<u32, BusError> {
        self.regs.borrow_mut().request(MailboxRequester::Soc);
        self.regs.borrow_mut().read(RvSize::Word, OFFSET_DATAIN)
    }

    pub fn write_datain(&mut self, val: u32) -> Result<(), BusError> {
        self.regs.borrow_mut().request(MailboxRequester::Soc);
        self.regs
            .borrow_mut()
            .write(RvSize::Word, OFFSET_DATAIN, val)
    }

    pub fn read_dataout(&mut self) -> Result<u32, BusError> {
        self.regs.borrow_mut().request(MailboxRequester::Soc);
        self.regs.borrow_mut().read(RvSize::Word, OFFSET_DATAOUT)
    }

    pub fn write_dataout(&mut self, val: u32) -> Result<(), BusError> {
        self.regs.borrow_mut().request(MailboxRequester::Soc);
        self.regs
            .borrow_mut()
            .write(RvSize::Word, OFFSET_DATAOUT, val)
    }

    pub fn try_acquire_lock(&mut self) -> bool {
        self.regs.borrow_mut().request(MailboxRequester::Soc);
        let result = self.regs.borrow_mut().read(RvSize::Word, OFFSET_LOCK);
        matches!(result, Ok(0))
    }

    pub fn is_locked(&mut self) -> bool {
        self.regs.borrow_mut().request(MailboxRequester::Soc);
        self.regs.borrow().state_machine.context().locked == 1
    }

    pub fn read_execute(&mut self) -> Result<u32, BusError> {
        self.regs.borrow_mut().request(MailboxRequester::Soc);
        self.regs.borrow_mut().read(RvSize::Word, OFFSET_EXECUTE)
    }

    pub fn write_execute(&mut self, val: u32) -> Result<(), BusError> {
        self.regs.borrow_mut().request(MailboxRequester::Soc);
        self.regs
            .borrow_mut()
            .write(RvSize::Word, OFFSET_EXECUTE, val)?;
        Ok(())
    }

    pub fn is_command_exec_requested(&self) -> bool {
        self.regs.borrow_mut().request(MailboxRequester::Soc);
        matches!(self.regs.borrow_mut().state_machine.state, States::ExecUc)
    }

    pub fn is_status_cmd_busy(&mut self) -> bool {
        self.regs.borrow_mut().request(MailboxRequester::Soc);
        self.match_status(Status::STATUS::CMD_BUSY.value)
    }

    pub fn is_status_data_ready(&mut self) -> bool {
        self.regs.borrow_mut().request(MailboxRequester::Soc);
        self.match_status(Status::STATUS::DATA_READY.value)
    }

    pub fn is_status_cmd_complete(&mut self) -> bool {
        self.regs.borrow_mut().request(MailboxRequester::Soc);
        self.match_status(Status::STATUS::CMD_COMPLETE.value)
    }

    fn match_status(&mut self, status: u32) -> bool {
        self.regs.borrow_mut().request(MailboxRequester::Soc);
        let val = self
            .regs
            .borrow_mut()
            .read(RvSize::Word, OFFSET_STATUS)
            .unwrap();
        let reg = InMemoryRegister::<u32, Status::Register>::new(val);
        reg.read(Status::STATUS) == status
    }

    fn set_status(&mut self, status_in: u32) -> Result<(), BusError> {
        self.regs.borrow_mut().request(MailboxRequester::Soc);
        let status = self
            .regs
            .borrow_mut()
            .read(RvSize::Word, OFFSET_STATUS)
            .unwrap();

        let status_reg: ReadWriteRegister<u32, Status::Register> = ReadWriteRegister::new(status);
        status_reg.reg.modify(Status::STATUS.val(status_in));

        self.regs
            .borrow_mut()
            .write(RvSize::Word, OFFSET_STATUS, status_reg.reg.get())?;
        Ok(())
    }

    pub fn set_status_cmd_complete(&mut self) -> Result<(), BusError> {
        self.regs.borrow_mut().request(MailboxRequester::Soc);
        self.set_status(Status::STATUS::CMD_COMPLETE.value)
    }

    pub fn set_status_data_ready(&mut self) -> Result<(), BusError> {
        self.regs.borrow_mut().request(MailboxRequester::Soc);
        self.set_status(Status::STATUS::DATA_READY.value)
    }
}
impl Bus for MailboxExternal {
    /// Read data of specified size from given address
    fn read(&mut self, size: RvSize, addr: RvAddr) -> Result<RvData, BusError> {
        self.regs.borrow_mut().request(MailboxRequester::Soc);
        self.regs.borrow_mut().read(size, addr)
    }

    /// Write data of specified size to given address
    fn write(&mut self, size: RvSize, addr: RvAddr, val: RvData) -> Result<(), BusError> {
        self.regs.borrow_mut().request(MailboxRequester::Soc);
        self.regs.borrow_mut().write(size, addr, val)
    }
}

#[derive(Clone)]
pub struct MailboxInternal {
    pub regs: Soc2CaliptraMailboxRegs,
}

/// Mailbox Peripheral

impl MailboxInternal {
    pub fn new(regs: Soc2CaliptraMailboxRegs) -> Self {
        Self { regs }
    }

    pub fn read_dlen(&mut self) -> Result<u32, BusError> {
        self.regs.borrow_mut().request(MailboxRequester::Caliptra);
        self.regs.borrow_mut().read(RvSize::Word, OFFSET_DLEN)
    }

    pub fn write_dlen(&mut self, dlen: u32) -> Result<(), BusError> {
        self.regs.borrow_mut().request(MailboxRequester::Caliptra);
        self.regs
            .borrow_mut()
            .write(RvSize::Word, OFFSET_DLEN, dlen)
    }

    pub fn read_cmd(&mut self) -> Result<u32, BusError> {
        self.regs.borrow_mut().request(MailboxRequester::Caliptra);
        self.regs.borrow_mut().read(RvSize::Word, OFFSET_CMD)
    }

    pub fn write_cmd(&mut self, cmd: u32) -> Result<(), BusError> {
        self.regs.borrow_mut().request(MailboxRequester::Caliptra);
        self.regs.borrow_mut().write(RvSize::Word, OFFSET_CMD, cmd)
    }

    pub fn read_datain(&mut self) -> Result<u32, BusError> {
        self.regs.borrow_mut().request(MailboxRequester::Caliptra);
        self.regs.borrow_mut().read(RvSize::Word, OFFSET_DATAIN)
    }

    pub fn write_datain(&mut self, val: u32) -> Result<(), BusError> {
        self.regs.borrow_mut().request(MailboxRequester::Caliptra);
        self.regs
            .borrow_mut()
            .write(RvSize::Word, OFFSET_DATAIN, val)
    }

    pub fn read_dataout(&mut self) -> Result<u32, BusError> {
        self.regs.borrow_mut().request(MailboxRequester::Caliptra);
        self.regs.borrow_mut().read(RvSize::Word, OFFSET_DATAOUT)
    }

    pub fn write_dataout(&mut self, val: u32) -> Result<(), BusError> {
        self.regs.borrow_mut().request(MailboxRequester::Caliptra);
        self.regs
            .borrow_mut()
            .write(RvSize::Word, OFFSET_DATAOUT, val)
    }

    pub fn try_acquire_lock(&mut self) -> bool {
        self.regs.borrow_mut().request(MailboxRequester::Caliptra);
        let result = self.regs.borrow_mut().read(RvSize::Word, OFFSET_LOCK);
        matches!(result, Ok(0))
    }

    pub fn is_locked(&mut self) -> bool {
        self.regs.borrow_mut().request(MailboxRequester::Caliptra);
        self.regs.borrow().state_machine.context().locked == 1
    }

    pub fn read_execute(&mut self) -> Result<u32, BusError> {
        self.regs.borrow_mut().request(MailboxRequester::Caliptra);
        self.regs.borrow_mut().read(RvSize::Word, OFFSET_EXECUTE)
    }

    pub fn write_execute(&mut self, val: u32) -> Result<(), BusError> {
        self.regs.borrow_mut().request(MailboxRequester::Caliptra);
        self.regs
            .borrow_mut()
            .write(RvSize::Word, OFFSET_EXECUTE, val)?;
        Ok(())
    }

    pub fn is_command_exec_requested(&self) -> bool {
        self.regs.borrow_mut().request(MailboxRequester::Caliptra);
        matches!(self.regs.borrow_mut().state_machine.state, States::ExecUc)
    }

    pub fn is_status_cmd_busy(&mut self) -> bool {
        self.regs.borrow_mut().request(MailboxRequester::Caliptra);
        self.match_status(Status::STATUS::CMD_BUSY.value)
    }

    pub fn is_status_data_ready(&mut self) -> bool {
        self.regs.borrow_mut().request(MailboxRequester::Caliptra);
        self.match_status(Status::STATUS::DATA_READY.value)
    }

    pub fn is_status_cmd_complete(&mut self) -> bool {
        self.regs.borrow_mut().request(MailboxRequester::Caliptra);
        self.match_status(Status::STATUS::CMD_COMPLETE.value)
    }

    fn match_status(&mut self, status: u32) -> bool {
        self.regs.borrow_mut().request(MailboxRequester::Caliptra);
        let val = self
            .regs
            .borrow_mut()
            .read(RvSize::Word, OFFSET_STATUS)
            .unwrap();
        let reg = InMemoryRegister::<u32, Status::Register>::new(val);
        reg.read(Status::STATUS) == status
    }

    fn set_status(&mut self, status_in: u32) -> Result<(), BusError> {
        self.regs.borrow_mut().request(MailboxRequester::Caliptra);
        let status = self
            .regs
            .borrow_mut()
            .read(RvSize::Word, OFFSET_STATUS)
            .unwrap();

        let status_reg: ReadWriteRegister<u32, Status::Register> = ReadWriteRegister::new(status);
        status_reg.reg.modify(Status::STATUS.val(status_in));

        self.regs
            .borrow_mut()
            .write(RvSize::Word, OFFSET_STATUS, status_reg.reg.get())?;
        Ok(())
    }

    pub fn set_status_cmd_complete(&mut self) -> Result<(), BusError> {
        self.regs.borrow_mut().request(MailboxRequester::Caliptra);
        self.set_status(Status::STATUS::CMD_COMPLETE.value)
    }

    pub fn set_status_data_ready(&mut self) -> Result<(), BusError> {
        self.regs.borrow_mut().request(MailboxRequester::Caliptra);
        self.set_status(Status::STATUS::DATA_READY.value)
    }
}

impl Bus for MailboxInternal {
    /// Read data of specified size from given address
    fn read(&mut self, size: RvSize, addr: RvAddr) -> Result<RvData, BusError> {
        self.regs.borrow_mut().request(MailboxRequester::Caliptra);
        self.regs.borrow_mut().read(size, addr)
    }

    /// Write data of specified size to given address
    fn write(&mut self, size: RvSize, addr: RvAddr, val: RvData) -> Result<(), BusError> {
        self.regs.borrow_mut().request(MailboxRequester::Caliptra);
        self.regs.borrow_mut().write(size, addr, val)
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]

pub enum MailboxRequester {
    Caliptra = 0,
    Soc = 1,
}

impl From<MailboxRequester> for u32 {
    fn from(val: MailboxRequester) -> Self {
        match val {
            MailboxRequester::Caliptra => 0,
            MailboxRequester::Soc => 1,
        }
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

    pub requester: MailboxRequester,
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
            requester: MailboxRequester::Caliptra,
        }
    }
    pub fn request(&mut self, requester: MailboxRequester) {
        self.requester = requester;
    }

    // Todo: Implement read_lock callback fn
    pub fn read_lock(&mut self, _size: RvSize) -> Result<u32, BusError> {
        if self
            .state_machine
            .process_event(Events::RdLock(self.requester))
            .is_ok()
        {
            Ok(0)
        } else {
            Ok(1)
        }
    }

    // Todo: Implement read_user callback fn
    pub fn read_user(&self, _size: RvSize) -> Result<MailboxRequester, BusError> {
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

    /// Write to execute register
    pub fn write_ex(&mut self, _size: RvSize, val: RvData) -> Result<(), BusError> {
        let event = {
            match self.requester {
                MailboxRequester::Caliptra => {
                    if val & 1 != 0 {
                        Events::UcExecSet
                    } else {
                        Events::UcExecClear
                    }
                }
                _ => {
                    if val & 1 != 0 {
                        Events::SocExecSet
                    } else {
                        Events::SocExecClear
                    }
                }
            }
        };

        let _ = self.state_machine.process_event(event);
        self.execute.reg.set(val);
        Ok(())
    }

    // Todo: Implement write status callback fn
    pub fn write_status(&mut self, _size: RvSize, val: RvData) -> Result<(), BusError> {
        //        let event = Events::StatusWrite(StatusRegister::new(val));
        //        let _ = self.state_machine.process_event(event);

        let val = LocalRegisterCopy::<u32, Status::Register>::new(val);
        self.state_machine
            .context
            .status
            .write(Status::STATUS.val(val.read(Status::STATUS)));
        Ok(())
    }

    // Todo: Implement read status callback fn
    pub fn read_status(&self, _size: RvSize) -> Result<u32, BusError> {
        let mut result = self.state_machine.context.status;
        result.modify(match self.state_machine.state {
            // TODO: What about MBOX_EXECUTE_SOC?
            States::ExecUc => Status::MBOX_FSM_PS::MBOX_EXECUTE_UC,
            States::ExecSoc => Status::MBOX_FSM_PS::MBOX_EXECUTE_SOC,
            States::Idle => Status::MBOX_FSM_PS::MBOX_IDLE,
            States::RdyForCmd => Status::MBOX_FSM_PS::MBOX_RDY_FOR_CMD,
            States::RdyForData => Status::MBOX_FSM_PS::MBOX_RDY_FOR_DATA,
            States::RdyForDlen => Status::MBOX_FSM_PS::MBOX_RDY_FOR_DLEN,
        });
        Ok(result.get())
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

        //move from idle to rdy for command when lock is acquired.
        *Idle + RdLock(MailboxRequester) [is_not_locked] / lock = RdyForCmd,

        //move from rdy for cmd to rdy for dlen when cmd is written to.
        RdyForCmd  + CmdWrite(Cmd) / set_cmd = RdyForDlen,

        //move from rdy for dlen to rdy for data when dlen is written to.
        RdyForDlen + DlenWrite(DataLength) / init_dlen = RdyForData,

        RdyForData + DataWrite(DataIn) / enqueue = RdyForData,

        //move from rdy for data to execute uc  when micro sets execute bit.
        RdyForData + UcExecSet = ExecUc,

        //move from rdy for data to execute soc when soc sets execute bit.
        RdyForData + SocExecSet = ExecSoc,

        ExecUc + DataRead / dequeue = ExecUc,
        ExecUc + DlenWrite(DataLength) / init_dlen = ExecUc,
        ExecUc + DataWrite(DataIn) / enqueue = ExecUc,
        ExecUc + UcExecClear [is_locked] / unlock = Idle,

        //ExecUc + StatusWrite(StatusRegister) [ is_not_busy ] = ExecUc,

        ExecSoc + DataRead / dequeue = ExecSoc,
        ExecSoc + DlenWrite(DataLength) / init_dlen = ExecSoc,
        ExecSoc + DataWrite(DataIn) / enqueue = ExecSoc,
        ExecSoc + SocExecClear [is_locked] / unlock = Idle

    }
}

/// State machine extended variables.
pub struct Context {
    /// lock state
    pub locked: u32,
    /// Who acquired the lock.
    pub user: MailboxRequester,
    /// Execute flag
    pub exec: bool,
    /// number of data elements
    pub dlen: u32,
    /// Fifo storage
    pub fifo: Fifo,
    /// Mailbox Status
    status: StatusRegister,
    /// Command
    pub cmd: u32,
    // data_out
    data_out: u32,
}

impl Context {
    fn new(ram: MailboxRam) -> Self {
        Self {
            locked: 0,
            user: MailboxRequester::Caliptra,
            exec: false,
            dlen: 0,
            status: LocalRegisterCopy::new(0),
            fifo: Fifo::new(ram),
            cmd: 0,
            data_out: 0,
        }
    }
}

impl StateMachineContext for Context {
    // guards
    fn is_not_locked(&mut self, _user: &MailboxRequester) -> Result<(), ()> {
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

    //fn is_not_busy(&mut self, event_data: &StatusRegister) -> Result<(), ()> {
    //    let status = event_data.read(Status::STATUS);
    //    if status != Status::STATUS::CMD_BUSY.value {
    //        Ok(())
    //    } else {
    // no transition
    //        Err(())
    //    }
    //}

    // actions
    fn init_dlen(&mut self, data_len: &DataLength) {
        self.fifo.reset();
        self.dlen = data_len.0;

        self.fifo.latch_dlen(self.dlen as usize);
    }

    fn set_cmd(&mut self, cmd: &Cmd) {
        self.cmd = cmd.0;
    }

    fn lock(&mut self, user: &MailboxRequester) {
        self.fifo.reset();
        self.locked = 1;
        self.user = *user;
    }
    fn unlock(&mut self) {
        self.locked = 0;
        // Reset status
        self.status.set(0);
    }
    fn dequeue(&mut self) {
        if let Ok(data_out) = self.fifo.dequeue() {
            self.data_out = data_out;
        }
    }
    fn enqueue(&mut self, data_in: &DataIn) {
        self.fifo.enqueue(data_in.0);
    }
}

pub struct Fifo {
    latched_dlen: u32,
    capacity: usize,
    read_index: usize,
    write_index: usize,
    mailbox_ram: MailboxRam,
}

impl Fifo {
    pub fn new(ram: MailboxRam) -> Self {
        let ram_size = ram.ram.borrow().data().len();
        Fifo {
            latched_dlen: 0,
            capacity: ram_size,
            read_index: 0,
            write_index: 0,
            mailbox_ram: ram,
        }
    }
    pub fn latch_dlen(&mut self, dlen: usize) {
        if dlen > self.capacity {
            self.latched_dlen = self.capacity as u32;
            return;
        }
        self.latched_dlen = dlen as u32;
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
    pub fn dequeue(&mut self) -> Result<u32, ()> {
        if self.read_index >= self.latched_dlen as usize {
            return Err(());
        }

        let element = self
            .mailbox_ram
            .read(RvSize::Word, self.read_index as u32)
            .unwrap();

        self.read_index += RvSize::Word as usize;

        Ok(element)
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

    pub fn get_mailbox() -> MailboxInternal {
        let ram = MailboxRam::new();
        // Acquire lock
        let soc_to_mailbox_regs = Rc::new(RefCell::new(MailboxRegs::new(ram)));
        MailboxInternal::new(soc_to_mailbox_regs)
    }

    pub fn get_mbox_regs(ram: MailboxRam) -> Soc2CaliptraMailboxRegs {
        Rc::new(RefCell::new(MailboxRegs::new(ram)))
    }

    #[test]
    fn test_soc_to_caliptra_lock() {
        let regs = get_mbox_regs(MailboxRam::new());
        let mut caliptra = MailboxInternal::new(regs.clone());
        let mut soc = MailboxExternal::new(regs);

        assert_eq!(soc.read(RvSize::Word, OFFSET_LOCK).unwrap(), 0);
        // Confirm it is locked
        let soc_has_lock = soc.read(RvSize::Word, OFFSET_LOCK).unwrap();
        assert_eq!(soc_has_lock, 1);

        // Confirm caliptra has lock
        let caliptra_has_lock = caliptra.read(RvSize::Word, OFFSET_LOCK).unwrap();
        assert_eq!(caliptra_has_lock, 1);
    }

    #[test]
    fn test_send_receive() {
        let request_to_send: [u32; 4] = [0x1111_1111, 0x2222_2222, 0x3333_3333, 0x4444_4444];

        let regs = get_mbox_regs(MailboxRam::new());
        let mut caliptra = MailboxInternal::new(regs.clone());
        let mut soc = MailboxExternal::new(regs);

        assert_eq!(soc.read(RvSize::Word, OFFSET_LOCK).unwrap(), 0);
        // Confirm it is locked
        let lock = soc.read(RvSize::Word, OFFSET_LOCK).unwrap();
        assert_eq!(lock, 1);

        let user = soc.read(RvSize::Word, OFFSET_USER).unwrap();
        assert_eq!(user, MailboxRequester::Soc as u32);

        // Write command
        assert_eq!(soc.write(RvSize::Word, OFFSET_CMD, 0x55).ok(), Some(()));
        // Confirm it is locked
        assert_eq!(soc.regs.borrow().state_machine.context.locked, 1);

        let dlen = request_to_send.len() as u32;
        let dlen = dlen * 4;
        // Write dlen
        assert_eq!(soc.write(RvSize::Word, OFFSET_DLEN, dlen).ok(), Some(()));

        // Confirm it is locked
        assert_eq!(soc.regs.borrow().state_machine.context.locked, 1);

        for data_in in request_to_send.iter() {
            // Write datain
            assert_eq!(
                soc.write(RvSize::Word, OFFSET_DATAIN, *data_in).ok(),
                Some(())
            );
            // Confirm it is locked
            assert_eq!(soc.regs.borrow().state_machine.context.locked, 1);
        }
        assert_eq!(
            soc.write(
                RvSize::Word,
                OFFSET_STATUS,
                Status::STATUS::DATA_READY.value
            )
            .ok(),
            Some(())
        );

        // Write exec
        assert_eq!(soc.write(RvSize::Word, OFFSET_EXECUTE, 0x55).ok(), Some(()));
        // Confirm it is locked
        assert_eq!(soc.regs.borrow().state_machine.context.locked, 1);

        assert!(matches!(
            soc.regs.borrow().state_machine.state(),
            States::ExecSoc
        ));

        let status = caliptra.read(RvSize::Word, OFFSET_STATUS).unwrap();
        assert_eq!(
            status,
            (Status::STATUS::DATA_READY + Status::MBOX_FSM_PS::MBOX_EXECUTE_SOC).value
        );

        let cmd = caliptra.read(RvSize::Word, OFFSET_CMD).unwrap();
        assert_eq!(cmd, 0x55);

        let dlen = caliptra.read(RvSize::Word, OFFSET_DLEN).unwrap();
        assert_eq!(dlen, (request_to_send.len() * 4) as u32);

        request_to_send.iter().for_each(|data_in| {
            // Read dataout
            let data_out = caliptra.read(RvSize::Word, OFFSET_DATAOUT).unwrap();
            // compare with queued data.
            assert_eq!(*data_in, data_out);
        });
        assert_eq!(
            caliptra
                .write(
                    RvSize::Word,
                    OFFSET_STATUS,
                    Status::STATUS::CMD_COMPLETE.value
                )
                .ok(),
            Some(())
        );

        // Receiver resets exec register
        assert_eq!(soc.write(RvSize::Word, OFFSET_EXECUTE, 0).ok(), Some(()));
        // Confirm it is unlocked
        assert_eq!(caliptra.regs.borrow().state_machine.context.locked, 0);

        assert!(matches!(
            caliptra.regs.borrow().state_machine.state(),
            States::Idle
        ));
    }

    #[test]
    fn test_sm_init() {
        let mb = get_mailbox();
        assert!(matches!(
            mb.regs.borrow().state_machine.state(),
            States::Idle
        ));
        assert_eq!(mb.regs.borrow().state_machine.context().locked, 0);
    }

    #[test]
    fn test_sm_lock() {
        let mb = get_mailbox();
        assert_eq!(mb.regs.borrow().state_machine.context().locked, 0);
        assert_eq!(mb.regs.borrow().state_machine.context().dlen, 0);

        let _ = mb
            .regs
            .borrow_mut()
            .state_machine
            .process_event(Events::RdLock(MailboxRequester::Caliptra));
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
            .process_event(Events::UcExecSet);
        assert!(matches!(
            mb.regs.borrow().state_machine.state(),
            States::ExecUc
        ));

        let _ = mb
            .regs
            .borrow_mut()
            .state_machine
            .process_event(Events::UcExecClear);
        assert!(matches!(
            mb.regs.borrow().state_machine.state(),
            States::Idle
        ));
        assert_eq!(mb.regs.borrow().state_machine.context().locked, 0);
    }

    #[test]
    fn test_send_receive_max_limit() {
        // Acquire lock
        let mut mb = get_mailbox();
        assert_eq!(mb.read(RvSize::Word, OFFSET_LOCK).unwrap(), 0);
        // Confirm it is locked
        let lock = mb.read(RvSize::Word, OFFSET_LOCK).unwrap();
        assert_eq!(lock, 1);

        let user = mb.read(RvSize::Word, OFFSET_USER).unwrap();
        assert_eq!(user, MailboxRequester::Caliptra as u32);

        // Write command
        assert_eq!(mb.write(RvSize::Word, OFFSET_CMD, 0x55).ok(), Some(()));

        // Write dlen
        assert_eq!(
            mb.write(
                RvSize::Word,
                OFFSET_DLEN,
                (MAX_MAILBOX_CAPACITY_BYTES + 4) as u32
            )
            .ok(),
            Some(())
        );

        for data_in in (0..MAX_MAILBOX_CAPACITY_BYTES).step_by(4) {
            // Write datain
            assert_eq!(
                mb.write(RvSize::Word, OFFSET_DATAIN, data_in as u32).ok(),
                Some(())
            );
        }

        // Write an additional DWORD. This should be a no-op.
        assert_eq!(
            mb.write(RvSize::Word, OFFSET_DATAIN, 0xDEADBEEF).ok(),
            Some(())
        );

        assert_eq!(
            mb.write(
                RvSize::Word,
                OFFSET_STATUS,
                Status::STATUS::DATA_READY.value
            )
            .ok(),
            Some(())
        );

        // Write exec
        assert_eq!(mb.write(RvSize::Word, OFFSET_EXECUTE, 0x55).ok(), Some(()));

        assert!(matches!(
            mb.regs.borrow().state_machine.state(),
            States::ExecUc
        ));

        let status = mb.read(RvSize::Word, OFFSET_STATUS).unwrap();
        assert_eq!(
            status,
            (Status::STATUS::DATA_READY + Status::MBOX_FSM_PS::MBOX_EXECUTE_UC).value
        );

        let cmd = mb.read(RvSize::Word, OFFSET_CMD).unwrap();
        assert_eq!(cmd, 0x55);

        let dlen = mb.read(RvSize::Word, OFFSET_DLEN).unwrap();
        assert_eq!(dlen, (MAX_MAILBOX_CAPACITY_BYTES + 4) as u32);

        let mut data_out = 0;
        for data_in in (0..MAX_MAILBOX_CAPACITY_BYTES).step_by(4) {
            // Read dataout
            data_out = mb.read(RvSize::Word, OFFSET_DATAOUT).unwrap();
            // compare with queued data.
            assert_eq!(data_in as u32, data_out);
        }

        // Read an additional DWORD. This should return the last word
        assert_eq!(mb.read(RvSize::Word, OFFSET_DATAOUT).unwrap(), data_out);

        assert_eq!(
            mb.write(
                RvSize::Word,
                OFFSET_STATUS,
                Status::STATUS::CMD_COMPLETE.value
            )
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
}
