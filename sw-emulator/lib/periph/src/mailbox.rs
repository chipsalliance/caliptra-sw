/*++

Licensed under the Apache-2.0 license.

File Name:

    mailbox.rs

Abstract:

    File contains MAILBOX implementation

--*/
use smlang::statemachine;

use caliptra_emu_bus::{AlignedRam, Bus, BusMmio, Clock, Timer};
use caliptra_emu_bus::{BusError, ReadOnlyRegister, ReadWriteRegister, WriteOnlyRegister};
use caliptra_emu_derive::Bus;
use caliptra_emu_types::{RvAddr, RvData, RvSize};
use std::{cell::RefCell, rc::Rc};
use tock_registers::interfaces::Writeable;
use tock_registers::{register_bitfields, LocalRegisterCopy};

// Mailbox size when in subsystem mode.
const MBOX_SIZE_SUBSYSTEM: usize = 16 << 10;

// Mailbox size when in passive mode.
const MBOX_SIZE_PASSIVE: usize = 256 << 10;

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
            MBOX_ERROR = 0x7,
        ],
        SOC_HAS_LOCK OFFSET(9) NUMBITS(1) [],
        RSVD OFFSET(10) NUMBITS(22) [],
    ],

];

type StatusRegister = LocalRegisterCopy<u32, Status::Register>;

#[derive(Clone)]
pub struct MailboxRam {
    ram: Rc<RefCell<AlignedRam>>,
}

impl MailboxRam {
    pub fn new(subsystem_mode: bool) -> Self {
        let mbox_len = if subsystem_mode {
            MBOX_SIZE_SUBSYSTEM
        } else {
            MBOX_SIZE_PASSIVE
        };
        Self {
            ram: Rc::new(RefCell::new(AlignedRam::new(vec![0u8; mbox_len]))),
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
        Self::new(false)
    }
}

#[derive(Clone)]
pub struct MailboxExternal {
    pub soc_user: MailboxRequester,
    pub regs: Rc<RefCell<MailboxRegs>>,
}
impl MailboxExternal {
    pub fn regs(&mut self) -> caliptra_registers::mbox::RegisterBlock<BusMmio<Self>> {
        unsafe {
            caliptra_registers::mbox::RegisterBlock::new_with_mmio(
                std::ptr::null_mut::<u32>(),
                BusMmio::new(self.clone()),
            )
        }
    }
}

impl Bus for MailboxExternal {
    /// Read data of specified size from given address
    fn read(&mut self, size: RvSize, addr: RvAddr) -> Result<RvData, BusError> {
        let mut regs = self.regs.borrow_mut();
        regs.set_request(self.soc_user);
        let result = regs.read(size, addr);
        regs.set_request(MailboxRequester::Caliptra);
        result
    }

    /// Write data of specified size to given address
    fn write(&mut self, size: RvSize, addr: RvAddr, val: RvData) -> Result<(), BusError> {
        let mut regs = self.regs.borrow_mut();
        regs.set_request(self.soc_user);
        let result = regs.write(size, addr, val);
        regs.set_request(MailboxRequester::Caliptra);
        result
    }
}

#[derive(Clone)]
pub struct MailboxInternal {
    regs: Rc<RefCell<MailboxRegs>>,
}

/// Mailbox Peripheral
impl MailboxInternal {
    pub fn new(clock: &Clock, ram: MailboxRam) -> Self {
        Self {
            regs: Rc::new(RefCell::new(MailboxRegs::new(clock, ram))),
        }
    }

    pub fn regs(&mut self) -> caliptra_registers::mbox::RegisterBlock<BusMmio<Self>> {
        unsafe {
            caliptra_registers::mbox::RegisterBlock::new_with_mmio(
                std::ptr::null_mut::<u32>(),
                BusMmio::new(self.clone()),
            )
        }
    }

    pub fn mailbox_regs(&mut self) -> Rc<RefCell<MailboxRegs>> {
        self.regs.clone()
    }

    pub fn as_external(&self, soc_user: MailboxRequester) -> MailboxExternal {
        MailboxExternal {
            soc_user,
            regs: self.regs.clone(),
        }
    }

    pub fn get_notif_irq(&mut self) -> bool {
        let mut regs = self.regs.borrow_mut();
        if regs.irq {
            regs.irq = false;
            return true;
        }
        false
    }
}

impl Bus for MailboxInternal {
    /// Read data of specified size from given address
    fn read(&mut self, size: RvSize, addr: RvAddr) -> Result<RvData, BusError> {
        self.regs
            .borrow_mut()
            .set_request(MailboxRequester::Caliptra);
        self.regs.borrow_mut().read(size, addr)
    }

    /// Write data of specified size to given address
    fn write(&mut self, size: RvSize, addr: RvAddr, val: RvData) -> Result<(), BusError> {
        self.regs
            .borrow_mut()
            .set_request(MailboxRequester::Caliptra);
        self.regs.borrow_mut().write(size, addr, val)
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]

pub enum MailboxRequester {
    Caliptra,
    SocUser(u32),
}

impl From<u32> for MailboxRequester {
    fn from(value: u32) -> Self {
        match value {
            0xFFFF_FFFF => MailboxRequester::Caliptra,
            _ => MailboxRequester::SocUser(value),
        }
    }
}

impl From<MailboxRequester> for u32 {
    fn from(val: MailboxRequester) -> Self {
        match val {
            MailboxRequester::Caliptra => 0xFFFF_FFFF,
            MailboxRequester::SocUser(pauser) => pauser,
        }
    }
}

/// Mailbox register accesses that are subject to the SoC request-phase protocol
/// checks (see [`MailboxRegs::fsm_rejects`]).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Access {
    /// Write to MBOX_CMD.
    Cmd,
    /// Write to MBOX_DLEN.
    Dlen,
    /// Write to MBOX_DATAIN.
    DataIn,
    /// Write to MBOX_EXECUTE.
    Execute,
    /// Write to MBOX_STATUS.
    Status,
    /// Write to MBOX_UNLOCK.
    Unlock,
    /// Read of MBOX_DATAOUT.
    DataOut,
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

    /// MBOX_UNLOCK register
    #[register(offset = 0x0000_0020, write_fn = write_unlock, read_fn = read_unlock)]
    _unlock: ReadWriteRegister<u32>,

    /// MBOX_TAP_MODE register
    #[register(offset = 0x0000_0024)]
    _tap_mode: ReadWriteRegister<u32>,

    /// State Machine
    state_machine: StateMachine<Context>,

    pub requester: MailboxRequester,

    /// Trigger interrupt
    irq: bool,

    /// Timer
    timer: Timer,
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
    const UNLOCK_VAL: RvData = 0x0;

    /// Create a new instance of Mailbox registers
    pub fn new(clock: &Clock, ram: MailboxRam) -> Self {
        Self {
            lock: ReadOnlyRegister::new(Self::LOCK_VAL),
            user: ReadOnlyRegister::new(Self::USER_VAL),
            _cmd: ReadWriteRegister::new(Self::CMD_VAL),
            _dlen: ReadWriteRegister::new(Self::DLEN_VAL),
            data_in: WriteOnlyRegister::new(Self::DATA_IN_VAL),
            data_out: ReadOnlyRegister::new(Self::DATA_OUT_VAL),
            execute: ReadWriteRegister::new(Self::EXEC_VAL),
            _status: ReadWriteRegister::new(Self::STATUS_VAL),
            _unlock: ReadWriteRegister::new(Self::UNLOCK_VAL),
            _tap_mode: ReadWriteRegister::new(0),
            state_machine: StateMachine::new(Context::new(ram)),
            requester: MailboxRequester::Caliptra,
            irq: false,
            timer: Timer::new(clock),
        }
    }
    pub fn set_request(&mut self, requester: MailboxRequester) {
        self.requester = requester;
    }

    /// Returns `true` if the FSM does not accept `access` by the current requester.
    ///
    /// While a SoC agent that holds the lock is filling the mailbox the RTL only
    /// accepts the access that advances the following protocol:
    ///
    /// | State          | Accepted access                       |
    /// |----------------|---------------------------------------|
    /// | `RDY_FOR_CMD`  | write `MBOX_CMD`                      |
    /// | `RDY_FOR_DLEN` | write `MBOX_DLEN`                     |
    /// | `RDY_FOR_DATA` | write `MBOX_DATAIN` or `MBOX_EXECUTE` |
    /// | `MBOX_ERROR`   | none                                  |
    ///
    /// Any other write, or a read of `MBOX_DATAOUT`, is a protocol error that parks
    /// the FSM in `MBOX_ERROR`. Accesses by other agents are __silently__ dropped
    /// by the RTL, and the Caliptra microcontroller is assumed never to make an
    /// invalid request, so neither is rejected here.
    ///
    /// The RTL also flags a SoC write to `MBOX_TAP_MODE`. The register is a plain
    /// read/write register in the emulator, hence this is not modeled.
    fn fsm_rejects(&self, access: Access) -> bool {
        if !(matches!(self.requester, MailboxRequester::SocUser(_))
            && self.state_machine.context.locked != 0
            && self.requester == self.state_machine.context.user)
        {
            // the SoC is not the owner, so reject.
            return false;
        }

        let accepted: &[Access] = match self.state_machine.state() {
            States::RdyForCmd => &[Access::Cmd],
            States::RdyForDlen => &[Access::Dlen],
            States::RdyForData => &[Access::DataIn, Access::Execute],
            States::Error => &[],
            _ => return false,
        };
        !accepted.contains(&access)
    }

    /// Moves the FSM to `MBOX_ERROR` if it does not accept `access` (see
    /// [`Self::fsm_rejects`]) and returns true in that case. Only a force unlock
    /// from Caliptra (`MBOX_UNLOCK` written by the microcontroller) leaves `MBOX_ERROR`.
    ///
    /// A rejected access does not reach the FSM. Whether it still changes a register
    /// is up to the caller. The RTL stores writes to `MBOX_CMD`, `MBOX_DLEN` and
    /// `MBOX_EXECUTE` whatever the state of the FSM (`swwe = valid_requester`).
    /// Outside `MBOX_EXECUTE_SOC` the SoC is not a valid receiver, so writes to
    /// `MBOX_STATUS` are dropped and reads of `MBOX_DATAOUT` are masked. SoC writes
    /// to `MBOX_UNLOCK` are never stored (`swwel = soc_req`), and data written to
    /// `MBOX_DATAIN` is only added to the mailbox in `RDY_FOR_DATA`.
    fn reject(&mut self, access: Access) -> bool {
        if !self.fsm_rejects(access) {
            return false;
        }
        let _ = self.state_machine.process_event(Events::OutOfOrder);
        true
    }

    // Todo: Implement read_lock callback fn
    pub fn read_lock(&mut self, _size: RvSize) -> Result<u32, BusError> {
        // If state is not idle mailbox is locked.
        let result = match self.state_machine.state() {
            States::Idle => Ok(0),
            _ => Ok(1),
        };
        // Deliver event to the state machine.
        let _ = self
            .state_machine
            .process_event(Events::RdLock(self.requester));

        result
    }

    // Todo: Implement read_user callback fn
    pub fn read_user(&self, _size: RvSize) -> Result<MailboxRequester, BusError> {
        Ok(self.state_machine.context.user)
    }

    // Todo: Implement write cmd callback fn
    pub fn write_cmd(&mut self, _size: RvSize, val: RvData) -> Result<(), BusError> {
        if self.reject(Access::Cmd) {
            // The FSM does not accept the write, but the register stores it.
            self.state_machine.context.cmd = val;
            return Ok(());
        }
        let _ = self.state_machine.process_event(Events::CmdWrite(Cmd(val)));
        Ok(())
    }

    // Todo: Implement read cmd callback fn
    pub fn read_cmd(&self, _size: RvSize) -> Result<u32, BusError> {
        Ok(self.state_machine.context.cmd)
    }

    // Todo: Implement write dlen callback fn
    pub fn write_dlen(&mut self, _size: RvSize, val: RvData) -> Result<(), BusError> {
        if self.reject(Access::Dlen) {
            // The FSM does not accept the write, but the register stores it.
            self.state_machine.context.dlen = val;
            return Ok(());
        }
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
        if self.reject(Access::DataIn) {
            return Ok(());
        }
        let _ = self
            .state_machine
            .process_event(Events::DataWrite(DataIn(val)));
        Ok(())
    }

    // Todo: Implement read dout callback fn
    pub fn read_dout(&mut self, _size: RvSize) -> Result<u32, BusError> {
        if self.reject(Access::DataOut) {
            // The RTL masks the read data of an agent that is not a valid receiver.
            return Ok(0);
        }
        let mb = &mut self.state_machine;
        let _ = mb.process_event(Events::DataRead);
        Ok(mb.context.data_out)
    }

    /// Write to execute register
    pub fn write_ex(&mut self, _size: RvSize, val: RvData) -> Result<(), BusError> {
        if self.reject(Access::Execute) {
            // The FSM does not accept the write, but the register stores it.
            // The microcontroller is not notified: there is no request to run.
            self.execute.reg.set(val);
            return Ok(());
        }
        // Only the lock owner can clear the execute bit.
        if self.requester != self.state_machine.context.user {
            let _ = self.state_machine.process_event(Events::Error);
            return Ok(());
        }

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

        // Notify soc_reg
        self.irq = true;
        self.timer.schedule_poll_in(1);

        let _ = self.state_machine.process_event(event);
        self.execute.reg.set(val);
        Ok(())
    }

    // Todo: Implement write status callback fn
    pub fn write_status(&mut self, _size: RvSize, val: RvData) -> Result<(), BusError> {
        if self.reject(Access::Status) {
            return Ok(());
        }
        // Send event to state machine.
        let _ = self.state_machine.process_event(Events::SetStatus);

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
            States::ExecUc => Status::MBOX_FSM_PS::MBOX_EXECUTE_UC,
            States::ExecSoc => Status::MBOX_FSM_PS::MBOX_EXECUTE_SOC,
            States::Idle => Status::MBOX_FSM_PS::MBOX_IDLE,
            States::RdyForCmd => Status::MBOX_FSM_PS::MBOX_RDY_FOR_CMD,
            States::RdyForData => Status::MBOX_FSM_PS::MBOX_RDY_FOR_DATA,
            States::RdyForDlen => Status::MBOX_FSM_PS::MBOX_RDY_FOR_DLEN,
            States::Error => Status::MBOX_FSM_PS::MBOX_ERROR,
        });
        Ok(result.get())
    }

    pub fn write_unlock(&mut self, _size: RvSize, _val: RvData) -> Result<(), BusError> {
        if self.reject(Access::Unlock) {
            return Ok(());
        }
        // Only the Caliptra microcontroller can force unlock the mailbox; the
        // RTL drops SoC writes to MBOX_UNLOCK.
        if matches!(self.requester, MailboxRequester::SocUser(_)) {
            return Ok(());
        }
        let _ = self.state_machine.process_event(Events::WrUnlock);
        Ok(())
    }

    pub fn read_unlock(&self, _size: RvSize) -> Result<u32, BusError> {
        Ok(self.state_machine.context.unlock)
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
#[allow(dead_code)]
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
        RdyForCmd + WrUnlock  / unlock_and_reset = Idle,
        //the SoC lock owner accessed the mailbox out of order.
        RdyForCmd + OutOfOrder = Error,

        //move from rdy for dlen to rdy for data when dlen is written to.
        RdyForDlen + DlenWrite(DataLength) / init_dlen = RdyForData,
        RdyForDlen + WrUnlock = Idle,
        RdyForDlen + OutOfOrder = Error,

        RdyForData + DataWrite(DataIn) / enqueue = RdyForData,
        RdyForData + WrUnlock  / unlock_and_reset = Idle,
        RdyForData + OutOfOrder = Error,

        //move from rdy for data to execute uc  when soc sets execute bit.
        RdyForData + SocExecSet = ExecUc,

        //move from rdy for data to execute soc when soc sets execute bit.
        RdyForData + UcExecSet = ExecSoc,

        ExecUc + DataRead / dequeue = ExecUc,
        ExecUc + DlenWrite(DataLength) / init_dlen = ExecUc,
        ExecUc + DataWrite(DataIn) / enqueue = ExecUc,
        ExecUc + SocExecClear [is_locked] / unlock = Idle,
        ExecUc + UcExecClear [is_locked] / unlock = Idle,
        ExecUc + SetStatus = ExecSoc,
        ExecUc + WrUnlock  / unlock_and_reset = Idle,

        ExecSoc + DataRead / dequeue = ExecSoc,
        ExecSoc + DlenWrite(DataLength) / init_dlen = ExecSoc,
        ExecSoc + DataWrite(DataIn) / enqueue = ExecSoc,
        ExecSoc + UcExecClear [is_locked] / unlock = Idle,
        ExecSoc + SocExecClear [is_locked] / unlock = Idle,
        ExecSoc + Error = Error,
        ExecSoc + SetStatus = ExecUc,
        ExecSoc + WrUnlock  / unlock_and_reset = Idle,

        Error + WrUnlock  / unlock_and_reset = Idle,

    }
}

/// State machine extended variables.
pub struct Context {
    /// lock state
    pub locked: u32,
    /// Who acquired the lock.
    pub user: MailboxRequester,
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
    // unlock
    pub unlock: u32,
}

impl Context {
    fn new(ram: MailboxRam) -> Self {
        Self {
            locked: 0,
            user: MailboxRequester::Caliptra,
            dlen: 0,
            status: LocalRegisterCopy::new(0),
            fifo: Fifo::new(ram),
            cmd: 0,
            data_out: 0,
            unlock: 0,
        }
    }
}

impl StateMachineContext for Context {
    // guards
    fn is_not_locked(&self, _user: &MailboxRequester) -> Result<bool, ()> {
        if self.locked == 1 {
            // no transition
            Err(())
        } else {
            Ok(true)
        }
    }

    fn is_locked(&self) -> Result<bool, ()> {
        if self.locked != 0 {
            Ok(true)
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
    fn init_dlen(&mut self, data_len: DataLength) -> Result<(), ()> {
        self.fifo.reset();
        self.dlen = data_len.0;

        self.fifo.latch_dlen(self.dlen as usize);
        Ok(())
    }

    fn set_cmd(&mut self, cmd: Cmd) -> Result<(), ()> {
        self.cmd = cmd.0;
        Ok(())
    }

    fn lock(&mut self, user: MailboxRequester) -> Result<(), ()> {
        self.fifo.reset();
        self.locked = 1;
        self.user = user;
        Ok(())
    }
    fn unlock(&mut self) -> Result<(), ()> {
        self.locked = 0;
        // Reset status
        self.status.set(0);
        Ok(())
    }
    fn dequeue(&mut self) -> Result<(), ()> {
        self.data_out = self.fifo.dequeue().unwrap_or(0);
        Ok(())
    }
    fn enqueue(&mut self, data_in: DataIn) -> Result<(), ()> {
        self.fifo.enqueue(data_in.0);
        Ok(())
    }
    fn unlock_and_reset(&mut self) -> Result<(), ()> {
        self.unlock()?;
        self.fifo.reset();
        Ok(())
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

    pub fn get_mailbox() -> MailboxInternal {
        // Acquire lock
        MailboxInternal::new(&Clock::new(), MailboxRam::default())
    }

    #[test]
    fn test_sm_arc_rdyfordata_unlock() {
        // Acquire lock
        let mut mb = get_mailbox();
        let uc_regs = mb.regs();
        assert!(!uc_regs.lock().read().lock());
        // Confirm it is locked
        assert!(uc_regs.lock().read().lock());

        assert_eq!(uc_regs.user().read(), 0xFFFF_FFFF);

        // Write command
        uc_regs.cmd().write(|_| 0x55);
        // Confirm it is locked
        assert_eq!(mb.regs.borrow().state_machine.context.locked, 1);

        // Release lock
        let _ = mb
            .regs
            .borrow_mut()
            .state_machine
            .process_event(Events::WrUnlock);

        // Check transition to idle
        assert!(matches!(
            mb.regs.borrow().state_machine.state(),
            States::Idle
        ));
    }

    #[test]
    fn test_sm_arc_rdyforcmd_unlock() {
        let mb = get_mailbox();
        assert_eq!(mb.regs.borrow().state_machine.context().locked, 0);
        assert_eq!(mb.regs.borrow().state_machine.context().dlen, 0);
        // Acquire lock
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

        // Release lock
        let _ = mb
            .regs
            .borrow_mut()
            .state_machine
            .process_event(Events::WrUnlock);

        assert_eq!(mb.regs.borrow().state_machine.context().locked, 0);
        assert!(matches!(
            mb.regs.borrow().state_machine.state(),
            States::Idle
        ));
    }

    #[test]
    fn test_soc_to_caliptra_lock() {
        let mut caliptra = MailboxInternal::new(&Clock::new(), MailboxRam::default());
        let mut soc = caliptra.as_external(MailboxRequester::SocUser(1u32));
        let soc_regs = soc.regs();

        assert!(!soc_regs.lock().read().lock());
        // Confirm it is locked
        assert!(soc_regs.lock().read().lock());

        // Confirm caliptra has lock
        let caliptra_has_lock = caliptra.regs().lock().read().lock();
        assert!(caliptra_has_lock);
    }

    #[test]
    fn test_send_receive() {
        let request_to_send: [u32; 4] = [0x1111_1111, 0x2222_2222, 0x3333_3333, 0x4444_4444];

        let mut caliptra = MailboxInternal::new(&Clock::new(), MailboxRam::default());
        let mut soc = caliptra.as_external(MailboxRequester::SocUser(1u32));
        let soc_regs = soc.regs();
        let uc_regs = caliptra.regs();

        assert!(!soc_regs.lock().read().lock());
        // Confirm it is locked
        assert!(soc_regs.lock().read().lock());

        assert_eq!(
            MailboxRequester::SocUser(soc_regs.user().read()),
            MailboxRequester::SocUser(1u32)
        );

        // Write command
        soc_regs.cmd().write(|_| 0x55);
        // Confirm it is locked
        assert_eq!(soc.regs.borrow().state_machine.context.locked, 1);

        let dlen = request_to_send.len() as u32;
        let dlen = dlen * 4;
        // Write dlen
        soc_regs.dlen().write(|_| dlen);

        // Confirm it is locked
        assert_eq!(soc.regs.borrow().state_machine.context.locked, 1);

        for data_in in request_to_send.iter() {
            // Write datain
            soc_regs.datain().write(|_| *data_in);
            // Confirm it is locked
            assert_eq!(soc.regs.borrow().state_machine.context.locked, 1);
        }

        // Write exec. The SoC must not touch the status register while it is
        // filling the mailbox; only the receiver reports a status.
        soc_regs.execute().write(|w| w.execute(true));
        // Confirm it is locked
        assert_eq!(soc.regs.borrow().state_machine.context.locked, 1);

        assert!(matches!(
            soc.regs.borrow().state_machine.state(),
            States::ExecUc
        ));

        assert_eq!(
            u32::from(uc_regs.status().read()),
            (Status::STATUS::CMD_BUSY + Status::MBOX_FSM_PS::MBOX_EXECUTE_UC).value
        );

        assert_eq!(uc_regs.cmd().read(), 0x55);

        let dlen = uc_regs.dlen().read();
        assert_eq!(dlen, (request_to_send.len() * 4) as u32);

        request_to_send.iter().for_each(|data_in| {
            // Read dataout
            let data_out = uc_regs.dataout().read();
            // compare with queued data.
            assert_eq!(*data_in, data_out);
        });
        uc_regs.status().write(|w| w.status(|w| w.cmd_complete()));

        // Requester resets exec register
        soc_regs.execute().write(|w| w.execute(false));
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
            States::ExecSoc
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
        let uc_regs = mb.regs();

        assert!(!uc_regs.lock().read().lock());
        // Confirm it is locked
        assert!(uc_regs.lock().read().lock());

        let user = uc_regs.user().read();
        assert_eq!(MailboxRequester::from(user), MailboxRequester::Caliptra);

        // Write command
        uc_regs.cmd().write(|_| 0x55);

        // Write dlen
        uc_regs.dlen().write(|_| (MBOX_SIZE_PASSIVE + 4) as u32);

        for data_in in (0..MBOX_SIZE_PASSIVE).step_by(4) {
            // Write datain
            uc_regs.datain().write(|_| data_in as u32);
        }

        // Write an additional DWORD. This should be a no-op.
        uc_regs.datain().write(|_| 0xDEADBEEF);

        uc_regs.status().write(|w| w.status(|w| w.data_ready()));

        uc_regs.execute().write(|w| w.execute(true));

        assert!(matches!(
            mb.regs.borrow().state_machine.state(),
            States::ExecSoc
        ));

        assert_eq!(
            u32::from(uc_regs.status().read()),
            (Status::STATUS::DATA_READY + Status::MBOX_FSM_PS::MBOX_EXECUTE_SOC).value
        );

        assert_eq!(uc_regs.cmd().read(), 0x55);

        assert_eq!(uc_regs.dlen().read(), (MBOX_SIZE_PASSIVE + 4) as u32);

        for data_in in (0..MBOX_SIZE_PASSIVE).step_by(4) {
            let data_out = uc_regs.dataout().read();
            assert_eq!(data_in as u32, data_out);
        }

        // Read an additional DWORD. This should return zero
        assert_eq!(uc_regs.dataout().read(), 0);

        uc_regs.status().write(|w| w.status(|w| w.cmd_complete()));
        uc_regs.execute().write(|w| w.execute(false));
        assert_eq!(mb.regs.borrow().state_machine.context.locked, 0);

        assert!(matches!(
            mb.regs.borrow().state_machine.state(),
            States::Idle
        ));
    }

    type SocRegs = caliptra_registers::mbox::RegisterBlock<BusMmio<MailboxExternal>>;

    /// An access of the SoC to its register block.
    type SocAccess = fn(&SocRegs);

    /// How far the SoC lock owner has advanced its request.
    #[derive(Clone, Copy, Debug)]
    enum Stage {
        /// Lock taken: the mailbox is in RDY_FOR_CMD.
        Locked,
        /// Command written: RDY_FOR_DLEN.
        CmdWritten,
        /// Data length written: RDY_FOR_DATA.
        DlenWritten,
    }

    /// The command the SoC lock owner writes in order.
    const SOC_CMD: u32 = 0x55;

    /// The data length in bytes the SoC lock owner writes in order: two words.
    const SOC_DLEN: u32 = 8;

    /// A command written out of order. It differs from `SOC_CMD` so that a read-back can tell the two apart.
    const OOO_CMD: u32 = 0x66;

    /// A data length written out of order. It differs from `SOC_DLEN` so that a read-back can tell the two apart.
    const OOO_DLEN: u32 = 16;

    /// A mailbox locked by SoC agent 1 and advanced to `stage`, with `SOC_CMD`
    /// and `SOC_DLEN` written as far as the stage allows.
    fn soc_owned_mailbox(stage: Stage) -> (MailboxInternal, MailboxExternal) {
        let caliptra = get_mailbox();
        let mut soc = caliptra.as_external(MailboxRequester::SocUser(1));
        let regs = soc.regs();
        assert!(!regs.lock().read().lock());
        if matches!(stage, Stage::CmdWritten | Stage::DlenWritten) {
            regs.cmd().write(|_| SOC_CMD);
        }
        if matches!(stage, Stage::DlenWritten) {
            regs.dlen().write(|_| SOC_DLEN);
        }
        (caliptra, soc)
    }

    /// The register of the SoC lock owner that an access changes. The RTL stores
    /// writes to MBOX_CMD, MBOX_DLEN and MBOX_EXECUTE whatever the state of the
    /// FSM (`swwe = valid_requester`). It does not store writes to MBOX_STATUS
    /// (the SoC is not a valid receiver in these states) and MBOX_UNLOCK, and
    /// data written to MBOX_DATAIN is not observable.
    #[derive(Clone, Copy, PartialEq)]
    enum StoredIn {
        Nothing,
        Cmd,
        Dlen,
        Execute,
    }

    /// An access of the SoC and the register it changes.
    struct AccessCase {
        name: &'static str,
        access: SocAccess,
        stored_in: StoredIn,
    }

    /// While the SoC lock owner fills the mailbox the RTL accepts only the access
    /// that advances the protocol; anything else parks the FSM in MBOX_ERROR.
    /// Writes to MBOX_CMD, MBOX_DLEN and MBOX_EXECUTE are stored either way.
    /// The expected behaviour was measured on the verilated RTL.
    #[test]
    fn test_soc_ooo_access_is_protocol_error() {
        use caliptra_registers::mbox::enums::MboxFsmE;

        let cases = [
            AccessCase {
                name: "cmd write",
                access: |r| r.cmd().write(|_| OOO_CMD),
                stored_in: StoredIn::Cmd,
            },
            AccessCase {
                name: "dlen write",
                access: |r| r.dlen().write(|_| OOO_DLEN),
                stored_in: StoredIn::Dlen,
            },
            AccessCase {
                name: "datain write",
                access: |r| r.datain().write(|_| 1),
                stored_in: StoredIn::Nothing,
            },
            AccessCase {
                name: "execute set",
                access: |r| r.execute().write(|w| w.execute(true)),
                stored_in: StoredIn::Execute,
            },
            AccessCase {
                name: "execute clear",
                access: |r| r.execute().write(|w| w.execute(false)),
                stored_in: StoredIn::Nothing,
            },
            AccessCase {
                name: "status write",
                access: |r| r.status().write(|w| w.status(|w| w.cmd_failure())),
                stored_in: StoredIn::Nothing,
            },
            AccessCase {
                name: "unlock write",
                access: |r| r.unlock().write(|w| w.unlock(true)),
                stored_in: StoredIn::Nothing,
            },
            AccessCase {
                name: "dataout read",
                access: |r| {
                    let _ = r.dataout().read();
                },
                stored_in: StoredIn::Nothing,
            },
        ];
        // The accesses that are accepted in each state, and where they lead.
        let expected_fsm = |stage: Stage, access: &str| match (stage, access) {
            (Stage::Locked, "cmd write") => MboxFsmE::MboxRdyForDlen,
            (Stage::CmdWritten, "dlen write") => MboxFsmE::MboxRdyForData,
            (Stage::DlenWritten, "datain write" | "execute clear") => MboxFsmE::MboxRdyForData,
            (Stage::DlenWritten, "execute set") => MboxFsmE::MboxExecuteUc,
            _ => MboxFsmE::MboxError,
        };

        for stage in [Stage::Locked, Stage::CmdWritten, Stage::DlenWritten] {
            let setup_cmd = if matches!(stage, Stage::Locked) {
                0
            } else {
                SOC_CMD
            };
            let setup_dlen = if matches!(stage, Stage::DlenWritten) {
                SOC_DLEN
            } else {
                0
            };

            for case in &cases {
                let name = case.name;
                let (mb, mut soc) = soc_owned_mailbox(stage);
                let regs = soc.regs();
                (case.access)(&regs);

                let fsm = regs.status().read().mbox_fsm_ps();
                let want = expected_fsm(stage, name);
                assert!(
                    fsm == want,
                    "{stage:?}, {name}: FSM is {} but should be {}",
                    fsm as u32,
                    want as u32
                );

                // Each register holds what was written to it, and only the
                // registers that store the access changed.
                let want_cmd = if case.stored_in == StoredIn::Cmd {
                    OOO_CMD
                } else {
                    setup_cmd
                };
                let want_dlen = if case.stored_in == StoredIn::Dlen {
                    OOO_DLEN
                } else {
                    setup_dlen
                };
                assert_eq!(regs.cmd().read(), want_cmd, "{stage:?}, {name}: cmd");
                assert_eq!(regs.dlen().read(), want_dlen, "{stage:?}, {name}: dlen");
                assert_eq!(
                    regs.execute().read().execute(),
                    case.stored_in == StoredIn::Execute,
                    "{stage:?}, {name}: execute"
                );
                assert!(
                    regs.status().read().status().cmd_busy(),
                    "{stage:?}, {name}: status"
                );

                if want == MboxFsmE::MboxError {
                    // The lock stays held.
                    assert_eq!(mb.regs.borrow().state_machine.context.locked, 1);
                }
            }
        }
    }

    /// MBOX_ERROR is sticky: the SoC keeps the lock and can neither continue
    /// nor release the mailbox. Only a force unlock from Caliptra recovers.
    /// The registers of the lock owner still store its writes, as in the RTL.
    #[test]
    fn test_soc_protocol_error_is_only_cleared_by_caliptra_unlock() {
        let (mut caliptra, mut soc) = soc_owned_mailbox(Stage::Locked);
        let soc_regs = soc.regs();

        // Clearing `execute` before the request is complete is out of order.
        soc_regs.execute().write(|w| w.execute(false));
        assert!(soc_regs.status().read().mbox_fsm_ps().mbox_error());
        assert!(soc_regs.lock().read().lock());

        // The SoC can neither continue the request nor release the mailbox,
        // although MBOX_CMD, MBOX_DLEN and MBOX_EXECUTE still store its writes
        // (MBOX_STATUS does not).
        soc_regs.cmd().write(|_| SOC_CMD);
        soc_regs.dlen().write(|_| SOC_DLEN);
        soc_regs.execute().write(|w| w.execute(true));
        soc_regs.status().write(|w| w.status(|w| w.cmd_failure()));
        soc_regs.unlock().write(|w| w.unlock(true));
        assert_eq!(soc_regs.cmd().read(), SOC_CMD);
        assert_eq!(soc_regs.dlen().read(), SOC_DLEN);
        assert!(soc_regs.execute().read().execute());
        assert!(soc_regs.status().read().status().cmd_busy());
        assert!(soc_regs.status().read().mbox_fsm_ps().mbox_error());
        assert_eq!(caliptra.regs.borrow().state_machine.context.locked, 1);

        // Caliptra can.
        caliptra.regs().unlock().write(|w| w.unlock(true));
        assert!(soc_regs.status().read().mbox_fsm_ps().mbox_idle());
        assert_eq!(caliptra.regs.borrow().state_machine.context.locked, 0);
        assert!(!soc_regs.lock().read().lock());
    }

    /// A SoC that sets `execute` before it has written the data length violates
    /// the protocol, but the RTL still stores the data length it writes next and
    /// ignores the data it sends afterwards. Reading the mailbox returns zeros.
    #[test]
    fn test_soc_registers_still_store_writes_after_an_ooo_execute() {
        let (_caliptra, mut soc) = soc_owned_mailbox(Stage::CmdWritten);
        let regs = soc.regs();

        regs.execute().write(|w| w.execute(true));
        assert!(regs.status().read().mbox_fsm_ps().mbox_error());

        regs.dlen().write(|_| SOC_DLEN);
        assert_eq!(regs.dlen().read(), SOC_DLEN);
        regs.datain().write(|_| 1);
        assert_eq!(regs.dataout().read(), 0);
        assert!(regs.status().read().mbox_fsm_ps().mbox_error());
    }

    /// The RTL silently drops accesses by agents that do not hold the lock, and
    /// the Caliptra microcontroller is assumed to never make an invalid
    /// request, so neither of them is a protocol error.
    #[test]
    fn test_ooo_access_by_other_agents_is_not_a_protocol_error() {
        let (mut caliptra, _soc) = soc_owned_mailbox(Stage::Locked);

        let mut other = caliptra.as_external(MailboxRequester::SocUser(2));
        let other_regs = other.regs();
        other_regs.dlen().write(|_| SOC_DLEN);
        other_regs.datain().write(|_| 1);
        other_regs.execute().write(|w| w.execute(true));
        other_regs.status().write(|w| w.status(|w| w.cmd_failure()));
        other_regs.unlock().write(|w| w.unlock(true));
        let _ = other_regs.dataout().read();
        assert!(other_regs.status().read().mbox_fsm_ps().mbox_rdy_for_cmd());

        let uc_regs = caliptra.regs();
        uc_regs.dlen().write(|_| SOC_DLEN);
        uc_regs.datain().write(|_| 1);
        let _ = uc_regs.dataout().read();
        assert!(uc_regs.status().read().mbox_fsm_ps().mbox_rdy_for_cmd());
    }

    /// Same for a mailbox locked by the Caliptra microcontroller itself.
    #[test]
    fn test_caliptra_owner_ooo_access_is_not_a_protocol_error() {
        let mut mb = get_mailbox();
        let uc_regs = mb.regs();
        assert!(!uc_regs.lock().read().lock());

        uc_regs.dlen().write(|_| SOC_DLEN);
        uc_regs.datain().write(|_| 1);
        uc_regs.status().write(|w| w.status(|w| w.cmd_failure()));
        let _ = uc_regs.dataout().read();
        assert!(uc_regs.status().read().mbox_fsm_ps().mbox_rdy_for_cmd());
    }
}
