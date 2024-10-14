/*++

Licensed under the Apache-2.0 license.

File Name:

    mailbox.rs

Abstract:

    File contains MAILBOX implementation

--*/
use smlang::statemachine;

use caliptra_emu_bus::{Bus, BusMmio, Clock, Ram, Timer};
use caliptra_emu_bus::{BusError, ReadOnlyRegister, ReadWriteRegister, WriteOnlyRegister};
use caliptra_emu_derive::Bus;
use caliptra_emu_types::{RvAddr, RvData, RvSize};
use std::{cell::RefCell, rc::Rc};
use tock_registers::interfaces::Writeable;
use tock_registers::{register_bitfields, LocalRegisterCopy};

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
            MBOX_ERROR = 0x7,
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

#[derive(Clone)]
pub struct MailboxExternal {
    regs: Rc<RefCell<MailboxRegs>>,
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
        regs.set_request(MailboxRequester::Soc);
        let result = regs.read(size, addr);
        regs.set_request(MailboxRequester::Caliptra);
        result
    }

    /// Write data of specified size to given address
    fn write(&mut self, size: RvSize, addr: RvAddr, val: RvData) -> Result<(), BusError> {
        let mut regs = self.regs.borrow_mut();
        regs.set_request(MailboxRequester::Soc);
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

    pub fn as_external(&self) -> MailboxExternal {
        MailboxExternal {
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

    /// MBOX_UNLOCK register
    #[register(offset = 0x0000_0020, write_fn = write_unlock, read_fn = read_unlock)]
    _unlock: ReadWriteRegister<u32>,

    /// State Machine
    state_machine: StateMachine<Context>,

    pub requester: MailboxRequester,

    /// Trigger interrupt
    irq: bool,

    ///
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
            state_machine: StateMachine::new(Context::new(ram)),
            requester: MailboxRequester::Caliptra,
            irq: false,
            timer: Timer::new(clock),
        }
    }
    pub fn set_request(&mut self, requester: MailboxRequester) {
        self.requester = requester;
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

        //move from rdy for dlen to rdy for data when dlen is written to.
        RdyForDlen + DlenWrite(DataLength) / init_dlen = RdyForData,
        RdyForDlen + WrUnlock = Idle,

        RdyForData + DataWrite(DataIn) / enqueue = RdyForData,
        RdyForData + WrUnlock  / unlock_and_reset = Idle,

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
    // unlock
    pub unlock: u32,
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
            unlock: 0,
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
        self.data_out = self.fifo.dequeue().unwrap_or(0);
    }
    fn enqueue(&mut self, data_in: &DataIn) {
        self.fifo.enqueue(data_in.0);
    }
    fn unlock_and_reset(&mut self) {
        self.unlock();
        self.fifo.reset();
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
        MailboxInternal::new(&Clock::new(), MailboxRam::new())
    }

    #[test]
    fn test_sm_arc_rdyfordata_unlock() {
        // Acquire lock
        let mut mb = get_mailbox();
        let uc_regs = mb.regs();
        assert!(!uc_regs.lock().read().lock());
        // Confirm it is locked
        assert!(uc_regs.lock().read().lock());

        assert_eq!(uc_regs.user().read(), 0);

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
        let mut caliptra = MailboxInternal::new(&Clock::new(), MailboxRam::new());
        let mut soc = caliptra.as_external();
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

        let mut caliptra = MailboxInternal::new(&Clock::new(), MailboxRam::new());
        let mut soc = caliptra.as_external();
        let soc_regs = soc.regs();
        let uc_regs = caliptra.regs();

        assert!(!soc_regs.lock().read().lock());
        // Confirm it is locked
        assert!(soc_regs.lock().read().lock());

        assert_eq!(soc_regs.user().read(), MailboxRequester::Soc as u32);

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
        soc_regs.status().write(|w| w.status(|w| w.data_ready()));

        // Write exec
        soc_regs.execute().write(|w| w.execute(true));
        // Confirm it is locked
        assert_eq!(soc.regs.borrow().state_machine.context.locked, 1);

        assert!(matches!(
            soc.regs.borrow().state_machine.state(),
            States::ExecUc
        ));

        assert_eq!(
            u32::from(uc_regs.status().read()),
            (Status::STATUS::DATA_READY + Status::MBOX_FSM_PS::MBOX_EXECUTE_UC).value
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
        assert_eq!(user, MailboxRequester::Caliptra as u32);

        // Write command
        uc_regs.cmd().write(|_| 0x55);

        // Write dlen
        uc_regs
            .dlen()
            .write(|_| (MAX_MAILBOX_CAPACITY_BYTES + 4) as u32);

        for data_in in (0..MAX_MAILBOX_CAPACITY_BYTES).step_by(4) {
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

        assert_eq!(
            uc_regs.dlen().read(),
            (MAX_MAILBOX_CAPACITY_BYTES + 4) as u32
        );

        for data_in in (0..MAX_MAILBOX_CAPACITY_BYTES).step_by(4) {
            // Read dataout
            let data_out = uc_regs.dataout().read();
            // compare with queued data.
            assert_eq!(data_in as u32, data_out);
        }

        // Read an additional DWORD. This should return zero
        assert_eq!(uc_regs.dataout().read(), 0);

        uc_regs.status().write(|w| w.status(|w| w.cmd_complete()));

        // Receiver resets exec register
        uc_regs.execute().write(|w| w.execute(false));
        // Confirm it is unlocked
        assert_eq!(mb.regs.borrow().state_machine.context.locked, 0);

        assert!(matches!(
            mb.regs.borrow().state_machine.state(),
            States::Idle
        ));
    }
}
