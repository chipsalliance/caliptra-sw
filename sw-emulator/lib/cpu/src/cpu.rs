/*++

Licensed under the Apache-2.0 license.

File Name:

    cpu.rs

Abstract:

    File contains the implementation of Caliptra CPU.

--*/

use crate::csr_file::{Csr, CsrFile};
use crate::instr::Instr;
use crate::types::{RvInstr, RvMEIHAP, RvMStatus};
use crate::xreg_file::{XReg, XRegFile};
use bit_vec::BitVec;
use caliptra_emu_bus::{Bus, BusError, Clock, TimerAction};
use caliptra_emu_types::{RvAddr, RvData, RvException, RvSize};

pub type InstrTracer<'a> = dyn FnMut(u32, RvInstr) + 'a;

/// Describes a Caliptra stack memory region
pub struct StackRange(u32, u32);
impl StackRange {
    /// **Note:** `stack_start` MUST be greater than `stack_end`. Caliptra's stack grows
    /// to a lower address.
    pub fn new(stack_start: u32, stack_end: u32) -> Self {
        if stack_start < stack_end {
            panic!("Caliptra's stack grows to a lower address");
        }
        Self(stack_start, stack_end)
    }
}

/// Describes a Caliptra code region
pub struct CodeRange(u32, u32);
impl CodeRange {
    pub fn new(code_start: u32, code_end: u32) -> Self {
        if code_start > code_end {
            panic!("code grows to a higher address");
        }
        Self(code_start, code_end)
    }
}

/// Contains metadata describing a Caliptra image
pub struct ImageInfo {
    stack_range: StackRange,
    code_range: CodeRange,
}

impl ImageInfo {
    pub fn new(stack_range: StackRange, code_range: CodeRange) -> Self {
        Self {
            stack_range,
            code_range,
        }
    }

    /// Checks if the program counter is contained in `self`
    ///
    /// returns `true` if the pc is in the image. `false` otherwise.
    fn contains_pc(&self, pc: u32) -> bool {
        self.code_range.0 <= pc && pc <= self.code_range.1
    }

    /// Checks if the stack pointer has overflowed.
    ///
    /// Returns `Some(u32)` if an overflow has occurred. The `u32` is set
    /// to the overflow amount.
    ///
    /// Returns `None` if no overflow has occurred.
    fn check_overflow(&self, sp: u32) -> Option<u32> {
        let stack_end = self.stack_range.1;

        // Stack grows to a lower address
        if sp < stack_end {
            let current_overflow = stack_end - sp;
            Some(current_overflow)
        } else {
            None
        }
    }
}

/// Describes the shape of Caliptra's stacks.
///
/// Used to monitor stack usage and check for overflows.
pub struct StackInfo {
    images: Vec<ImageInfo>,
    max_stack_overflow: u32,
    has_overflowed: bool,
}

impl StackInfo {
    /// Create a new `StackInfo` by describing the start and end of the stack and code segment for each
    /// Caliptra image.
    pub fn new(images: Vec<ImageInfo>) -> Self {
        Self {
            images,
            max_stack_overflow: 0,
            has_overflowed: false,
        }
    }
}

impl StackInfo {
    /// Fetch the largest stack overflow.
    ///
    /// If the stack never overflowed, returns `None`.
    fn max_stack_overflow(&self) -> Option<u32> {
        if self.has_overflowed {
            Some(self.max_stack_overflow)
        } else {
            None
        }
    }

    /// Checks if the stack will overflow when pushed to `stack_address`.
    ///
    /// Returns `Some(u32)` if the stack will overflow and by how much, `None` if it will not overflow.
    fn check_overflow(&mut self, pc: u32, stack_address: u32) -> Option<u32> {
        if stack_address == 0 {
            // sp is initialized to 0.
            return None;
        }

        for image in self.images.iter() {
            if image.contains_pc(pc) {
                if let Some(overflow_amount) = image.check_overflow(stack_address) {
                    self.max_stack_overflow = self.max_stack_overflow.max(overflow_amount);
                    self.has_overflowed = true;
                    return Some(overflow_amount);
                }
            }
        }

        None
    }
}

#[derive(Clone)]
pub struct CodeCoverage {
    rom_bit_vec: BitVec,
    iccm_bit_vec: BitVec,
}

pub struct CoverageBitmaps<'a> {
    pub rom: &'a bit_vec::BitVec,
    pub iccm: &'a bit_vec::BitVec,
}

const ICCM_SIZE: usize = 128 * 1024;
const ICCM_ORG: usize = 0x40000000;
const ICCM_UPPER: usize = ICCM_ORG + ICCM_SIZE - 1;

const ROM_SIZE: usize = 48 * 1024;
const ROM_ORG: usize = 0x00000000;
const ROM_UPPER: usize = ROM_ORG + ROM_SIZE - 1;

impl CodeCoverage {
    pub fn new(rom_capacity_in_bytes: usize, iccm_capacity_in_bytes: usize) -> Self {
        Self {
            rom_bit_vec: BitVec::from_elem(rom_capacity_in_bytes, false),
            iccm_bit_vec: BitVec::from_elem(iccm_capacity_in_bytes, false),
        }
    }

    pub fn log_execution(&mut self, pc: RvData, instr: &Instr) {
        let num_bytes = match instr {
            Instr::Compressed(_) => 2,
            Instr::General(_) => 4,
        };

        match pc as usize {
            ROM_ORG..=ROM_UPPER => {
                // Mark the bytes corresponding to the executed instruction as true.
                for i in 0..num_bytes {
                    let byte_index = (pc as usize - ROM_ORG) + i;
                    if byte_index < self.rom_bit_vec.len() {
                        self.rom_bit_vec.set(byte_index, true);
                    }
                }
            }
            ICCM_ORG..=ICCM_UPPER => {
                // Mark the bytes corresponding to the executed instruction as true.
                for i in 0..num_bytes {
                    let byte_index = (pc as usize - ICCM_ORG) + i;
                    if byte_index < self.iccm_bit_vec.len() {
                        self.iccm_bit_vec.set(byte_index, true);
                    }
                }
            }
            _ => (),
        }
    }

    pub fn code_coverage_bitmap(&self) -> CoverageBitmaps {
        CoverageBitmaps {
            rom: &self.rom_bit_vec,
            iccm: &self.iccm_bit_vec,
        }
    }
}

#[derive(PartialEq)]
pub enum WatchPtrKind {
    Read,
    Write,
}

pub struct WatchPtrHit {
    pub addr: u32,
    pub kind: WatchPtrKind,
}

pub struct WatchPtrCfg {
    pub write: Vec<u32>,
    pub read: Vec<u32>,
    pub hit: Option<WatchPtrHit>,
}

impl WatchPtrCfg {
    pub fn new() -> Self {
        Self {
            write: Vec::new(),
            read: Vec::new(),
            hit: None,
        }
    }
}

impl Default for WatchPtrCfg {
    fn default() -> Self {
        Self::new()
    }
}
/// RISCV CPU
pub struct Cpu<TBus: Bus> {
    /// General Purpose register file
    xregs: XRegFile,

    /// Configuration & status registers
    csrs: CsrFile,

    // Program counter
    pc: RvData,

    /// The next program counter after the current instruction is finished executing.
    next_pc: RvData,

    /// The NMI vector. In the real CPU, this is hardwired from the outside.
    nmivec: u32,

    /// The External interrupt vector table.
    ext_int_vec: u32,

    /// Global interrupt enabled
    global_int_en: bool,

    /// Machine External interrupt enabled
    ext_int_en: bool,

    /// Halted state
    halted: bool,

    // The bus the CPU uses to talk to memory and peripherals.
    pub bus: TBus,

    pub clock: Clock,

    // Track if Execution is in progress
    pub(crate) is_execute_instr: bool,

    // This is used to track watchpointers
    pub(crate) watch_ptr_cfg: WatchPtrCfg,

    pub code_coverage: CodeCoverage,
    stack_info: Option<StackInfo>,
}

impl<TBus: Bus> Drop for Cpu<TBus> {
    fn drop(&mut self) {
        if let Some(stack_info) = &self.stack_info {
            if stack_info.has_overflowed {
                panic!(
                    "[EMU] Fatal: Caliptra's stack overflowed by {} bytes!",
                    stack_info.max_stack_overflow().unwrap()
                )
            }
        }
    }
}

/// Cpu instruction step action
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum StepAction {
    /// Continue
    Continue,

    /// Break
    Break,

    /// Fatal
    Fatal,
}

impl<TBus: Bus> Cpu<TBus> {
    /// Default Program counter reset value
    const PC_RESET_VAL: RvData = 0;

    /// Create a new RISCV CPU
    pub fn new(bus: TBus, clock: Clock) -> Self {
        Self {
            xregs: XRegFile::new(),
            csrs: CsrFile::new(&clock),
            pc: Self::PC_RESET_VAL,
            next_pc: Self::PC_RESET_VAL,
            bus,
            clock,
            is_execute_instr: false,
            watch_ptr_cfg: WatchPtrCfg::new(),
            nmivec: 0,
            ext_int_vec: 0,
            global_int_en: false,
            ext_int_en: false,
            halted: false,
            // TODO: Pass in code_coverage from the outside (as caliptra-emu-cpu
            // isn't supposed to know anything about the caliptra memory map)
            code_coverage: CodeCoverage::new(ROM_SIZE, ICCM_SIZE),
            stack_info: None,
        }
    }

    pub fn with_stack_info(&mut self, stack_info: StackInfo) {
        self.stack_info = Some(stack_info);
    }

    /// Read the RISCV CPU Program counter
    ///
    ///  # Return
    ///
    ///  * `RvData` - PC value.
    pub fn read_pc(&self) -> RvData {
        self.pc
    }

    /// Write the RISCV CPU Program counter
    ///
    /// # Arguments
    ///
    /// * `pc` - Program counter value
    pub fn write_pc(&mut self, pc: RvData) {
        self.pc = pc;
    }

    fn reset_pc(&mut self) {
        self.pc = 0;
    }

    /// Returns the next program counter after the current instruction is finished executing.
    pub fn next_pc(&self) -> RvData {
        self.next_pc
    }

    /// Set the next program counter after the current instruction is finished executing.
    ///
    /// Should only be set by instruction implementations.
    pub fn set_next_pc(&mut self, next_pc: RvData) {
        self.next_pc = next_pc;
    }

    /// Read the specified RISCV General Purpose Register
    ///
    /// # Arguments
    ///
    /// * `reg` - Register to read
    ///
    ///  # Return
    ///
    ///  * `RvData` - Register value if addr is valid; u32::MAX otherwise.
    ///
    /// # Error
    ///
    /// * `RvException` - Exception with cause `RvExceptionCause::IllegalRegister`
    pub fn read_xreg(&self, reg: XReg) -> Result<RvData, RvException> {
        self.xregs.read(reg)
    }

    /// Write the specified RISCV General Purpose Register
    ///
    /// # Arguments
    ///
    /// * `reg` - Register to write
    /// * `val` - Value to write
    ///
    /// # Error
    ///
    /// * `RvException` - Exception with cause `RvExceptionCause::IllegalRegister`
    pub fn write_xreg(&mut self, reg: XReg, val: RvData) -> Result<(), RvException> {
        // XReg::X2 is the sp register.
        if reg == XReg::X2 {
            self.check_stack(val);
        }
        self.xregs.write(reg, val)?;
        Ok(())
    }

    // Check if the stack overflows at the requested address.
    fn check_stack(&mut self, val: RvData) {
        if let Some(stack_info) = &mut self.stack_info {
            if let Some(overflow_amount) = stack_info.check_overflow(self.pc, val) {
                eprintln!(
                    "[EMU] Caliptra's stack overflowed by {} bytes at pc 0x{:x}.",
                    overflow_amount, self.pc
                );
            }
        }
    }

    /// Read the specified configuration status register
    ///
    /// # Arguments
    ///
    /// * `csr` - Configuration status register to read
    ///
    ///  # Return
    ///
    ///  * `RvData` - Register value
    ///
    /// # Error
    ///
    /// * `RvException` - Exception with cause `RvExceptionCause::IllegalRegister`
    pub fn read_csr(&self, csr: RvAddr) -> Result<RvData, RvException> {
        self.csrs.read(csr)
    }

    /// Write the specified Configuration status register
    ///
    /// # Arguments
    ///
    /// * `reg` - Configuration  status register to write
    /// * `val` - Value to write
    ///
    /// # Error
    ///
    /// * `RvException` - Exception with cause `RvExceptionCause::IllegalRegister`
    pub fn write_csr(&mut self, csr: RvAddr, val: RvData) -> Result<(), RvException> {
        self.csrs.write(csr, val)
    }

    /// Read from bus
    ///
    /// # Arguments
    ///
    /// * `size` - Size of the read
    /// * `addr` - Address to read from
    ///
    /// # Error
    ///
    /// * `RvException` - Exception with cause `RvExceptionCause::LoadAccessFault`
    ///                   or `RvExceptionCause::LoadAddrMisaligned`
    pub fn read_bus(&mut self, size: RvSize, addr: RvAddr) -> Result<RvData, RvException> {
        // Check if we are in step mode
        if self.is_execute_instr {
            self.watch_ptr_cfg.hit = match self.watch_ptr_cfg.read.contains(&addr) {
                true => Some(WatchPtrHit {
                    addr,
                    kind: WatchPtrKind::Read,
                }),
                false => None,
            }
        }

        match self.bus.read(size, addr) {
            Ok(val) => Ok(val),
            Err(exception) => match exception {
                BusError::InstrAccessFault => Err(RvException::instr_access_fault(addr)),
                BusError::LoadAccessFault => Err(RvException::load_access_fault(addr)),
                BusError::LoadAddrMisaligned => Err(RvException::load_addr_misaligned(addr)),
                BusError::StoreAccessFault => Err(RvException::store_access_fault(addr)),
                BusError::StoreAddrMisaligned => Err(RvException::store_addr_misaligned(addr)),
            },
        }
    }

    /// Write to bus
    ///
    /// # Arguments
    ///
    /// * `size` - Size of the read
    /// * `addr` - Address to read from
    /// * `val`  - Value to write
    ///
    /// # Error
    ///
    /// * `RvException` - Exception with cause `RvExceptionCause::StoreAccessFault`
    ///                   or `RvExceptionCause::StoreAddrMisaligned`
    pub fn write_bus(
        &mut self,
        size: RvSize,
        addr: RvAddr,
        val: RvData,
    ) -> Result<(), RvException> {
        // Check if we are in step mode
        if self.is_execute_instr {
            self.watch_ptr_cfg.hit = match self.watch_ptr_cfg.write.contains(&addr) {
                true => Some(WatchPtrHit {
                    addr,
                    kind: WatchPtrKind::Write,
                }),
                false => None,
            }
        }
        match self.bus.write(size, addr, val) {
            Ok(val) => Ok(val),
            Err(exception) => match exception {
                BusError::InstrAccessFault => Err(RvException::instr_access_fault(addr)),
                BusError::LoadAccessFault => Err(RvException::load_access_fault(addr)),
                BusError::LoadAddrMisaligned => Err(RvException::load_addr_misaligned(addr)),
                BusError::StoreAccessFault => Err(RvException::store_access_fault(addr)),
                BusError::StoreAddrMisaligned => Err(RvException::store_addr_misaligned(addr)),
            },
        }
    }

    /// Read instruction
    ///
    /// # Arguments
    ///
    /// * `size` - Size of the read
    /// * `addr` - Address to read from
    ///
    /// # Error
    ///
    /// * `RvException` - Exception with cause `RvExceptionCause::LoadAccessFault`
    ///                   or `RvExceptionCause::LoadAddrMisaligned`
    pub fn read_instr(&mut self, size: RvSize, addr: RvAddr) -> Result<RvData, RvException> {
        match size {
            RvSize::Byte => Err(RvException::instr_access_fault(addr)),
            _ => match self.bus.read(size, addr) {
                Ok(val) => Ok(val),
                Err(exception) => match exception {
                    BusError::InstrAccessFault => Err(RvException::instr_access_fault(addr)),
                    BusError::LoadAccessFault => Err(RvException::instr_access_fault(addr)),
                    BusError::LoadAddrMisaligned => Err(RvException::instr_addr_misaligned(addr)),
                    BusError::StoreAccessFault => Err(RvException::store_access_fault(addr)),
                    BusError::StoreAddrMisaligned => Err(RvException::store_addr_misaligned(addr)),
                },
            },
        }
    }

    pub fn warm_reset(&mut self) {
        self.clock
            .timer()
            .schedule_action_in(0, TimerAction::WarmReset);
    }

    /// Step a single instruction
    pub fn step(&mut self, instr_tracer: Option<&mut InstrTracer>) -> StepAction {
        let fired_action_types = self
            .clock
            .increment_and_process_timer_actions(1, &mut self.bus);
        for action_type in fired_action_types.iter() {
            match action_type {
                TimerAction::WarmReset => {
                    self.halted = false;
                    self.reset_pc();
                    break;
                }
                TimerAction::UpdateReset => {
                    self.halted = false;
                    self.reset_pc();
                    break;
                }
                TimerAction::Nmi { mcause } => {
                    self.halted = false;
                    return self.handle_nmi(*mcause, 0);
                }
                TimerAction::SetNmiVec { addr } => self.nmivec = *addr,
                TimerAction::ExtInt { irq, can_wake } => {
                    if self.global_int_en && self.ext_int_en && (!self.halted || *can_wake) {
                        self.halted = false;
                        return self.handle_external_int(*irq);
                    }
                }
                TimerAction::SetExtIntVec { addr } => self.ext_int_vec = *addr,
                TimerAction::SetGlobalIntEn { en } => self.global_int_en = *en,
                TimerAction::SetExtIntEn { en } => self.ext_int_en = *en,
                TimerAction::Halt => self.halted = true,
                _ => {}
            }
        }

        // We are in a halted state. Don't continue executing but poll the bus for interrupts
        if self.halted {
            self.set_next_pc(self.pc);
            return StepAction::Continue;
        }

        match self.exec_instr(instr_tracer) {
            Ok(result) => result,
            Err(exception) => self.handle_exception(exception),
        }
    }

    /// Handle synchronous exception
    fn handle_exception(&mut self, exception: RvException) -> StepAction {
        let ret = self.handle_trap(
            self.read_pc(),
            exception.cause().into(),
            exception.info(),
            // Cannot panic; mtvec is a valid CSR
            self.read_csr(Csr::MTVEC).unwrap() & !0b11,
        );
        match ret {
            Ok(_) => StepAction::Continue,
            Err(_) => StepAction::Fatal,
        }
    }

    /// Handle non-maskable interrupt (VeeR-specific)
    fn handle_nmi(&mut self, cause: u32, info: u32) -> StepAction {
        let ret = self.handle_trap(self.read_pc(), cause, info, self.nmivec);
        match ret {
            Ok(_) => StepAction::Continue,
            Err(_) => StepAction::Fatal,
        }
    }

    /// Handle synchronous & asynchronous trap
    ///
    /// # Error
    ///
    /// * `RvException` - Exception
    fn handle_trap(
        &mut self,
        pc: RvAddr,
        cause: u32,
        info: u32,
        next_pc: u32,
    ) -> Result<(), RvException> {
        self.write_csr(Csr::MEPC, pc)?;
        self.write_csr(Csr::MCAUSE, cause)?;
        self.write_csr(Csr::MTVAL, info)?;

        let mut status = RvMStatus(self.read_csr(Csr::MSTATUS)?);
        status.set_mpie(status.mie());
        status.set_mie(0);
        self.write_csr(Csr::MSTATUS, status.0)?;
        // Don't rely on write_csr to disable global interrupts as the scheduled action could be
        // after a next interrupt
        self.global_int_en = false;

        self.write_pc(next_pc);
        println!(
            "handle_trap: cause={:x}, mtval={:x}, next_pc={:x}",
            cause, info, next_pc
        );
        Ok(())
    }

    //// Handle external interrupts
    fn handle_external_int(&mut self, irq: u8) -> StepAction {
        const REDIRECT_ENTRY_SIZE: u32 = 4;
        const MAX_IRQ: u32 = 32;
        const DCCM_ORG: u32 = 0x5000_0000;
        const DCCM_SIZE: u32 = 128 * 1024;

        let vec_table = self.ext_int_vec;
        if vec_table < DCCM_ORG || vec_table + MAX_IRQ * REDIRECT_ENTRY_SIZE > DCCM_ORG + DCCM_SIZE
        {
            const NON_DCCM_NMI: u32 = 0xF000_1002;
            return self.handle_nmi(NON_DCCM_NMI, 0);
        }
        let next_pc_ptr = vec_table + REDIRECT_ENTRY_SIZE * u32::from(irq);
        let mut meihap = RvMEIHAP(vec_table);
        meihap.set_claimid(irq.into());
        match self.write_csr(Csr::MEIHAP, meihap.0) {
            Ok(_) => (),
            Err(_) => return StepAction::Fatal,
        };
        let Ok(next_pc) = self.read_bus(RvSize::Word, next_pc_ptr) else { return StepAction::Fatal; };
        const MACHINE_EXTERNAL_INT: u32 = 0x8000_000B;
        let ret = self.handle_trap(self.read_pc(), MACHINE_EXTERNAL_INT, 0, next_pc);
        match ret {
            Ok(_) => StepAction::Continue,
            Err(_) => StepAction::Fatal,
        }
    }

    //// Append WatchPointer
    pub fn add_watchptr(&mut self, addr: u32, len: u32, kind: WatchPtrKind) {
        for addr in addr..(addr + len) {
            match kind {
                WatchPtrKind::Read => self.watch_ptr_cfg.read.push(addr),
                WatchPtrKind::Write => self.watch_ptr_cfg.write.push(addr),
            }
        }
    }

    //// Remove WatchPointer
    pub fn remove_watchptr(&mut self, addr: u32, len: u32, kind: WatchPtrKind) {
        let watch_ptr = match kind {
            WatchPtrKind::Read => &mut self.watch_ptr_cfg.read,
            WatchPtrKind::Write => &mut self.watch_ptr_cfg.write,
        };
        watch_ptr.retain(|&x| -> bool { (x < addr) || (x > (addr + len)) });
    }

    //// Get WatchPointer
    pub fn get_watchptr_hit(&self) -> Option<&WatchPtrHit> {
        self.watch_ptr_cfg.hit.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use caliptra_emu_bus::{testing::FakeBus, DynamicBus, Rom, Timer};

    #[test]
    fn test_new() {
        let cpu = Cpu::new(DynamicBus::new(), Clock::new());
        assert_eq!(cpu.read_pc(), 0);
    }

    #[test]
    fn test_pc() {
        let mut cpu = Cpu::new(DynamicBus::new(), Clock::new());
        cpu.write_pc(0xFF);
        assert_eq!(cpu.read_pc(), 0xFF);
    }

    #[test]
    fn test_xreg() {
        let mut cpu = Cpu::new(DynamicBus::new(), Clock::new());
        for reg in 1..32u32 {
            assert_eq!(cpu.write_xreg(reg.into(), 0xFF).ok(), Some(()));
            assert_eq!(cpu.read_xreg(reg.into()).ok(), Some(0xFF));
        }
    }

    #[test]
    fn test_bus_poll() {
        const RV32_NO_OP: u32 = 0x00000013;

        let clock = Clock::new();
        let timer = Timer::new(&clock);
        let mut bus = DynamicBus::new();

        let rom = Rom::new(
            std::iter::repeat(RV32_NO_OP)
                .take(256)
                .flat_map(u32::to_le_bytes)
                .collect(),
        );
        bus.attach_dev("ROM", 0..=0x3ff, Box::new(rom)).unwrap();

        let fake_bus = FakeBus::new();
        let fake_bus_log = fake_bus.log.clone();
        bus.attach_dev("FAKE", 0x2000..=0x3000, Box::new(fake_bus))
            .unwrap();

        let mut action0 = Some(timer.schedule_poll_in(31));

        let mut cpu = Cpu::new(bus, clock);
        for i in 0..30 {
            assert_eq!(cpu.clock.now(), i);
            assert_eq!(cpu.step(None), StepAction::Continue);
        }
        assert_eq!(fake_bus_log.take(), "");
        assert!(!timer.fired(&mut action0));

        assert_eq!(cpu.step(None), StepAction::Continue);
        assert_eq!(fake_bus_log.take(), "poll()\n");
        assert!(timer.fired(&mut action0));

        assert_eq!(cpu.read_pc(), 31 * 4);
    }

    pub fn count_executed(coverage: &CodeCoverage) -> usize {
        coverage
            .rom_bit_vec
            .iter()
            .filter(|&executed| executed)
            .count()
    }

    #[test]
    fn test_coverage() {
        // represent program as an array of 16-bit and 32-bit instructions
        let instructions = vec![
            Instr::Compressed(0x1234),
            Instr::Compressed(0xABCD),
            Instr::General(0xDEADBEEF),
        ];

        // Instantiate coverage with a capacity for the mix of instructions above
        let mut coverage = CodeCoverage::new(8, 0);

        // Log execution of the instructions above
        coverage.log_execution(0, &instructions[0]);
        coverage.log_execution(2, &instructions[1]);
        coverage.log_execution(4, &instructions[2]);

        // Check for expected values
        assert_eq!(count_executed(&coverage), 8);
    }
}
