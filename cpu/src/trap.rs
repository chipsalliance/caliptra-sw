/*++

Licensed under the Apache-2.0 license.

File Name:

    exception.rs

Abstract:

    File contains RISCV trap  related types.

--*/

/// Exception Record
#[repr(C)]
pub struct TrapRecord {
    pub ra: u32,
    pub sp: u32,
    pub a0: u32,
    pub a1: u32,
    pub a2: u32,
    pub a3: u32,
    pub a4: u32,
    pub a5: u32,
    pub a6: u32,
    pub a7: u32,
    pub t0: u32,
    pub t1: u32,
    pub t2: u32,
    pub t3: u32,
    pub t4: u32,
    pub t5: u32,
    pub t6: u32,
    pub mepc: u32,
    pub mcause: u32,
    pub mscause: u32,
    pub mstatus: u32,
    pub mtval: u32,
}

pub enum Trap {
    Synchronous(Exception),
    Asynchronous(Interrupt),
}

/// Exceptions are unusual conditions that occur at run time, associated with an instruction in the current RISC-V hart.
#[derive(Debug, Clone, Copy)]
pub enum Exception {
    /// Instruction access fault
    InstructionAccessFault,
    /// Illegal instruction
    IllegalInstruction,
    /// Breakpoint
    Breakpoint,
    /// Load address misaligned
    LoadMisaligned,
    /// Load access fault
    LoadAccessFault,
    /// Store/AMO address misaligned
    StoreMisaligned,
    /// Store access fault
    StoreAccessFault,
    /// Environment call from M-mode
    MachineEnvCall,
    // Not Implemented
    NotImplemented,
}

// Convert machine cause register value to Exception
impl From<u32> for Exception {
    #[inline(always)]
    fn from(val: u32) -> Exception {
        match val {
            0x01 => Exception::InstructionAccessFault,
            0x02 => Exception::IllegalInstruction,
            0x03 => Exception::Breakpoint,
            0x04 => Exception::LoadMisaligned,
            0x05 => Exception::LoadAccessFault,
            0x07 => Exception::StoreMisaligned,
            0x08 => Exception::StoreAccessFault,
            0x0b => Exception::MachineEnvCall,
            _ => Exception::NotImplemented,
        }
    }
}

/// Interrupts are events that occur asynchronously outside any of the RISC-V harts.
#[derive(Debug, Clone, Copy)]
pub enum Interrupt {
    MachineSoftwareInterrupt,
    MachineTimerInterrupt,
    MachineExternalInterrupt,
    MachineInternalLocalTimer1,
    MachineInternalLocalTimer0,
    MachineCorrectableErrLocalInterrupt,
    NotImplemented,
}

impl From<u32> for Interrupt {
    #[inline(always)]
    fn from(val: u32) -> Self {
        match val {
            0x03 => Self::MachineSoftwareInterrupt,
            0x07 => Self::MachineTimerInterrupt,
            0x0b => Self::MachineExternalInterrupt,
            0x1c => Self::MachineInternalLocalTimer1,
            0x1d => Self::MachineInternalLocalTimer0,
            0x1e => Self::MachineCorrectableErrLocalInterrupt,
            _ => Self::NotImplemented,
        }
    }
}
