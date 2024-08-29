/*++

Licensed under the Apache-2.0 license.

File Name:

    exception.rs

Abstract:

    File contains the implementation for RISCV exceptions

--*/

use crate::emu_enum;
emu_enum! {
    /// RISCV Exception Cause
    #[derive(Debug, PartialOrd, Ord, PartialEq, Eq, Clone, Copy)]
    pub RvExceptionCause;
    u32;
    {
        /// Instruction address misaligned exception
        InstrAddrMisaligned = 0,

        /// Instruction access exception
        InstrAccessFault = 1,

        /// Illegal instruction exception
        IllegalInstr = 2,

        /// Breakpoint
        Breakpoint = 3,

        /// Load address misaligned exception
        LoadAddrMisaligned = 4,

        /// Load access fault exception
        LoadAccessFault = 5,

        /// Store address misaligned exception
        StoreAddrMisaligned = 6,

        /// Store access fault exception
        StoreAccessFault = 7,

        /// Environment Call (User)
        EnvironmentCallUser = 8,

        /// Environment Call (Machine)
        EnvironmentCallMachine = 11,

        /// Illegal Register exception
        IllegalRegister = 24,
    };
    Invalid
}

/// RISCV Exception
#[derive(Debug, Eq, PartialEq)]
pub struct RvException {
    /// Exception cause
    cause: RvExceptionCause,

    /// Info
    info: u32,
}

impl RvException {
    /// Create a new instruction address misaligned exception
    pub fn instr_addr_misaligned(addr: u32) -> Self {
        RvException::new(RvExceptionCause::InstrAddrMisaligned, addr)
    }

    /// Create a new instruction access fault exception
    pub fn instr_access_fault(addr: u32) -> Self {
        RvException::new(RvExceptionCause::InstrAccessFault, addr)
    }

    /// Create a new illegal instruction exception
    pub fn illegal_instr(instr: u32) -> Self {
        RvException::new(RvExceptionCause::IllegalInstr, instr)
    }

    /// Create a new breakpoint exception
    pub fn breakpoint(instr: u32) -> Self {
        RvException::new(RvExceptionCause::Breakpoint, instr)
    }

    /// Create a new load address misaligned exception
    pub fn load_addr_misaligned(addr: u32) -> Self {
        RvException::new(RvExceptionCause::LoadAddrMisaligned, addr)
    }

    /// Create a new load access fault exception
    pub fn load_access_fault(addr: u32) -> Self {
        RvException::new(RvExceptionCause::LoadAccessFault, addr)
    }

    /// Create a new store address misaligned exception
    pub fn store_addr_misaligned(addr: u32) -> Self {
        RvException::new(RvExceptionCause::StoreAddrMisaligned, addr)
    }

    /// Create a new store access fault exception
    pub fn store_access_fault(addr: u32) -> Self {
        RvException::new(RvExceptionCause::StoreAccessFault, addr)
    }

    /// Create a new illegal register exception
    pub fn illegal_register() -> Self {
        RvException::new(RvExceptionCause::IllegalRegister, 0)
    }

    /// Create a new environment call from U mode exception
    pub fn environment_call_user() -> Self {
        RvException::new(RvExceptionCause::EnvironmentCallUser, 0)
    }

    /// Create a new environment call from M mode exception
    pub fn environment_call_machine() -> Self {
        RvException::new(RvExceptionCause::EnvironmentCallMachine, 0)
    }

    /// Returns the exception cause
    pub fn cause(&self) -> RvExceptionCause {
        self.cause
    }

    /// Returns the exception info
    pub fn info(&self) -> u32 {
        self.info
    }

    /// Create new exception
    ///
    /// # Arguments
    ///
    /// * `cause` - Exception cause
    /// * `info` - Information associated with exception
    fn new(cause: RvExceptionCause, info: u32) -> Self {
        Self { cause, info }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_instr_addr_misaligned() {
        let e = RvException::instr_addr_misaligned(u32::MAX);
        assert_eq!(e.cause(), RvExceptionCause::InstrAddrMisaligned);
        assert_eq!(e.info(), u32::MAX);
    }

    #[test]
    fn test_instr_access_fault() {
        let e = RvException::instr_access_fault(u32::MAX);
        assert_eq!(e.cause(), RvExceptionCause::InstrAccessFault);
        assert_eq!(e.info(), u32::MAX);
    }

    #[test]
    fn test_illegal_instr() {
        let e = RvException::illegal_instr(u32::MAX);
        assert_eq!(e.cause(), RvExceptionCause::IllegalInstr);
        assert_eq!(e.info(), u32::MAX);
    }

    #[test]
    fn test_breakpoint() {
        let e = RvException::breakpoint(u32::MAX);
        assert_eq!(e.cause(), RvExceptionCause::Breakpoint);
        assert_eq!(e.info(), u32::MAX);
    }

    #[test]
    fn test_load_addr_misaligned() {
        let e = RvException::load_addr_misaligned(u32::MAX);
        assert_eq!(e.cause(), RvExceptionCause::LoadAddrMisaligned);
        assert_eq!(e.info(), u32::MAX);
    }

    #[test]
    fn test_load_access_fault() {
        let e = RvException::load_access_fault(u32::MAX);
        assert_eq!(e.cause(), RvExceptionCause::LoadAccessFault);
    }
    #[test]
    fn test_store_addr_misaligned() {
        let e = RvException::store_addr_misaligned(u32::MAX);
        assert_eq!(e.cause(), RvExceptionCause::StoreAddrMisaligned);
        assert_eq!(e.info(), u32::MAX);
    }

    #[test]
    fn test_store_access_fault() {
        let e = RvException::store_access_fault(u32::MAX);
        assert_eq!(e.cause(), RvExceptionCause::StoreAccessFault);
        assert_eq!(e.info(), u32::MAX);
    }

    #[test]
    fn test_illegal_register() {
        let e = RvException::illegal_register();
        assert_eq!(e.cause(), RvExceptionCause::IllegalRegister);
        assert_eq!(e.info(), 0);
    }

    #[test]
    fn test_environment_call_user() {
        let e = RvException::environment_call_user();
        assert_eq!(e.cause(), RvExceptionCause::EnvironmentCallUser);
        assert_eq!(e.info(), 0);
    }

    #[test]
    fn test_environment_call_machine() {
        let e = RvException::environment_call_machine();
        assert_eq!(e.cause(), RvExceptionCause::EnvironmentCallMachine);
        assert_eq!(e.info(), 0);
    }
}
