/*++

Licensed under the Apache-2.0 license.

File Name:

    gdb_target.rs

Abstract:

    File contains gdb_target module for Caliptra Emulator.

--*/

use caliptra_emu_cpu::xreg_file::XReg;
use caliptra_emu_cpu::StepAction;
use caliptra_emu_cpu::{Cpu, WatchPtrKind};
use caliptra_emu_periph::CaliptraRootBus;
use caliptra_emu_types::RvSize;
use gdbstub::arch::SingleStepGdbBehavior;
use gdbstub::common::Signal;
use gdbstub::stub::SingleThreadStopReason;
use gdbstub::target;
use gdbstub::target::ext::base::singlethread::{SingleThreadBase, SingleThreadResume};
use gdbstub::target::ext::base::BaseOps;
use gdbstub::target::ext::breakpoints::WatchKind;
use gdbstub::target::Target;
use gdbstub::target::TargetResult;
use gdbstub_arch;

pub enum ExecMode {
    Step,
    Continue,
}

pub struct GdbTarget {
    cpu: Cpu<CaliptraRootBus>,
    exec_mode: ExecMode,
    breakpoints: Vec<u32>,
}

impl GdbTarget {
    // Create new instance of GdbTarget
    pub fn new(cpu: Cpu<CaliptraRootBus>) -> Self {
        Self {
            cpu,
            exec_mode: ExecMode::Continue,
            breakpoints: Vec::new(),
        }
    }

    // Conditional Run (Private function)
    fn cond_run(&mut self) -> SingleThreadStopReason<u32> {
        loop {
            match self.cpu.step(None) {
                StepAction::Continue => {
                    if self.breakpoints.contains(&self.cpu.read_pc()) {
                        return SingleThreadStopReason::SwBreak(());
                    }
                }
                StepAction::Break => {
                    let watch = self.cpu.get_watchptr_hit().unwrap();
                    return SingleThreadStopReason::Watch {
                        tid: (),
                        kind: if watch.kind == WatchPtrKind::Write {
                            WatchKind::Write
                        } else {
                            WatchKind::Read
                        },
                        addr: watch.addr,
                    };
                }
                _ => break,
            }
        }
        SingleThreadStopReason::Exited(0)
    }

    // run the gdb target
    pub fn run(&mut self) -> SingleThreadStopReason<u32> {
        match self.exec_mode {
            ExecMode::Step => {
                self.cpu.step(None);
                SingleThreadStopReason::DoneStep
            }
            ExecMode::Continue => self.cond_run(),
        }
    }
}

impl Target for GdbTarget {
    type Arch = gdbstub_arch::riscv::Riscv32;
    type Error = &'static str;

    fn base_ops(&mut self) -> BaseOps<Self::Arch, Self::Error> {
        BaseOps::SingleThread(self)
    }

    fn guard_rail_implicit_sw_breakpoints(&self) -> bool {
        true
    }

    fn guard_rail_single_step_gdb_behavior(&self) -> SingleStepGdbBehavior {
        SingleStepGdbBehavior::Optional
    }

    fn support_breakpoints(
        &mut self,
    ) -> Option<target::ext::breakpoints::BreakpointsOps<'_, Self>> {
        Some(self)
    }
}

impl SingleThreadBase for GdbTarget {
    fn read_registers(
        &mut self,
        regs: &mut gdbstub_arch::riscv::reg::RiscvCoreRegs<u32>,
    ) -> TargetResult<(), Self> {
        // Read PC
        regs.pc = self.cpu.read_pc();

        // Read XReg
        for idx in 0..regs.x.len() {
            regs.x[idx] = self.cpu.read_xreg(XReg::from(idx as u16)).unwrap();
        }

        Ok(())
    }

    fn write_registers(
        &mut self,
        regs: &gdbstub_arch::riscv::reg::RiscvCoreRegs<u32>,
    ) -> TargetResult<(), Self> {
        // Write PC
        self.cpu.write_pc(regs.pc);

        // Write XReg
        for idx in 0..regs.x.len() {
            self.cpu
                .write_xreg(XReg::from(idx as u16), regs.x[idx])
                .unwrap();
        }

        Ok(())
    }

    fn read_addrs(&mut self, start_addr: u32, data: &mut [u8]) -> TargetResult<(), Self> {
        for (addr, val) in (start_addr..).zip(data.iter_mut()) {
            *val = self.cpu.read_bus(RvSize::Byte, addr).unwrap() as u8;
        }
        Ok(())
    }

    fn write_addrs(&mut self, start_addr: u32, data: &[u8]) -> TargetResult<(), Self> {
        for (addr, val) in (start_addr..).zip(data.iter().copied()) {
            self.cpu.write_bus(RvSize::Byte, addr, val as u32).unwrap();
        }
        Ok(())
    }

    fn support_resume(
        &mut self,
    ) -> Option<target::ext::base::singlethread::SingleThreadResumeOps<'_, Self>> {
        Some(self)
    }
}

impl target::ext::base::singlethread::SingleThreadSingleStep for GdbTarget {
    fn step(&mut self, signal: Option<Signal>) -> Result<(), Self::Error> {
        if signal.is_some() {
            return Err("no support for stepping with signal");
        }

        self.exec_mode = ExecMode::Step;

        Ok(())
    }
}

impl SingleThreadResume for GdbTarget {
    fn resume(&mut self, signal: Option<Signal>) -> Result<(), Self::Error> {
        if signal.is_some() {
            return Err("no support for continuing with signal");
        }

        self.exec_mode = ExecMode::Continue;

        Ok(())
    }

    #[inline(always)]
    fn support_single_step(
        &mut self,
    ) -> Option<target::ext::base::singlethread::SingleThreadSingleStepOps<'_, Self>> {
        Some(self)
    }
}

impl target::ext::breakpoints::Breakpoints for GdbTarget {
    #[inline(always)]
    fn support_sw_breakpoint(
        &mut self,
    ) -> Option<target::ext::breakpoints::SwBreakpointOps<'_, Self>> {
        Some(self)
    }
    #[inline(always)]
    fn support_hw_watchpoint(
        &mut self,
    ) -> Option<target::ext::breakpoints::HwWatchpointOps<'_, Self>> {
        Some(self)
    }
}

impl target::ext::breakpoints::SwBreakpoint for GdbTarget {
    fn add_sw_breakpoint(&mut self, addr: u32, _kind: usize) -> TargetResult<bool, Self> {
        self.breakpoints.push(addr);
        Ok(true)
    }

    fn remove_sw_breakpoint(&mut self, addr: u32, _kind: usize) -> TargetResult<bool, Self> {
        match self.breakpoints.iter().position(|x| *x == addr) {
            None => return Ok(false),
            Some(pos) => self.breakpoints.remove(pos),
        };

        Ok(true)
    }
}

impl target::ext::breakpoints::HwWatchpoint for GdbTarget {
    fn add_hw_watchpoint(
        &mut self,
        addr: u32,
        len: u32,
        kind: WatchKind,
    ) -> TargetResult<bool, Self> {
        // Add Watchpointer (and transform WatchKind to WatchPtrKind)
        self.cpu.add_watchptr(
            addr,
            len,
            if kind == WatchKind::Write {
                WatchPtrKind::Write
            } else {
                WatchPtrKind::Read
            },
        );

        Ok(true)
    }

    fn remove_hw_watchpoint(
        &mut self,
        addr: u32,
        len: u32,
        kind: WatchKind,
    ) -> TargetResult<bool, Self> {
        // Remove Watchpointer (and transform WatchKind to WatchPtrKind)
        self.cpu.remove_watchptr(
            addr,
            len,
            if kind == WatchKind::Write {
                WatchPtrKind::Write
            } else {
                WatchPtrKind::Read
            },
        );
        Ok(true)
    }
}
