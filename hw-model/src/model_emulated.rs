// Licensed under the Apache-2.0 license

use std::cell::RefCell;
use std::env;
use std::error::Error;
use std::fs::File;
use std::io::BufWriter;
use std::io::Write;
use std::path::Path;
use std::rc::Rc;
use std::sync::mpsc;

use caliptra_emu_bus::Clock;
use caliptra_emu_cpu::Cpu;
use caliptra_emu_cpu::InstrTracer;
use caliptra_emu_periph::{CaliptraRootBus, CaliptraRootBusArgs, TbServicesCb};
use caliptra_emu_types::{RvAddr, RvData, RvSize};

use crate::InitParams;
use crate::Output;
use caliptra_emu_bus::Bus;

#[derive(Clone)]
struct LogFile(Rc<RefCell<BufWriter<File>>>);
impl LogFile {
    fn open(path: &Path) -> std::io::Result<Self> {
        Ok(Self(Rc::new(RefCell::new(BufWriter::new(File::create(
            path,
        )?)))))
    }
}
impl Write for LogFile {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.borrow_mut().write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.0.borrow_mut().flush()
    }
}

pub struct EmulatedApbBus<'a> {
    model: &'a mut ModelEmulated,
}

impl<'a> Bus for EmulatedApbBus<'a> {
    fn read(&mut self, size: RvSize, addr: RvAddr) -> Result<RvData, caliptra_emu_bus::BusError> {
        let result = self.model.cpu.bus.bus.read(size, addr);
        self.model.cpu.bus.log_read("SoC", size, addr, result);
        result
    }
    fn write(
        &mut self,
        size: RvSize,
        addr: RvAddr,
        val: RvData,
    ) -> Result<(), caliptra_emu_bus::BusError> {
        let result = self.model.cpu.bus.write(size, addr, val);
        self.model.cpu.bus.log_write("SoC", size, addr, val, result);
        result
    }
}

struct BusLogger<TBus: Bus> {
    bus: TBus,
    log: Option<LogFile>,
}
impl<TBus: Bus> BusLogger<TBus> {
    fn new(bus: TBus) -> Self {
        Self { bus, log: None }
    }
    fn log_read(
        &mut self,
        bus_name: &str,
        size: RvSize,
        addr: RvAddr,
        result: Result<RvData, caliptra_emu_bus::BusError>,
    ) {
        if addr < 0x1000_0000 {
            // Don't care about memory
            return;
        }
        if let Some(log) = &mut self.log {
            let size = usize::from(size);
            match result {
                Ok(val) => {
                    writeln!(log, "{bus_name} read{size} *0x{addr:08x} -> 0x{val:x}").unwrap()
                }
                Err(e) => {
                    writeln!(log, "{bus_name} read{size}  *0x{addr:08x} ***FAULT {e:?}").unwrap()
                }
            }
        }
    }
    fn log_write(
        &mut self,
        bus_name: &str,
        size: RvSize,
        addr: RvAddr,
        val: RvData,
        result: Result<(), caliptra_emu_bus::BusError>,
    ) {
        if addr < 0x1000_0000 {
            // Don't care about memory
            return;
        }
        if let Some(log) = &mut self.log {
            let size = usize::from(size);
            match result {
                Ok(()) => {
                    writeln!(log, "{bus_name} write{size} *0x{addr:08x} <- 0x{val:x}").unwrap()
                }
                Err(e) => writeln!(
                    log,
                    "{bus_name} write{size} *0x{addr:08x} <- 0x{val:x} ***FAULT {e:?}"
                )
                .unwrap(),
            }
        }
    }
}
impl<TBus: Bus> Bus for BusLogger<TBus> {
    fn read(&mut self, size: RvSize, addr: RvAddr) -> Result<RvData, caliptra_emu_bus::BusError> {
        let result = self.bus.read(size, addr);
        self.log_read("UC", size, addr, result);
        result
    }

    fn write(
        &mut self,
        size: RvSize,
        addr: RvAddr,
        val: RvData,
    ) -> Result<(), caliptra_emu_bus::BusError> {
        let result = self.bus.write(size, addr, val);
        self.log_write("UC", size, addr, val, result);
        result
    }
    fn poll(&mut self) {
        self.bus.poll();
    }
}

/// Emulated model
pub struct ModelEmulated {
    cpu: Cpu<BusLogger<CaliptraRootBus>>,
    output: Output,
    generic_load_rx: mpsc::Receiver<u8>,
    trace_fn: Option<Box<InstrTracer<'static>>>,
}

impl crate::HwModel for ModelEmulated {
    type TBus<'a> = EmulatedApbBus<'a>;

    fn init(params: InitParams) -> Result<Self, Box<dyn Error>>
    where
        Self: Sized,
    {
        let (generic_load_tx, generic_load_rx) = mpsc::channel();
        let clock = Clock::new();
        let bus_args = CaliptraRootBusArgs {
            rom: params.rom.into(),
            tb_services_cb: TbServicesCb(Box::new(move |ch| {
                let _ = generic_load_tx.send(ch);
            })),
            ..CaliptraRootBusArgs::default()
        };
        let cpu = Cpu::new(
            BusLogger::new(CaliptraRootBus::new(&clock, bus_args)),
            clock,
        );

        let mut m = ModelEmulated {
            generic_load_rx,
            output: Output::new(),
            cpu,
            trace_fn: None,
        };
        // Turn tracing on if CPTRA_TRACE_PATH environment variable is set
        m.tracing_hint(true);

        Ok(m)
    }
    fn apb_bus(&mut self) -> Self::TBus<'_> {
        EmulatedApbBus { model: self }
    }

    fn step(&mut self) {
        self.cpu.step(self.trace_fn.as_deref_mut());
    }

    fn output(&mut self) -> &mut Output {
        // Make sure output contains all the latest generic loads from the verilator model
        while let Ok(ch) = self.generic_load_rx.try_recv() {
            self.output.process_generic_load(ch)
        }
        &mut self.output
    }

    fn tracing_hint(&mut self, enable: bool) {
        if enable == self.trace_fn.is_some() {
            // No change
            return;
        }
        self.trace_fn = None;
        self.cpu.bus.log = None;
        let trace_path = env::var("CPTRA_TRACE_PATH").unwrap_or_else(|_| "".into());
        if trace_path.is_empty() {
            return;
        }

        let mut log = match LogFile::open(Path::new(&trace_path)) {
            Ok(file) => file,
            Err(e) => {
                eprintln!("Unable to open file {trace_path:?}: {e}");
                return;
            }
        };
        self.cpu.bus.log = Some(log.clone());
        self.trace_fn = Some(Box::new(move |pc, _instr| {
            writeln!(log, "pc=0x{pc:x}").unwrap();
        }))
    }
}
