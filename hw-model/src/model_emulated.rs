// Licensed under the Apache-2.0 license

use std::cell::Cell;
use std::error::Error;
use std::io::Write;
use std::path::PathBuf;
use std::rc::Rc;

use caliptra_emu_bus::Clock;
use caliptra_emu_cpu::Cpu;
use caliptra_emu_cpu::InstrTracer;
use caliptra_emu_periph::ActionCb;
use caliptra_emu_periph::ReadyForFwCb;
use caliptra_emu_periph::{CaliptraRootBus, CaliptraRootBusArgs, SocToCaliptraBus, TbServicesCb};
use caliptra_emu_types::{RvAddr, RvData, RvSize};
use caliptra_hw_model_types::ErrorInjectionMode;

use crate::bus_logger::BusLogger;
use crate::bus_logger::LogFile;
use crate::trace_path_or_env;
use crate::InitParams;
use crate::ModelError;
use crate::Output;
use crate::TrngMode;
use caliptra_emu_bus::Bus;

pub struct EmulatedApbBus<'a> {
    model: &'a mut ModelEmulated,
}

impl<'a> Bus for EmulatedApbBus<'a> {
    fn read(&mut self, size: RvSize, addr: RvAddr) -> Result<RvData, caliptra_emu_bus::BusError> {
        let result = self.model.soc_to_caliptra_bus.read(size, addr);
        self.model.cpu.bus.log_read("SoC", size, addr, result);
        result
    }
    fn write(
        &mut self,
        size: RvSize,
        addr: RvAddr,
        val: RvData,
    ) -> Result<(), caliptra_emu_bus::BusError> {
        let result = self.model.soc_to_caliptra_bus.write(size, addr, val);
        self.model.cpu.bus.log_write("SoC", size, addr, val, result);
        result
    }
}

/// Emulated model
pub struct ModelEmulated {
    cpu: Cpu<BusLogger<CaliptraRootBus>>,
    soc_to_caliptra_bus: SocToCaliptraBus,
    output: Output,
    trace_fn: Option<Box<InstrTracer<'static>>>,
    ready_for_fw: Rc<Cell<bool>>,
    cpu_enabled: Rc<Cell<bool>>,
    trace_path: Option<PathBuf>,

    image_tag: u64,
}
impl Drop for ModelEmulated {
    fn drop(&mut self) {
        let bitmap = self.code_coverage_bitmap();
        let _ = caliptra_coverage::dump_emu_coverage_to_file(self.image_tag, bitmap);
    }
}

impl ModelEmulated {
    pub fn code_coverage_bitmap(&self) -> &bit_vec::BitVec {
        self.cpu.code_coverage.code_coverage_bitmap()
    }
}

impl crate::HwModel for ModelEmulated {
    type TBus<'a> = EmulatedApbBus<'a>;

    fn new_unbooted(params: InitParams) -> Result<Self, Box<dyn Error>>
    where
        Self: Sized,
    {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::Hasher;

        let clock = Clock::new();
        let timer = clock.timer();

        let ready_for_fw = Rc::new(Cell::new(false));
        let ready_for_fw_clone = ready_for_fw.clone();

        let cpu_enabled = Rc::new(Cell::new(false));
        let cpu_enabled_cloned = cpu_enabled.clone();

        let output = Output::new(params.log_writer);

        let output_sink = output.sink().clone();

        let bus_args = CaliptraRootBusArgs {
            rom: params.rom.into(),
            tb_services_cb: TbServicesCb::new(move |ch| {
                output_sink.set_now(timer.now());
                output_sink.push_uart_char(ch);
            }),
            ready_for_fw_cb: ReadyForFwCb::new(move |_| {
                ready_for_fw_clone.set(true);
            }),
            bootfsm_go_cb: ActionCb::new(move || {
                cpu_enabled_cloned.set(true);
            }),
            security_state: params.security_state,
            cptra_obf_key: params.cptra_obf_key,

            itrng_nibbles: Some(params.itrng_nibbles),
            etrng_responses: params.etrng_responses,
            ..CaliptraRootBusArgs::default()
        };
        let mut root_bus = CaliptraRootBus::new(&clock, bus_args);

        let trng_mode = TrngMode::resolve(params.trng_mode);
        root_bus.soc_reg.set_hw_config(match trng_mode {
            TrngMode::Internal => 1.into(),
            TrngMode::External => 0.into(),
        });

        {
            let mut iccm_ram = root_bus.iccm.ram().borrow_mut();
            let Some(iccm_dest) = iccm_ram.data_mut().get_mut(0..params.iccm.len()) else {
                return Err(ModelError::ProvidedIccmTooLarge.into());
            };
            iccm_dest.copy_from_slice(params.iccm);

            let Some(dccm_dest) = root_bus.dccm.data_mut().get_mut(0..params.dccm.len()) else {
                return Err(ModelError::ProvidedDccmTooLarge.into());
            };
            dccm_dest.copy_from_slice(params.dccm);
        }
        let soc_to_caliptra_bus = root_bus.soc_to_caliptra_bus();
        let cpu = Cpu::new(BusLogger::new(root_bus), clock);

        let mut hasher = DefaultHasher::new();
        std::hash::Hash::hash_slice(params.rom, &mut hasher);
        let image_tag = hasher.finish();

        let mut m = ModelEmulated {
            output,
            cpu,
            soc_to_caliptra_bus,
            trace_fn: None,
            ready_for_fw,
            cpu_enabled,
            trace_path: trace_path_or_env(params.trace_path),
            image_tag,
        };
        // Turn tracing on if the trace path was set
        m.tracing_hint(true);

        Ok(m)
    }

    fn ready_for_fw(&self) -> bool {
        self.ready_for_fw.get()
    }
    fn apb_bus(&mut self) -> Self::TBus<'_> {
        EmulatedApbBus { model: self }
    }

    fn step(&mut self) {
        if self.cpu_enabled.get() {
            self.cpu.step(self.trace_fn.as_deref_mut());
        }
    }

    fn output(&mut self) -> &mut Output {
        // In case the caller wants to log something, make sure the log has the
        // correct time.
        self.output.sink().set_now(self.cpu.clock.now());
        &mut self.output
    }

    fn tracing_hint(&mut self, enable: bool) {
        if enable == self.trace_fn.is_some() {
            // No change
            return;
        }
        self.trace_fn = None;
        self.cpu.bus.log = None;
        let Some(trace_path) = &self.trace_path else {
            return;
        };

        let mut log = match LogFile::open(trace_path) {
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

    fn ecc_error_injection(&mut self, mode: ErrorInjectionMode) {
        match mode {
            ErrorInjectionMode::None => {
                self.cpu.bus.bus.iccm.ram().borrow_mut().error_injection = 0;
                self.cpu.bus.bus.dccm.error_injection = 0;
            }
            ErrorInjectionMode::IccmDoubleBitEcc => {
                self.cpu.bus.bus.iccm.ram().borrow_mut().error_injection = 2;
            }
            ErrorInjectionMode::DccmDoubleBitEcc => {
                self.cpu.bus.bus.dccm.error_injection = 8;
            }
        }
    }

    fn set_apb_pauser(&mut self, _pauser: u32) {
        unimplemented!();
    }
}
