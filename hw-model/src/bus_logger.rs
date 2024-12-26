// Licensed under the Apache-2.0 license

use std::{
    cell::RefCell,
    fs::File,
    io::{BufWriter, Write},
    path::Path,
    rc::Rc,
};

use caliptra_emu_bus::{Bus, BusError};
use caliptra_emu_types::{RvAddr, RvData, RvSize};

#[derive(Clone)]
pub struct LogFile(Rc<RefCell<BufWriter<File>>>);
impl LogFile {
    pub fn open(path: &Path) -> std::io::Result<Self> {
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

pub struct NullBus();
impl Bus for NullBus {
    fn read(&mut self, _size: RvSize, _addr: RvAddr) -> Result<RvData, caliptra_emu_bus::BusError> {
        Err(BusError::LoadAccessFault)
    }

    fn write(
        &mut self,
        _size: RvSize,
        _addr: RvAddr,
        _val: RvData,
    ) -> Result<(), caliptra_emu_bus::BusError> {
        Err(BusError::StoreAccessFault)
    }
}

pub struct BusLogger<TBus: Bus> {
    pub bus: TBus,
    pub log: Option<LogFile>,
}
impl<TBus: Bus> BusLogger<TBus> {
    pub fn new(bus: TBus) -> Self {
        Self { bus, log: None }
    }
    pub fn log_read(
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
                    writeln!(log, "{bus_name}  read{size} *0x{addr:08x} -> 0x{val:x}").unwrap()
                }
                Err(e) => {
                    writeln!(log, "{bus_name}  read{size}  *0x{addr:08x} ***FAULT {e:?}").unwrap()
                }
            }
        }
    }
    pub fn log_write(
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
    fn warm_reset(&mut self) {
        self.bus.warm_reset();
    }
    fn update_reset(&mut self) {
        self.bus.update_reset();
    }
}
