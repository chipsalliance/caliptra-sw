// Licensed under the Apache-2.0 license

use std::{
    io::{self, ErrorKind},
    time::Duration,
};

use libftdi1_sys::{ftdi_bits_type, ftdi_interface, ftdi_parity_type, ftdi_stopbits_type};
use std::cell::RefCell;
use std::rc::Rc;

use crate::{
    ftdi::{BitMode, FtdiCtx},
    usb_port_path::UsbPortPath,
};

pub struct FtdiUartReader {
    ftdi: Rc<RefCell<FtdiCtx>>,
}

pub struct FtdiUartReaderBlocking {
    ftdi: Rc<RefCell<FtdiCtx>>,
}

pub struct FtdiUartWriter {
    ftdi: Rc<RefCell<FtdiCtx>>,
}
impl FtdiUartWriter {
    pub fn send_break(&self) -> anyhow::Result<()> {
        const BREAK_TIME: Duration = Duration::from_micros(100);

        let mut ftdi = self.ftdi.borrow_mut();
        ftdi.set_bitmode(0x01, BitMode::BitBang)?;
        ftdi.write_all_data(&[0x00])?;
        std::thread::sleep(BREAK_TIME);
        ftdi.set_bitmode(0x01, BitMode::Reset)?;
        ftdi.set_baudrate(115200)?;
        ftdi.set_line_property(
            ftdi_bits_type::BITS_8,
            ftdi_stopbits_type::STOP_BIT_1,
            ftdi_parity_type::NONE,
        )?;
        Ok(())
    }
}

pub fn open(
    port_path: UsbPortPath,
    iface: ftdi_interface,
) -> anyhow::Result<(FtdiUartReader, FtdiUartWriter)> {
    let mut ftdi = FtdiCtx::open(port_path, iface)?;
    ftdi.set_bitmode(0, BitMode::Reset)?;
    ftdi.set_baudrate(115200)?;
    ftdi.set_line_property(
        ftdi_bits_type::BITS_8,
        ftdi_stopbits_type::STOP_BIT_1,
        ftdi_parity_type::NONE,
    )?;
    let ftdi = Rc::new(RefCell::new(ftdi));
    Ok((
        FtdiUartReader { ftdi: ftdi.clone() },
        FtdiUartWriter { ftdi },
    ))
}

pub fn open_blocking(
    port_path: UsbPortPath,
    iface: ftdi_interface,
) -> anyhow::Result<(FtdiUartReaderBlocking, FtdiUartWriter)> {
    let (rx, tx) = open(port_path, iface)?;
    Ok((FtdiUartReaderBlocking { ftdi: rx.ftdi }, tx))
}

impl io::Read for FtdiUartReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.ftdi
            .borrow_mut()
            .read_data(buf)
            .map_err(|e| io::Error::new(ErrorKind::Other, e))
    }
}

impl io::Read for FtdiUartReaderBlocking {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            let bytes_read = self
                .ftdi
                .borrow_mut()
                .read_data(buf)
                .map_err(|e| io::Error::new(ErrorKind::Other, e))?;
            if bytes_read > 0 {
                return Ok(bytes_read);
            }
        }
    }
}

impl io::Write for FtdiUartWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.ftdi
            .borrow_mut()
            .write_data(buf)
            .map_err(|e| io::Error::new(ErrorKind::Other, e))
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
