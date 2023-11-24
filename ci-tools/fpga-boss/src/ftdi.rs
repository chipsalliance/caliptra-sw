// Licensed under the Apache-2.0 license

use std::ffi::{c_int, CStr};

use libftdi1_sys::{ftdi_bits_type, ftdi_parity_type, ftdi_stopbits_type};
use rusb::{Device, GlobalContext};

use crate::UsbPortPath;

fn device_from_path(port_path: &UsbPortPath) -> anyhow::Result<Device<GlobalContext>> {
    for dev in rusb::devices()?.iter() {
        if dev.bus_number() == port_path.bus && dev.port_numbers()? == port_path.ports {
            return Ok(dev);
        }
    }
    anyhow::bail!("USB device not found: {}", port_path);
}

pub type FtdiInterface = libftdi1_sys::ftdi_interface;

#[repr(u8)]
pub enum BitMode {
    Reset = 0,
    BitBang = 0x01,
    CBus = 0x20,
}
pub struct FtdiCtx {
    ctx: *mut libftdi1_sys::ftdi_context,
    port_path: UsbPortPath,
}
impl FtdiCtx {
    pub fn open(port_path: UsbPortPath, iface: FtdiInterface) -> anyhow::Result<Self> {
        let dev = device_from_path(&port_path)?;
        println!("Opening device {} {}", dev.bus_number(), dev.address());
        unsafe {
            let ctx = libftdi1_sys::ftdi_new();
            if ctx.is_null() {
                anyhow::bail!("ftdi_new failed");
            }
            let rv = libftdi1_sys::ftdi_set_interface(ctx, iface);
            if rv < 0 {
                let err = anyhow::format_err!(
                    "{} ftdi_set_interface failed: {:?}",
                    port_path,
                    CStr::from_ptr(libftdi1_sys::ftdi_get_error_string(ctx))
                );
                libftdi1_sys::ftdi_free(ctx);
                return Err(err);
            }
            let rv = libftdi1_sys::ftdi_usb_open_dev(ctx, dev.as_raw());
            if rv < 0 {
                let err = anyhow::format_err!(
                    "ftdi_usb_open failed for device {port_path}: {:?}",
                    CStr::from_ptr(libftdi1_sys::ftdi_get_error_string(ctx))
                );
                libftdi1_sys::ftdi_free(ctx);
                return Err(err);
            }
            Ok(Self { ctx, port_path })
        }
    }

    pub fn reset(&mut self) -> anyhow::Result<()> {
        unsafe {
            let rv = libftdi1_sys::ftdi_usb_reset(self.ctx);
            if rv < 0 {
                anyhow::bail!(
                    "{} ftdi_usb_reset failed: {:?}",
                    self.port_path,
                    CStr::from_ptr(libftdi1_sys::ftdi_get_error_string(self.ctx))
                );
            }
        }
        Ok(())
    }

    pub fn set_bitmode(&mut self, pin_state: u8, mode: BitMode) -> anyhow::Result<()> {
        unsafe {
            let rv = libftdi1_sys::ftdi_set_bitmode(self.ctx, pin_state, mode as u8);
            if rv < 0 {
                anyhow::bail!(
                    "{} ftdi_set_bitmode failed: {:?}",
                    self.port_path,
                    CStr::from_ptr(libftdi1_sys::ftdi_get_error_string(self.ctx))
                );
            }
            Ok(())
        }
    }

    #[allow(unused)]
    pub fn read_pins(&mut self, pin_state: u8, mode: BitMode) -> anyhow::Result<u8> {
        unsafe {
            let mut pins: u8 = 0;
            let rv = libftdi1_sys::ftdi_read_pins(self.ctx, &mut pins as *mut _);
            if rv < 0 {
                anyhow::bail!(
                    "{} ftdi_read_pins failed: {:?}",
                    self.port_path,
                    CStr::from_ptr(libftdi1_sys::ftdi_get_error_string(self.ctx))
                );
            }
            Ok(pins)
        }
    }
    pub fn read_data(&mut self, buf: &mut [u8]) -> anyhow::Result<usize> {
        unsafe {
            let rv =
                libftdi1_sys::ftdi_read_data(self.ctx, buf.as_mut_ptr(), buf.len().try_into()?);
            if rv < 0 {
                anyhow::bail!(
                    "ftdi_write_data failed: {:?}",
                    CStr::from_ptr(libftdi1_sys::ftdi_get_error_string(self.ctx))
                );
            }
            Ok(rv.try_into()?)
        }
    }

    pub fn write_all_data(&mut self, data: &[u8]) -> anyhow::Result<()> {
        let bytes_written = self.write_data(data)?;
        if bytes_written != data.len() {
            anyhow::bail!(
                "{} ftdi_write data returned {} bytes, expected {}",
                self.port_path,
                bytes_written,
                data.len()
            );
        }
        Ok(())
    }

    pub fn write_data(&mut self, data: &[u8]) -> anyhow::Result<usize> {
        unsafe {
            let rv = libftdi1_sys::ftdi_write_data(self.ctx, data.as_ptr(), data.len().try_into()?);
            if rv < 0 {
                anyhow::bail!(
                    "ftdi_write_data failed: {:?}",
                    CStr::from_ptr(libftdi1_sys::ftdi_get_error_string(self.ctx))
                );
            }
            Ok(rv.try_into()?)
        }
    }
    pub fn set_baudrate(&mut self, baudrate: u32) -> anyhow::Result<()> {
        unsafe {
            let rv = libftdi1_sys::ftdi_set_baudrate(self.ctx, c_int::try_from(baudrate)?);
            if rv < 0 {
                anyhow::bail!(
                    "ftdi_set_baudrate failed: {:?}",
                    CStr::from_ptr(libftdi1_sys::ftdi_get_error_string(self.ctx))
                );
            }
        }
        Ok(())
    }

    pub fn set_line_property(
        &mut self,
        bits: ftdi_bits_type,
        stopbits: ftdi_stopbits_type,
        parity: ftdi_parity_type,
    ) -> anyhow::Result<()> {
        unsafe {
            let rv = libftdi1_sys::ftdi_set_line_property(self.ctx, bits, stopbits, parity);
            if rv < 0 {
                anyhow::bail!(
                    "ftdi_set_line_property failed: {:?}",
                    CStr::from_ptr(libftdi1_sys::ftdi_get_error_string(self.ctx))
                );
            }
        }
        Ok(())
    }
}

impl Drop for FtdiCtx {
    fn drop(&mut self) {
        unsafe { libftdi1_sys::ftdi_usb_close(self.ctx) };
        unsafe { libftdi1_sys::ftdi_free(self.ctx) };
    }
}
