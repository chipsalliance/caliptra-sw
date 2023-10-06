// Licensed under the Apache-2.0 license

use std::time::Duration;

use crate::{
    ftdi::{BitMode, FtdiInterface},
    FtdiCtx, UsbPortPath,
};

pub enum FpgaReset {
    Reset = 0,
    Run = 1,
}

pub struct FpgaJtag {
    pub ftdi: FtdiCtx,
}
impl FpgaJtag {
    pub fn open(port_path: UsbPortPath) -> anyhow::Result<Self> {
        Ok(Self {
            ftdi: FtdiCtx::open(port_path, FtdiInterface::INTERFACE_A)?,
        })
    }

    pub fn set_reset(&mut self, reset: FpgaReset) -> anyhow::Result<()> {
        self.ftdi.set_bitmode(0xc0, BitMode::BitBang)?;
        match reset {
            FpgaReset::Reset => {
                // Set PS_POR_B and PS_SRST_B pins low
                self.ftdi.write_all_data(&[0x0d])?;
            }
            FpgaReset::Run => {
                // Set PS_POR_B high, PS_SRST_B low
                self.ftdi.write_all_data(&[0x8d])?;

                // wait a bi
                std::thread::sleep(Duration::from_millis(1));

                // Set PS_POR_B and PS_SRST_B pins high
                self.ftdi.write_all_data(&[0xcd])?;
            }
        }
        Ok(())
    }
}
