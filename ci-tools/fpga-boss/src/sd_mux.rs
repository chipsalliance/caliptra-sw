// Licensed under the Apache-2.0 license

use std::str::FromStr;

use clap::PossibleValue;
use libftdi1_sys::ftdi_interface;

use crate::{ftdi, FtdiCtx, UsbPortPath};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SdMuxTarget {
    Host,
    Dut,
}
impl clap::ValueEnum for SdMuxTarget {
    fn value_variants<'a>() -> &'a [Self] {
        &[Self::Host, Self::Dut]
    }

    fn to_possible_value<'a>(&self) -> Option<clap::PossibleValue<'a>> {
        match self {
            Self::Host => Some(PossibleValue::new("host").help("host can access sd card")),
            Self::Dut => {
                Some(PossibleValue::new("dut").help("device-under-test can boot from sd card"))
            }
        }
    }
}
impl FromStr for SdMuxTarget {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "dut" => Ok(Self::Dut),
            "host" => Ok(Self::Host),
            _ => Err(()),
        }
    }
}

pub struct SdMux {
    ftdi: FtdiCtx,
}
impl SdMux {
    pub fn open(port_path: UsbPortPath) -> anyhow::Result<Self> {
        let mut result = Self {
            ftdi: FtdiCtx::open(port_path, ftdi_interface::INTERFACE_A)?,
        };
        result.ftdi.set_bitmode(0xc0, ftdi::BitMode::BitBang)?;
        Ok(result)
    }

    pub fn set_target(&mut self, target: SdMuxTarget) -> anyhow::Result<()> {
        let pin_state = match target {
            SdMuxTarget::Dut => 0xf0,
            SdMuxTarget::Host => 0xf1,
        };
        self.ftdi.set_bitmode(pin_state, ftdi::BitMode::CBus)?;
        Ok(())
    }
}
