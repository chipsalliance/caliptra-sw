// Licensed under the Apache-2.0 license

use anyhow::Context;
use std::fs;
use std::path::PathBuf;
use std::str::FromStr;

use clap::PossibleValue;
use libftdi1_sys::ftdi_interface;

use crate::{find_usb_block_device::find_usb_block_device, ftdi, FtdiCtx, UsbPortPath};

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

// SdMux is a trait for SD muxes. It provides a way to set the target (DUT or host) and open the mux.
pub trait SdMux {
    fn set_target(&mut self, target: SdMuxTarget) -> anyhow::Result<()>;

    /// Opens the mux and returns a new instance of the mux.
    /// For SDWire, this is the FTDI device. It will be converted into UsbPortPath.
    /// For UsbSDMux, this is UID for the USBSDMUX device.
    fn open(port_path: String) -> anyhow::Result<Self>
    where
        Self: Sized;

    /// Returns the path to the block device associated with the SD mux.
    fn get_sd_dev_path(&mut self) -> anyhow::Result<PathBuf>;
}

// Implementation specific to SDWire (idVendor=04e8, idProduct=6001)
pub struct SDWire {
    // The FTDI device used to communicate with the SDWire mux.
    ftdi: FtdiCtx,

    // The USB port path of the SDWire mux.
    port_path: UsbPortPath,
}

impl SdMux for SDWire {
    fn open(port_path: String) -> anyhow::Result<Self> {
        let port_path: UsbPortPath = UsbPortPath::from_str(&port_path)
            .map_err(|_| anyhow::anyhow!("Failed to parse port path"))?;

        let mut result = Self {
            ftdi: FtdiCtx::open(port_path.clone(), ftdi_interface::INTERFACE_A)?,
            port_path,
        };

        result.ftdi.set_bitmode(0xc0, ftdi::BitMode::BitBang)?;
        Ok(result)
    }

    fn set_target(&mut self, target: SdMuxTarget) -> anyhow::Result<()> {
        let pin_state = match target {
            SdMuxTarget::Dut => 0xf0,
            SdMuxTarget::Host => 0xf1,
        };
        self.ftdi.set_bitmode(pin_state, ftdi::BitMode::CBus)?;
        Ok(())
    }

    fn get_sd_dev_path(&mut self) -> anyhow::Result<PathBuf> {
        let sdwire_hub_path = self.port_path.child(0);
        find_usb_block_device(&sdwire_hub_path.child(1)).with_context(|| {
            format!(
                "Could not find block device associated with {}",
                sdwire_hub_path.child(1)
            )
        })
    }
}

// The UsbSDMux does expose the following things:
// 1. A python cli interface to set the target.
// 1.1 change target
// 1.2 Shut the mux off
// 1.3 manipulate GPIO pins on the MUX
// 2. A SCSI generic device interface to set the target.
// 2.1 A block device that can be used to access the SD card.
// NO FTDI interface is exposed.
// The SCSI generic device is usually /dev/sg0 but can be different (check sg_map -i).
// https://github.com/linux-automation/usbsdmux/
pub struct UsbsdMux {
    // SCSI generic device name, e.g. sg0.
    scsi_generic_name: String,
}

impl SdMux for UsbsdMux {
    /// USBSDMUX exposes all connected adapters as linux devices under dev/usb-sd-mux/id-xxxxx.xxxxx.
    /// The ID used to construct an UsbdsdMux instance is the symlink name without the leading "id-".
    /// Resolving these symlinks by ID resolves them to the according /dev/sgX device.
    fn open(sdmux_id: String) -> anyhow::Result<Self> {
        let symlink_path = format!("/dev/usb-sd-mux/id-{}", sdmux_id);

        // this will be of format ../sgx
        let had_dev = std::fs::read_link(symlink_path)?
            .to_string_lossy()
            .to_string();

        return Ok(Self {
            scsi_generic_name: had_dev.strip_prefix("../").unwrap().to_string(),
        });
    }

    // For now we use the python cli tool implementation provided by the vendor.
    // Further, we assume there is only one usbsdmux device connected, exposed
    // via /dev/sg0.
    fn set_target(&mut self, target: SdMuxTarget) -> anyhow::Result<()> {
        let target = match target {
            SdMuxTarget::Dut => "dut",
            SdMuxTarget::Host => "host",
        };

        if std::process::Command::new("usbsdmux")
            .arg("--help")
            .output()
            .is_err()
        {
            return Err(anyhow::anyhow!("usbsdmux tool not found"));
        }

        let out = std::process::Command::new("usbsdmux")
            .arg(format!("/dev/{}", self.scsi_generic_name.clone()))
            .arg(target)
            .output()
            .map_err(|e| anyhow::anyhow!("usbsdmux: {}", e))?;

        if !out.status.success() {
            return Err(anyhow::anyhow!(
                "Failed to set target: {}",
                String::from_utf8_lossy(&out.stderr)
            ));
        }
        if !out.stdout.is_empty() {
            println!("usbsdmux output: {}", String::from_utf8_lossy(&out.stdout));
        }
        Ok(())
    }

    // Resolve the SCSI generic device name to the block device name.
    fn get_sd_dev_path(&mut self) -> anyhow::Result<PathBuf> {
        let scsi_block_dev = format!(
            "/sys/class/scsi_generic/{}/device/block/",
            self.scsi_generic_name
        );
        if let Some(entry) = fs::read_dir(&scsi_block_dev)?.next() {
            let entry = entry?;
            let block_dev_name = entry.file_name();
            let block_dev_path = format!("/dev/{}", block_dev_name.to_string_lossy());
            Ok(PathBuf::from(block_dev_path))
        } else {
            Err(anyhow::anyhow!(
                "Failed to find block device for SCSI generic device {}. Ensure the device is connected and the path {} exists.",
                self.scsi_generic_name,
                &scsi_block_dev
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sd_mux_target() {
        assert_eq!(SdMuxTarget::from_str("host").unwrap(), SdMuxTarget::Host);
        assert_eq!(SdMuxTarget::from_str("dut").unwrap(), SdMuxTarget::Dut);
        assert!(SdMuxTarget::from_str("invalid").is_err());
    }
}
