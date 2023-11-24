// Licensed under the Apache-2.0 license

use std::{
    os::unix::prelude::OsStrExt,
    path::{Path, PathBuf},
};

use crate::UsbPortPath;

/// Returns the path to the block device connected to a particular USB port.
pub fn find_usb_block_device(usb_path: &UsbPortPath) -> anyhow::Result<PathBuf> {
    let iface_prefix = format!("{usb_path}:");
    let path = Path::new("/sys/bus/usb/devices").join(usb_path.to_string());
    for entry in std::fs::read_dir(path)? {
        let entry = entry?;
        if entry
            .file_name()
            .as_bytes()
            .starts_with(iface_prefix.as_bytes())
        {
            let Ok(iface_dir_iter) = std::fs::read_dir(entry.path()) else {
                continue;
            };
            for entry2 in iface_dir_iter {
                let Ok(iface_entry) = entry2 else {
                    continue;
                };
                if !iface_entry.file_name().as_bytes().starts_with(b"host") {
                    continue;
                }
                let Ok(iter3) = std::fs::read_dir(iface_entry.path()) else {
                    continue;
                };
                for entry3 in iter3 {
                    let Ok(entry3) = entry3 else {
                        continue;
                    };
                    if !entry3.file_name().as_bytes().starts_with(b"target") {
                        continue;
                    }
                    let Ok(iter4) = std::fs::read_dir(entry3.path()) else {
                        continue;
                    };
                    for entry4 in iter4 {
                        let Ok(entry4) = entry4 else {
                            continue;
                        };
                        let block_dir = entry4.path().join("block");
                        let Ok(block_devs) = std::fs::read_dir(block_dir) else {
                            continue;
                        };
                        let block_devs: Vec<_> = block_devs.collect();
                        if block_devs.len() != 1 {
                            continue;
                        }
                        let Ok(block_dev_name) = &block_devs[0] else {
                            continue;
                        };
                        let result = Path::new("/dev").join(block_dev_name.file_name());
                        println!(
                            "Block device associated with {usb_path} is {}",
                            result.display()
                        );
                        return Ok(result);
                    }
                }
            }
        }
    }
    unreachable!();
}
