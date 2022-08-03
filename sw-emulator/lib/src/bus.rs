/*++

Licensed under the Apache-2.0 license.

File Name:

    bus.rs

Abstract:

    File contains types related to the CPU bus.

--*/

use std::io::ErrorKind;

use crate::{Device, RvAddr, RvData, RvException, RvSize};

/// Represents an abstract memory bus. Used to read and write from RAM and
/// peripheral addresses.
pub trait Bus {
    /// Read data of specified size from given address
    ///
    /// # Arguments
    ///
    /// * `size` - Size of the read
    /// * `addr` - Address to read from
    ///
    /// # Error
    ///
    /// * `RvException` - Exception with cause `RvExceptionCause::LoadAccessFault`
    ///                   or `RvExceptionCause::LoadAddrMisaligned`
    fn read(&self, size: RvSize, addr: RvAddr) -> Result<RvData, RvException>;

    /// Write data of specified size to given address
    ///
    /// # Arguments
    ///
    /// * `size` - Size of the write
    /// * `addr` - Address to write
    /// * `val` - Data to write
    ///
    /// # Error
    ///
    /// * `RvException` - Exception with cause `RvExceptionCause::StoreAccessFault`
    ///                   or `RvExceptionCause::StoreAddrMisaligned`
    fn write(&mut self, size: RvSize, addr: RvAddr, val: RvData) -> Result<(), RvException>;
}

/// A bus that uses dynamic-dispatch to delegate to a runtime-modifiable list of
/// devices. Useful as a quick-and-dirty Bus implementation.
pub struct DynamicBus {
    /// Devices connected to the CPU
    devs: Vec<Box<dyn Device>>,
}

impl DynamicBus {
    pub fn new() -> DynamicBus {
        Self { devs: Vec::new() }
    }
    /// Attach the specified device to the CPU
    ///
    /// # Arguments
    ///
    /// * `dev` - Device to attach
    pub fn attach_dev(&mut self, dev: Box<dyn Device>) -> std::io::Result<()> {
        let mut index = 0;
        let dev_addr = dev.mmap_range();
        for cur_dev in self.devs.iter() {
            let cur_dev_addr = cur_dev.mmap_range();
            // Check if the device range overlaps existing device
            if dev_addr.end() >= cur_dev_addr.start() && dev_addr.start() <= cur_dev_addr.end() {
                return Err(std::io::Error::new(
                    ErrorKind::AddrInUse,
                    format!("Address space for device {} ({:#010x}-{:#010x}) collides with device {} ({:#010x}-{:#010x})",
                    dev.name(), dev.mmap_range().start(), dev.mmap_range().end(),
                    cur_dev.name(), cur_dev.mmap_range().start(), cur_dev.mmap_range().end())));
            }
            // Found the position to insert the device
            if dev_addr.start() < cur_dev_addr.start() {
                break;
            }
            index += 1;
        }
        self.devs.insert(index, dev);
        Ok(())
    }

    /// Return the list of devices attached to the CPU
    ///
    ///  # Return
    ///
    ///  * `&Vec<Box<dyn Device>>` - List of devices
    #[allow(dead_code)]
    pub fn devs(&self) -> &Vec<Box<dyn Device>> {
        &self.devs
    }
}

impl Bus for DynamicBus {
    fn read(&self, size: RvSize, addr: RvAddr) -> Result<RvData, RvException> {
        let dev = self.devs.iter().find(|d| d.mmap_range().contains(&addr));
        match dev {
            Some(dev) => dev.read(size, addr - dev.mmap_addr()),
            None => Err(RvException::load_access_fault(addr)),
        }
    }

    fn write(&mut self, size: RvSize, addr: RvAddr, val: RvData) -> Result<(), RvException> {
        let dev = self
            .devs
            .iter_mut()
            .find(|d| d.mmap_range().contains(&addr));
        match dev {
            Some(dev) => dev.write(size, addr - dev.mmap_addr(), val),
            None => Err(RvException::store_access_fault(addr)),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{Ram, Rom, RvSize};

    #[test]
    fn test_dynamic_bus_read() {
        let mut bus = DynamicBus::new();
        let rom = Rom::new("ROM0", 1, vec![1, 2]);
        bus.attach_dev(Box::new(rom)).unwrap();
        assert_eq!(bus.read(RvSize::Byte, 1).ok(), Some(1));
        assert_eq!(bus.read(RvSize::Byte, 2).ok(), Some(2));
        assert_eq!(
            bus.read(RvSize::Byte, 3).err(),
            Some(RvException::load_access_fault(3))
        );
    }

    #[test]
    fn test_dynamic_bus_write() {
        let mut bus = DynamicBus::new();
        let rom = Ram::new("RAM0", 1, vec![1, 2]);
        bus.attach_dev(Box::new(rom)).unwrap();
        assert_eq!(bus.write(RvSize::Byte, 1, 3).ok(), Some(()));
        assert_eq!(bus.read(RvSize::Byte, 1).ok(), Some(3));
        assert_eq!(bus.write(RvSize::Byte, 2, 4).ok(), Some(()));
        assert_eq!(bus.read(RvSize::Byte, 2).ok(), Some(4));
        assert_eq!(
            bus.write(RvSize::Byte, 3, 0).err(),
            Some(RvException::store_access_fault(3))
        );
    }

    fn is_sorted<T>(slice: &[T]) -> bool
    where
        T: Ord,
    {
        slice.windows(2).all(|s| s[0] <= s[1])
    }

    #[test]
    fn test_attach_dev() {
        let mut bus = DynamicBus::new();
        let rom = Rom::new("ROM0", 1, vec![1, 2]);
        // Attach valid devices
        bus.attach_dev(Box::new(rom)).unwrap();
        let rom = Rom::new("ROM1", 0, vec![1]);
        bus.attach_dev(Box::new(rom)).unwrap();
        let rom = Rom::new("ROM2", 3, vec![1]);
        bus.attach_dev(Box::new(rom)).unwrap();

        // Try inserting devices whose address maps overlap existing devices

        let rom = Rom::new("ROM3", 1, vec![1]);
        let err = bus.attach_dev(Box::new(rom)).err().unwrap();
        assert_eq!(err.to_string(), "Address space for device ROM3 (0x00000001-0x00000001) collides with device ROM0 (0x00000001-0x00000002)");

        let rom = Rom::new("ROM4", 2, vec![1]);
        let err = bus.attach_dev(Box::new(rom)).err().unwrap();
        assert_eq!(err.to_string(), "Address space for device ROM4 (0x00000002-0x00000002) collides with device ROM0 (0x00000001-0x00000002)");

        let addrs: Vec<RvAddr> = bus
            .devs()
            .iter()
            .flat_map(|d| [d.mmap_addr(), d.mmap_addr() + d.mmap_size() - 1])
            .collect();
        assert_eq!(addrs.len(), 6);
        assert!(is_sorted(&addrs));
    }
}
