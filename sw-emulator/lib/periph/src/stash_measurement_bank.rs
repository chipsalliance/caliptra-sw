/*++

Licensed under the Apache-2.0 license.

File Name:

    stash_measurement_bank.rs

Abstract:

    File contains stash measurement bank peripheral implementation.

--*/

use caliptra_emu_bus::{BusError, ReadWriteRegister};
use caliptra_emu_derive::Bus;
use caliptra_emu_types::{RvData, RvSize};
use tock_registers::{
    interfaces::{ReadWriteable, Readable, Writeable},
    register_bitfields,
};

const NUM_REGISTERS_PER_SLOT: usize = 26;
const NUM_SLOTS: usize = 8;
const STASH_DATA_REGISTER_SIZE: usize = NUM_REGISTERS_PER_SLOT * NUM_SLOTS;

register_bitfields! [
    u32,

    /// Stash measurement: per-slot lock
    SocLock [
        LOCK OFFSET(0) NUMBITS(8) [],
        RSVD OFFSET(8) NUMBITS(24) [],
    ],

    /// Stash measurement: global end-of-stash latch
    EndStash [
        END_STASH OFFSET(0) NUMBITS(1) [],
        RSVD OFFSET(1) NUMBITS(31) [],
    ],

    /// Stash measurement: Caliptra-side post-drain lock
    CptraLock [
        LOCK OFFSET(0) NUMBITS(1) [],
        RSVD OFFSET(1) NUMBITS(31) [],
    ],

    // Stash measurement: status
    pub Status [
        SLOT_LOCKED OFFSET(0) NUMBITS(8) [],
        END_STASH OFFSET(8) NUMBITS(1) [],
        CPTRA_LOCK OFFSET(9) NUMBITS(1) [],
        RSVD OFFSET(10) NUMBITS(22) [],
    ],
];

#[derive(Bus)]
#[warm_reset_fn(warm_reset)]
pub struct StashMeasurementBank {
    #[register_array(offset = 0x00, write_fn = write_data)]
    data: [u32; STASH_DATA_REGISTER_SIZE],

    #[register(offset = 0x340, read_fn = read_write_only, write_fn = write_sticky_soc_lock)]
    soc_lock: ReadWriteRegister<u32, SocLock::Register>,

    #[register(offset = 0x344, read_fn = read_write_only, write_fn = write_sticky_end_stash)]
    end_stash: ReadWriteRegister<u32, EndStash::Register>,

    #[register(offset = 0x348, read_fn = read_write_only, write_fn = write_sticky_cptra_lock)]
    cptra_lock: ReadWriteRegister<u32, CptraLock::Register>,

    #[register(offset = 0x34c, write_fn = write_status)]
    status: ReadWriteRegister<u32, Status::Register>,

    subsystem_mode: bool,
}

impl StashMeasurementBank {
    pub fn new(subsystem_mode: bool) -> Self {
        Self {
            data: [0; STASH_DATA_REGISTER_SIZE],
            soc_lock: ReadWriteRegister::new(0),
            end_stash: ReadWriteRegister::new(0),
            cptra_lock: ReadWriteRegister::new(0),
            status: ReadWriteRegister::new(0),
            subsystem_mode,
        }
    }

    fn read_write_only(&self, _size: RvSize) -> Result<u32, BusError> {
        // Write-only registers always read 0 from bus.
        Ok(0)
    }

    fn write_sealed(&self) -> bool {
        self.end_stash.reg.read(EndStash::END_STASH) != 0 || self.post_drain_locked()
    }

    fn post_drain_locked(&self) -> bool {
        self.cptra_lock.reg.read(CptraLock::LOCK) != 0
    }

    fn write_sticky_soc_lock(&mut self, _size: RvSize, val: RvData) -> Result<(), BusError> {
        if self.write_sealed() {
            return Ok(());
        }

        let mask = if self.subsystem_mode { 0x1 } else { 0xff };
        let lock = self.soc_lock.reg.read(SocLock::LOCK) | (val & mask);
        self.soc_lock.reg.modify(SocLock::LOCK.val(lock));
        self.status.reg.modify(Status::SLOT_LOCKED.val(lock));

        Ok(())
    }

    fn write_sticky_end_stash(&mut self, _size: RvSize, val: RvData) -> Result<(), BusError> {
        if self.post_drain_locked() {
            return Ok(());
        }

        let bit = self.end_stash.reg.read(EndStash::END_STASH) | (val & 0x1);
        self.end_stash.reg.modify(EndStash::END_STASH.val(bit));
        self.status.reg.modify(Status::END_STASH.val(bit));

        Ok(())
    }

    fn write_sticky_cptra_lock(&mut self, _size: RvSize, val: RvData) -> Result<(), BusError> {
        let bit = self.cptra_lock.reg.read(CptraLock::LOCK) | (val & 0x1);
        self.cptra_lock.reg.modify(CptraLock::LOCK.val(bit));
        self.status.reg.modify(Status::CPTRA_LOCK.val(bit));

        Ok(())
    }

    fn write_data(&mut self, _size: RvSize, index: usize, val: RvData) -> Result<(), BusError> {
        if self.write_sealed() {
            return Ok(());
        }

        // Once a slot is locked, writes to it are dropped.
        let lock = self.soc_lock.reg.read(SocLock::LOCK);
        if lock & (1 << (index / NUM_REGISTERS_PER_SLOT)) != 0 {
            return Ok(());
        }

        // In subsystem mode, writes to slots after the first one are dropped.
        if self.subsystem_mode && index >= NUM_REGISTERS_PER_SLOT {
            return Ok(());
        }

        *self.data.get_mut(index).ok_or(BusError::StoreAccessFault)? = val;
        Ok(())
    }

    fn write_status(&mut self, _size: RvSize, _val: RvData) -> Result<(), BusError> {
        // Status is read-only from bus.
        Ok(())
    }

    fn warm_reset(&mut self) {
        self.data.fill(0);
        self.soc_lock.reg.set(0);
        self.end_stash.reg.set(0);
        self.cptra_lock.reg.set(0);
        self.status.reg.set(0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use caliptra_emu_bus::Bus;
    use core::mem::size_of;

    const DATA_OFFSET: u32 = 0x0;
    const SOC_LOCK_OFFSET: u32 = 0x340;
    const END_STASH_OFFSET: u32 = 0x344;
    const CPTRA_LOCK_OFFSET: u32 = 0x348;

    #[test]
    fn test_access_data() {
        // In passive mode all slots are accessible.
        let mut stash = StashMeasurementBank::new(false);
        assert!(!stash.subsystem_mode);

        for i in 0..STASH_DATA_REGISTER_SIZE {
            let addr = DATA_OFFSET + (size_of::<u32>() * i) as u32;
            stash.write(RvSize::Word, addr, i as u32).unwrap();
            let val = stash.read(RvSize::Word, addr as u32).unwrap();
            assert_eq!(val, i as u32);
        }

        // In subsystem mode only the first slot is accessible.
        let mut stash = StashMeasurementBank::new(true);
        assert!(stash.subsystem_mode);

        for i in 0..STASH_DATA_REGISTER_SIZE {
            let addr = DATA_OFFSET + (size_of::<u32>() * i) as u32;
            stash.write(RvSize::Word, addr, i as u32).unwrap();
            if i < NUM_REGISTERS_PER_SLOT {
                let val = stash.read(RvSize::Word, addr as u32).unwrap();
                assert_eq!(val, i as u32);
            } else {
                // Writes to slots after the first one are dropped.
                let val = stash.read(RvSize::Word, addr as u32).unwrap();
                assert_eq!(val, 0);
            }
        }
    }

    #[test]
    fn test_access_soc_lock() {
        // In passive mode only the least significant 8 bits are accessible.
        let mut stash = StashMeasurementBank::new(false);
        stash
            .write(RvSize::Word, SOC_LOCK_OFFSET, 0xdeadbeef)
            .unwrap();
        assert_eq!(stash.soc_lock.reg.get(), 0xef);

        // Verify sticky writes.
        stash.write(RvSize::Word, SOC_LOCK_OFFSET, 0x00).unwrap();
        assert_eq!(stash.soc_lock.reg.get(), 0xef);
        stash.write(RvSize::Word, SOC_LOCK_OFFSET, 0x10).unwrap();
        assert_eq!(stash.soc_lock.reg.get(), 0xff);

        // In subsystem mode only the least significant bit is accessible.
        let mut stash = StashMeasurementBank::new(true);
        stash
            .write(RvSize::Word, SOC_LOCK_OFFSET, 0xdeadbeef)
            .unwrap();
        assert_eq!(stash.soc_lock.reg.get(), 0x1);

        // Write-only: bus reads always return 0.
        let val = stash.read(RvSize::Word, SOC_LOCK_OFFSET).unwrap();
        assert_eq!(val, 0x0);
    }

    #[test]
    fn test_access_end_stash() {
        let mut stash = StashMeasurementBank::new(true);
        stash
            .write(RvSize::Word, END_STASH_OFFSET, 0xdeadbeee)
            .unwrap();
        assert_eq!(stash.end_stash.reg.get(), 0);

        stash
            .write(RvSize::Word, END_STASH_OFFSET, 0xdeadbeef)
            .unwrap();
        assert_eq!(stash.end_stash.reg.get(), 0x1);

        // Verify sticky writes.
        stash.write(RvSize::Word, END_STASH_OFFSET, 0x00).unwrap();
        assert_eq!(stash.end_stash.reg.get(), 0x1);

        // Write-only: bus reads always return 0.
        let val = stash.read(RvSize::Word, END_STASH_OFFSET).unwrap();
        assert_eq!(val, 0x0);
    }

    #[test]
    fn test_access_cptra_lock() {
        let mut stash = StashMeasurementBank::new(false);
        stash
            .write(RvSize::Word, CPTRA_LOCK_OFFSET, 0xdeadbeee)
            .unwrap();
        assert_eq!(stash.cptra_lock.reg.get(), 0);

        stash
            .write(RvSize::Word, CPTRA_LOCK_OFFSET, 0xdeadbeef)
            .unwrap();
        assert_eq!(stash.cptra_lock.reg.get(), 0x1);

        // Verify sticky writes.
        stash.write(RvSize::Word, CPTRA_LOCK_OFFSET, 0x00).unwrap();
        assert_eq!(stash.cptra_lock.reg.get(), 0x1);

        // Write-only: bus reads always return 0.
        let val = stash.read(RvSize::Word, CPTRA_LOCK_OFFSET).unwrap();
        assert_eq!(val, 0x0);
    }

    #[test]
    fn test_warm_reset() {
        let mut stash = StashMeasurementBank::new(false);

        stash.write(RvSize::Word, DATA_OFFSET, 0xdeadbeef).unwrap();
        stash
            .write(RvSize::Word, SOC_LOCK_OFFSET, 0xdeadbeef)
            .unwrap();
        stash
            .write(RvSize::Word, END_STASH_OFFSET, 0xdeadbeef)
            .unwrap();
        stash
            .write(RvSize::Word, CPTRA_LOCK_OFFSET, 0xdeadbeef)
            .unwrap();

        assert_eq!(stash.data[0], 0xdeadbeef);
        assert_eq!(stash.soc_lock.reg.get(), 0xef);
        assert_eq!(stash.end_stash.reg.get(), 0x1);
        assert_eq!(stash.cptra_lock.reg.get(), 0x1);

        stash.warm_reset();

        assert_eq!(stash.data, [0; STASH_DATA_REGISTER_SIZE]);
        assert_eq!(stash.soc_lock.reg.get(), 0);
        assert_eq!(stash.end_stash.reg.get(), 0);
        assert_eq!(stash.cptra_lock.reg.get(), 0);
        assert_eq!(stash.status.reg.get(), 0);

        stash.write(RvSize::Word, END_STASH_OFFSET, 0x1).unwrap();
        assert_eq!(stash.end_stash.reg.get(), 0x1);
    }

    #[test]
    fn test_drop_writes_once_end_stash_or_cptra_lock_is_set() {
        for addr in [END_STASH_OFFSET, CPTRA_LOCK_OFFSET] {
            let mut stash = StashMeasurementBank::new(false);
            stash.write(RvSize::Word, addr, 0x1).unwrap();

            for i in 0..STASH_DATA_REGISTER_SIZE {
                let addr = DATA_OFFSET + (size_of::<u32>() * i) as u32;
                stash.write(RvSize::Word, addr, i as u32).unwrap();
                assert_eq!(stash.data[i], 0);
            }
        }
    }

    #[test]
    fn test_drop_writes_once_soc_locked() {
        let mut stash = StashMeasurementBank::new(false);
        const LOCKED_SLOTS: u32 = 0b1010_0101;

        // Locked slots.
        stash
            .write(RvSize::Word, SOC_LOCK_OFFSET, LOCKED_SLOTS)
            .unwrap();

        // Writes to the locked slots should be dropped.
        for i in 0..STASH_DATA_REGISTER_SIZE {
            let addr = DATA_OFFSET + (size_of::<u32>() * i) as u32;
            stash.write(RvSize::Word, addr, i as u32).unwrap();

            if LOCKED_SLOTS & (1 << (i / NUM_REGISTERS_PER_SLOT)) != 0 {
                assert_eq!(stash.data[i], 0);
            } else {
                assert_eq!(stash.data[i], i as u32);
            }
        }
    }

    #[test]
    fn test_drop_writes_to_soc_lock_once_end_stash_is_set() {
        let mut stash = StashMeasurementBank::new(false);

        // Lock some slots.
        stash.write(RvSize::Word, SOC_LOCK_OFFSET, 0x3c).unwrap();
        assert_eq!(stash.soc_lock.reg.get(), 0x3c);

        // Set end-of-stash.
        stash.write(RvSize::Word, END_STASH_OFFSET, 0x1).unwrap();

        // Subsequent writes to SOC_LOCK should be dropped.
        stash.write(RvSize::Word, SOC_LOCK_OFFSET, 0xff).unwrap();
        assert_eq!(stash.soc_lock.reg.get(), 0x3c);
    }

    #[test]
    fn test_drop_writes_once_cptra_lock_is_set() {
        let mut stash = StashMeasurementBank::new(false);

        // Lock some slots.
        stash.write(RvSize::Word, SOC_LOCK_OFFSET, 0x3c).unwrap();
        assert_eq!(stash.soc_lock.reg.get(), 0x3c);

        // Set CPTRA_LOCK.
        stash.write(RvSize::Word, CPTRA_LOCK_OFFSET, 0x1).unwrap();

        // Subsequent writes to SOC_LOCK or END_STASH should be dropped.
        stash.write(RvSize::Word, SOC_LOCK_OFFSET, 0xff).unwrap();
        assert_eq!(stash.soc_lock.reg.get(), 0x3c);
        stash.write(RvSize::Word, END_STASH_OFFSET, 0x1).unwrap();
        assert_eq!(stash.end_stash.reg.get(), 0);
    }

    #[test]
    fn test_update_status() {
        let mut stash = StashMeasurementBank::new(false);

        assert_eq!(stash.status.reg.get(), 0);

        // Lock some slots.
        const LOCKED_SLOTS: u32 = 0b0011_1100;
        stash
            .write(RvSize::Word, SOC_LOCK_OFFSET, LOCKED_SLOTS)
            .unwrap();
        assert_eq!(stash.soc_lock.reg.get(), LOCKED_SLOTS);
        let val = stash.status.reg.read(Status::SLOT_LOCKED);
        assert_eq!(val, LOCKED_SLOTS);

        // Set end-of-stash.
        stash.write(RvSize::Word, END_STASH_OFFSET, 0x1).unwrap();
        let val = stash.status.reg.read(Status::END_STASH);
        assert_eq!(val, 0x1);

        // Set CPTRA_LOCK.
        stash.write(RvSize::Word, CPTRA_LOCK_OFFSET, 0x1).unwrap();
        let val = stash.status.reg.read(Status::CPTRA_LOCK);
        assert_eq!(val, 0x1);
    }
}
