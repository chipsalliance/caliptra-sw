/*++

Licensed under the Apache-2.0 license.

File Name:

    iccm.rs

Abstract:

    File contains ICCM Implementation

--*/
use crate::boot_integrity::SharedBootIntegrity;
use crate::KeyVault;
use caliptra_emu_bus::Bus;
use caliptra_emu_bus::BusError;
use caliptra_emu_bus::Clock;
use caliptra_emu_bus::Ram;
use caliptra_emu_bus::Timer;
use caliptra_emu_bus::TimerAction;
use caliptra_emu_crypto::EndianessTransform;
use caliptra_emu_types::RvAddr;
use caliptra_emu_types::RvData;
use caliptra_emu_types::RvSize;
use sha2::{Digest, Sha384};
use std::cell::Cell;
use std::{cell::RefCell, rc::Rc};

#[derive(Clone)]
pub struct Iccm {
    iccm: Rc<IccmImpl>,
}
const ICCM_SIZE_BYTES: usize = 256 * 1024;

impl Iccm {
    pub fn lock(&mut self) -> Result<(), BusError> {
        self.iccm.locked.set(true);
        let binding = self.iccm.integrity.borrow().clone();
        if let Some((state, mut vault)) = binding {
            let digest = state.borrow_mut().digest_to_finalize();
            if let Some(digest) = digest {
                let mut current_input = [0u8; 96];
                let mut previous_current = vault.read_pcr(4);
                previous_current.to_little_endian();
                current_input[..48].copy_from_slice(&previous_current);
                current_input[48..].copy_from_slice(&digest);
                let mut journey_input = [0u8; 96];
                let mut previous = vault.read_pcr(5);
                previous.to_little_endian();
                journey_input[..48].copy_from_slice(&previous);
                journey_input[48..].copy_from_slice(&digest);
                let mut current: [u8; 48] = Sha384::digest(current_input).into();
                let mut journey: [u8; 48] = Sha384::digest(journey_input).into();
                current.to_big_endian();
                journey.to_big_endian();
                vault.write_hardware_pcr(4, &current)?;
                vault.write_hardware_pcr(5, &journey)?;
                state.borrow_mut().finish_measurement();
            }
        }
        Ok(())
    }

    pub fn unlock(&mut self) {
        self.iccm.locked.set(false);
    }

    pub fn new(clock: &Clock) -> Self {
        Self {
            iccm: Rc::new(IccmImpl::new(clock)),
        }
    }

    pub fn ram(&self) -> &RefCell<Ram> {
        &self.iccm.ram
    }

    pub(crate) fn attach_boot_integrity(&mut self, state: SharedBootIntegrity, vault: KeyVault) {
        *self.iccm.integrity.borrow_mut() = Some((state, vault));
    }
}

struct IccmImpl {
    ram: RefCell<Ram>,
    locked: Cell<bool>,
    timer: Timer,
    integrity: RefCell<Option<(SharedBootIntegrity, KeyVault)>>,
}

impl IccmImpl {
    pub fn new(clock: &Clock) -> Self {
        Self {
            ram: RefCell::new(Ram::new(vec![0; ICCM_SIZE_BYTES])),
            locked: Cell::new(false),
            timer: clock.timer(),
            integrity: RefCell::new(None),
        }
    }
}

impl Bus for Iccm {
    /// Read data of specified size from given address
    fn read(&mut self, size: RvSize, addr: RvAddr) -> Result<RvData, BusError> {
        let value = self.iccm.ram.borrow_mut().read(size, addr)?;
        if let Some((state, mut vault)) = self.iccm.integrity.borrow().clone() {
            let transition = state.borrow_mut().observe_read(addr & !3);
            if let Some(transition) = transition {
                vault.boot_transition(transition);
            }
        }
        Ok(value)
    }

    /// Write data of specified size to given address
    fn write(&mut self, size: RvSize, addr: RvAddr, val: RvData) -> Result<(), BusError> {
        // NMIs don't fire immediately; a couple instructions is a fairly typicaly delay on VeeR.
        const NMI_DELAY: u64 = 2;

        // From RISC-V_VeeR_EL2_PRM.pdf
        const NMI_CAUSE_DBUS_STORE_ERROR: u32 = 0xf000_0000;

        if size != RvSize::Word || (addr & 0x3) != 0 {
            self.iccm.timer.schedule_action_in(
                NMI_DELAY,
                TimerAction::Nmi {
                    mcause: NMI_CAUSE_DBUS_STORE_ERROR,
                },
            );
            return Ok(());
        }
        if self.iccm.locked.get() {
            self.iccm.timer.schedule_action_in(
                NMI_DELAY,
                TimerAction::Nmi {
                    mcause: NMI_CAUSE_DBUS_STORE_ERROR,
                },
            );
            return Ok(());
        }
        self.iccm.ram.borrow_mut().write(size, addr, val)?;
        if let Some((state, _)) = self.iccm.integrity.borrow().as_ref() {
            state.borrow_mut().record_write(val);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::boot_integrity::BootIntegrity;
    use crate::{KeyUsage, MailboxRam, Sha512Accelerator};

    fn expected_extension(previous: [u8; 48], words: &[u32]) -> [u8; 48] {
        let stream: Vec<u8> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
        let mut input = previous.to_vec();
        input.extend_from_slice(&Sha384::digest(stream));
        Sha384::digest(input).into()
    }

    fn read_digest(vault: &KeyVault, id: u32) -> [u8; 48] {
        let mut digest = vault.read_pcr(id);
        digest.to_little_endian();
        digest
    }

    fn next_action(clock: &Clock) -> Option<TimerAction> {
        let mut actions = clock.increment(4);
        match actions.len() {
            0 => None,
            1 => actions.drain().next(),
            _ => panic!("More than one action scheduled; unexpected"),
        }
    }

    #[test]
    fn test_iccm_measurement_order_update_chain_and_accelerator_ownership() {
        let clock = Clock::new();
        let state = BootIntegrity::new(true, false, false, false);
        let mut vault = KeyVault::new();
        vault.attach_boot_integrity(state.clone());
        let mut iccm = Iccm::new(&clock);
        iccm.attach_boot_integrity(state.clone(), vault.clone());
        let mut accelerator = Sha512Accelerator::new(&clock, MailboxRam::default());
        accelerator.attach_boot_integrity(state.clone());
        iccm.write(RvSize::Word, 0, 0).unwrap();
        assert!(!state.borrow().measurement_busy());
        accelerator.write(RvSize::Word, 0, 1).unwrap();

        let cold_words = [0x04030201, 0x08070605, 0x0c0b0a09];
        for (addr, word) in [4, 0, 4].into_iter().zip(cold_words) {
            iccm.write(RvSize::Word, addr, word).unwrap();
        }
        assert_eq!(accelerator.read(RvSize::Word, 0), Ok(1));
        assert_eq!(
            accelerator.write(RvSize::Word, 0, 1),
            Err(BusError::StoreAccessFault)
        );
        iccm.lock().unwrap();
        let current = expected_extension([0; 48], &cold_words);
        assert_eq!(read_digest(&vault, 4), current);
        assert_eq!(read_digest(&vault, 5), current);
        assert_eq!(accelerator.read(RvSize::Word, 0), Ok(0));
        assert_eq!(accelerator.read(RvSize::Word, 0), Ok(1));
        accelerator.write(RvSize::Word, 0, 1).unwrap();
        iccm.lock().unwrap();
        assert_eq!(read_digest(&vault, 5), current);

        state.borrow_mut().reset(false);
        iccm.unlock();
        iccm.lock().unwrap();
        let warm = expected_extension(current, &[]);
        assert_eq!(read_digest(&vault, 4), warm);
        assert_eq!(read_digest(&vault, 5), warm);

        state.borrow_mut().reset(true);
        vault.write_hardware_pcr(4, &[0; 48]).unwrap();
        iccm.unlock();
        let update_words = [0x100f0e0d, 0x14131211];
        for (index, word) in update_words.into_iter().enumerate() {
            iccm.write(RvSize::Word, 0x9000 + index as u32 * 4, word)
                .unwrap();
        }
        iccm.lock().unwrap();
        assert_eq!(
            read_digest(&vault, 4),
            expected_extension([0; 48], &update_words)
        );
        assert_eq!(
            read_digest(&vault, 5),
            expected_extension(warm, &update_words)
        );
    }

    #[test]
    fn test_iccm_measurement_padding_and_empty_stream() {
        for length in [0, 4, 124, 128, 132, 256] {
            let clock = Clock::new();
            let state = BootIntegrity::new(true, false, false, false);
            let vault = KeyVault::new();
            let mut iccm = Iccm::new(&clock);
            iccm.attach_boot_integrity(state, vault.clone());
            let words: Vec<u32> = (0..length / 4).map(|index| 0x01020300 + index).collect();
            for (index, word) in words.iter().enumerate() {
                iccm.write(RvSize::Word, index as u32 * 4, *word).unwrap();
            }
            iccm.lock().unwrap();
            let expected = expected_extension([0; 48], &words);
            assert_eq!(read_digest(&vault, 4), expected);
            assert_eq!(read_digest(&vault, 5), expected);
        }
    }

    #[test]
    fn test_iccm_measurement_disabled_in_passive_mode() {
        let clock = Clock::new();
        let state = BootIntegrity::new(false, false, false, false);
        let vault = KeyVault::new();
        let mut iccm = Iccm::new(&clock);
        iccm.attach_boot_integrity(state, vault.clone());
        iccm.write(RvSize::Word, 0, 0x04030201).unwrap();
        iccm.lock().unwrap();
        assert_eq!(vault.read_pcr(4), [0; 48]);
        assert_eq!(vault.read_pcr(5), [0; 48]);
    }

    #[test]
    fn test_iccm_data_read_before_region_lock_flushes_keys_and_reports_fatal() {
        let clock = Clock::new();
        let state = BootIntegrity::new(true, true, false, false);
        let mut vault = KeyVault::new();
        vault.attach_boot_integrity(state.clone());
        vault.write_key(6, &[0x5a; 48], 1).unwrap();
        let mut iccm = Iccm::new(&clock);
        iccm.attach_boot_integrity(state.clone(), vault.clone());
        assert_eq!(iccm.read(RvSize::Word, 0), Ok(0));
        assert_eq!(state.borrow().fatal_error, 1 << 4);
        assert_eq!(
            vault.read_key(6, KeyUsage(1)),
            Err(BusError::LoadAccessFault)
        );
        assert_eq!(next_action(&clock), None);
    }

    #[test]
    fn test_unlocked_write() {
        let clock = Clock::new();
        let mut iccm = Iccm::new(&clock);
        for word_offset in (0u32..ICCM_SIZE_BYTES as u32).step_by(4) {
            assert_eq!(iccm.read(RvSize::Word, word_offset).unwrap(), 0);
            assert_eq!(
                iccm.write(RvSize::Word, word_offset, u32::MAX).ok(),
                Some(())
            );
            assert_eq!(iccm.read(RvSize::Word, word_offset).ok(), Some(u32::MAX));
        }
        assert_eq!(next_action(&clock), None);
    }

    #[test]
    fn test_locked_write() {
        let clock = Clock::new();
        let mut iccm = Iccm::new(&clock);
        iccm.lock().unwrap();
        for word_offset in (0u32..ICCM_SIZE_BYTES as u32).step_by(4) {
            assert_eq!(iccm.read(RvSize::Word, word_offset).unwrap(), 0);
            assert!(iccm.write(RvSize::Word, word_offset, u32::MAX).is_ok());
            assert_eq!(
                next_action(&clock),
                Some(TimerAction::Nmi {
                    mcause: 0xf000_0000
                })
            );
        }
        assert_eq!(next_action(&clock), None);
    }

    #[test]
    fn test_byte_write() {
        let clock = Clock::new();
        let mut iccm = Iccm::new(&clock);
        assert_eq!(iccm.write(RvSize::Byte, 0, 42), Ok(()));
        assert_eq!(
            next_action(&clock),
            Some(TimerAction::Nmi {
                mcause: 0xf000_0000
            })
        );
    }
}
