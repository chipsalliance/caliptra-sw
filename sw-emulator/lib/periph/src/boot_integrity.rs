// Licensed under the Apache-2.0 license

use caliptra_emu_bus::BusError;
use caliptra_emu_types::{RvAddr, RvData, RvSize};
use sha2::{Digest, Sha384};
use std::{cell::RefCell, rc::Rc};

pub(crate) type SharedBootIntegrity = Rc<RefCell<BootIntegrity>>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BootTransition {
    Fmc,
    Runtime,
    Error,
}

#[derive(Default)]
struct ShadowRegion {
    value: u32,
    pending: Option<u32>,
    committed: bool,
}

pub(crate) struct BootIntegrity {
    measurement_enabled: bool,
    monitor_enabled: bool,
    pub(crate) stable_owner: bool,
    pub(crate) ocp_lock: bool,
    regions: [ShadowRegion; 4],
    region_lock: bool,
    fmc: bool,
    runtime: bool,
    monitor_failed: bool,
    pub(crate) fatal_error: u32,
    pub(crate) non_fatal_error: u32,
    stream: Sha384,
    armed: bool,
    done: bool,
    software_sha_locked: bool,
}

impl BootIntegrity {
    pub(crate) fn new(
        subsystem: bool,
        debug_locked: bool,
        stable_owner: bool,
        ocp_lock: bool,
    ) -> SharedBootIntegrity {
        Rc::new(RefCell::new(Self {
            measurement_enabled: subsystem,
            monitor_enabled: subsystem && debug_locked,
            stable_owner,
            ocp_lock,
            regions: std::array::from_fn(|_| ShadowRegion::default()),
            region_lock: false,
            fmc: false,
            runtime: false,
            monitor_failed: false,
            fatal_error: 0,
            non_fatal_error: 0,
            stream: Sha384::new(),
            armed: false,
            done: false,
            software_sha_locked: false,
        }))
    }

    pub(crate) fn measurement_enabled(&self) -> bool {
        self.measurement_enabled
    }

    pub(crate) fn measurement_busy(&self) -> bool {
        self.measurement_enabled && self.armed && !self.done
    }

    pub(crate) fn record_write(&mut self, value: u32) {
        if self.measurement_enabled && !self.done && (!self.software_sha_locked || self.armed) {
            self.armed = true;
            self.stream.update(value.to_le_bytes());
        }
    }

    pub(crate) fn digest_to_finalize(&mut self) -> Option<[u8; 48]> {
        if !self.measurement_enabled || self.done || (self.software_sha_locked && !self.armed) {
            return None;
        }
        self.armed = true;
        Some(self.stream.clone().finalize().into())
    }

    pub(crate) fn finish_measurement(&mut self) {
        self.done = true;
    }

    pub(crate) fn set_software_sha_lock(&mut self, locked: bool) {
        self.software_sha_locked = locked;
    }

    pub(crate) fn reset(&mut self, update: bool) {
        if update {
            for region in &mut self.regions {
                region.committed = false;
            }
        } else {
            self.regions = std::array::from_fn(|_| ShadowRegion::default());
        }
        self.region_lock = false;
        self.fmc = false;
        self.runtime = false;
        self.monitor_failed = false;
        self.stream = Sha384::new();
        self.armed = false;
        self.done = false;
    }

    pub(crate) fn is_region_address(&self, address: RvAddr) -> bool {
        (0x650..=0x660).contains(&address)
    }

    pub(crate) fn read_region(
        &mut self,
        size: RvSize,
        address: RvAddr,
        external: bool,
    ) -> Result<RvData, BusError> {
        if size != RvSize::Word || !address.is_multiple_of(4) {
            return Err(BusError::LoadAccessFault);
        }
        if external {
            return Ok(0);
        }
        if address == 0x660 {
            return Ok(u32::from(self.region_lock));
        }
        let region = &mut self.regions[(address - 0x650) as usize / 4];
        region.pending = None;
        Ok(region.value)
    }

    pub(crate) fn write_region(
        &mut self,
        size: RvSize,
        address: RvAddr,
        value: RvData,
        external: bool,
    ) -> Result<(), BusError> {
        if size != RvSize::Word || !address.is_multiple_of(4) {
            return Err(BusError::StoreAccessFault);
        }
        if external {
            return Ok(());
        }
        if address == 0x660 {
            self.region_lock |= value & 1 != 0;
            return Ok(());
        }
        if self.region_lock {
            return Ok(());
        }
        let region = &mut self.regions[(address - 0x650) as usize / 4];
        let value = value & 0x3ffff;
        match region.pending.take() {
            None => region.pending = Some(value),
            Some(previous) if previous == value => {
                region.value = value;
                region.committed = true;
            }
            Some(_) => self.non_fatal_error |= 1 << 3,
        }
        Ok(())
    }

    pub(crate) fn fail(&mut self) {
        self.monitor_failed = true;
        self.fatal_error |= 1 << 4;
    }

    pub(crate) fn observe_read(&mut self, address: RvAddr) -> Option<BootTransition> {
        if !self.monitor_enabled || self.monitor_failed {
            return None;
        }
        let locked = self.region_lock && self.regions.iter().all(|r| r.committed);
        let in_fmc = (self.regions[0].value..=self.regions[1].value).contains(&address);
        let in_rt = (self.regions[2].value..=self.regions[3].value).contains(&address);
        if !locked || (in_rt && !self.fmc) || (!in_fmc && !in_rt) {
            self.fail();
            return Some(BootTransition::Error);
        }
        if in_fmc && !self.fmc {
            self.fmc = true;
            return Some(BootTransition::Fmc);
        }
        if in_rt && !self.runtime {
            self.runtime = true;
            return Some(BootTransition::Runtime);
        }
        None
    }

    pub(crate) fn entered_firmware(&self) -> bool {
        self.fmc || self.runtime
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state(locked: bool) -> SharedBootIntegrity {
        BootIntegrity::new(true, locked, false, false)
    }

    fn program(state: &mut BootIntegrity) {
        for (index, value) in [0, 0xfff, 0x9000, 0x9fff].into_iter().enumerate() {
            for _ in 0..2 {
                state
                    .write_region(RvSize::Word, 0x650 + index as u32 * 4, value, false)
                    .unwrap();
            }
        }
        state.write_region(RvSize::Word, 0x660, 1, false).unwrap();
    }

    #[test]
    fn shadow_protocol_and_external_access() {
        let state = state(true);
        let mut state = state.borrow_mut();
        state
            .write_region(RvSize::Word, 0x650, 0x100, false)
            .unwrap();
        assert_eq!(state.read_region(RvSize::Word, 0x650, true), Ok(0));
        state
            .write_region(RvSize::Word, 0x650, 0x100, false)
            .unwrap();
        assert_eq!(state.read_region(RvSize::Word, 0x650, false), Ok(0x100));
        state
            .write_region(RvSize::Word, 0x654, 0xfff, false)
            .unwrap();
        state.read_region(RvSize::Word, 0x654, false).unwrap();
        state
            .write_region(RvSize::Word, 0x654, 0xfff, false)
            .unwrap();
        assert!(!state.regions[1].committed);
        state
            .write_region(RvSize::Word, 0x654, 0x2000, false)
            .unwrap();
        assert_eq!(state.non_fatal_error, 1 << 3);
    }

    #[test]
    fn ranges_transitions_and_reset_rearm() {
        let state = state(true);
        let mut state = state.borrow_mut();
        program(&mut state);
        assert_eq!(state.observe_read(0), Some(BootTransition::Fmc));
        assert_eq!(state.observe_read(0x9000), Some(BootTransition::Runtime));
        state.reset(true);
        assert_eq!(state.read_region(RvSize::Word, 0x660, false), Ok(0));
        program(&mut state);
        assert_eq!(state.observe_read(0x9000), Some(BootTransition::Error));
        assert_eq!(state.fatal_error, 1 << 4);
    }

    #[test]
    fn subsystem_and_debug_gating() {
        for subsystem in [false, true] {
            for debug_locked in [false, true] {
                let state = BootIntegrity::new(subsystem, debug_locked, false, false);
                let mut state = state.borrow_mut();
                assert!(state.is_region_address(0x650));
                state.record_write(0x04030201);
                assert_eq!(state.measurement_busy(), subsystem);
                assert_eq!(
                    state.observe_read(0),
                    if subsystem && debug_locked {
                        Some(BootTransition::Error)
                    } else {
                        None
                    }
                );
            }
        }
    }

    #[test]
    fn region_lock_requires_all_commits_and_is_write_once() {
        let incomplete = state(true);
        let mut incomplete = incomplete.borrow_mut();
        for _ in 0..2 {
            incomplete
                .write_region(RvSize::Word, 0x650, 0, false)
                .unwrap();
        }
        incomplete
            .write_region(RvSize::Word, 0x660, 1, false)
            .unwrap();
        assert_eq!(incomplete.observe_read(0), Some(BootTransition::Error));

        let complete = state(true);
        let mut complete = complete.borrow_mut();
        program(&mut complete);
        complete
            .write_region(RvSize::Word, 0x660, 0, false)
            .unwrap();
        for external in [false, true] {
            for _ in 0..2 {
                complete
                    .write_region(RvSize::Word, 0x650, 0x2000, external)
                    .unwrap();
            }
        }
        assert_eq!(complete.read_region(RvSize::Word, 0x650, false), Ok(0));
        assert_eq!(complete.read_region(RvSize::Word, 0x660, false), Ok(1));
        assert_eq!(complete.observe_read(0), Some(BootTransition::Fmc));
    }

    #[test]
    fn region_reads_are_inclusive_and_phase_transitions_are_single_shot() {
        let state = state(true);
        let mut state = state.borrow_mut();
        program(&mut state);
        assert_eq!(state.observe_read(0xffc), Some(BootTransition::Fmc));
        assert_eq!(state.observe_read(0), None);
        assert!(state.entered_firmware());
        assert_eq!(state.observe_read(0x9ffc), Some(BootTransition::Runtime));
        assert_eq!(state.observe_read(0x9000), None);
        assert_eq!(state.observe_read(0xa000), Some(BootTransition::Error));
        assert_eq!(state.fatal_error, 1 << 4);
    }

    #[test]
    fn reset_rearms_warm_and_changed_update_bounds() {
        let state = state(true);
        let mut state = state.borrow_mut();
        program(&mut state);
        for update in [false, true] {
            state.reset(update);
            assert!(!state.entered_firmware());
            assert_eq!(
                state.read_region(RvSize::Word, 0x65c, false),
                Ok(if update { 0x9fff } else { 0 })
            );
            program(&mut state);
            assert_eq!(state.observe_read(0), Some(BootTransition::Fmc));
        }
        state.reset(true);
        for (index, value) in [0, 0xfff, 0x9000, 0xafff].into_iter().enumerate() {
            for _ in 0..2 {
                state
                    .write_region(RvSize::Word, 0x650 + index as u32 * 4, value, false)
                    .unwrap();
            }
        }
        state.write_region(RvSize::Word, 0x660, 1, false).unwrap();
        assert_eq!(state.observe_read(0), Some(BootTransition::Fmc));
        assert_eq!(state.observe_read(0xa000), Some(BootTransition::Runtime));
    }

    #[test]
    fn write_stream_uses_native_words_and_single_shot() {
        let state = state(false);
        let mut state = state.borrow_mut();
        state.record_write(0x04030201);
        assert!(state.measurement_busy());
        assert_eq!(
            state.digest_to_finalize().unwrap(),
            <[u8; 48]>::from(Sha384::digest([1, 2, 3, 4]))
        );
        state.finish_measurement();
        assert!(!state.measurement_busy());
        assert!(state.digest_to_finalize().is_none());
        state.reset(false);
        assert!(state.digest_to_finalize().is_some());
    }

    #[test]
    fn software_sha_lock_blocks_initial_iccm_measurement() {
        let state = state(false);
        let mut state = state.borrow_mut();
        state.set_software_sha_lock(true);
        state.record_write(0);
        assert!(!state.measurement_busy());
        assert!(state.digest_to_finalize().is_none());
        state.set_software_sha_lock(false);
        state.record_write(0x04030201);
        assert_eq!(
            state.digest_to_finalize().unwrap(),
            <[u8; 48]>::from(Sha384::digest([1, 2, 3, 4]))
        );
    }
}
