// Licensed under the Apache-2.0 license

use caliptra_emu_bus::{Bus, BusError, Clock};
use caliptra_emu_types::{RvAddr, RvData, RvSize};
use sha3::{Digest, Sha3_384};
use std::{cell::Cell, rc::Rc};

#[derive(Default)]
pub(crate) struct CombinerLink {
    policy: Cell<u32>,
    errors: Cell<u32>,
    pub zeroize_epoch: Cell<u64>,
}

impl CombinerLink {
    pub fn output_fips(&self, es0: bool, es1: bool) -> bool {
        let policy = self.policy.get();
        match policy & 3 {
            1 => es0,
            2 => policy & 0x100 != 0,
            _ => es0 && es1,
        }
    }

    pub fn has_error(&self) -> bool {
        self.errors.get() != 0
    }
}

/// Functional model of the ROM KAT and policy registers. Operational seeds
/// are assembled by CSRNG using the same policy and zeroize state.
pub struct EntropyCombiner {
    clock: Rc<Clock>,
    present: bool,
    message: [u8; 96],
    length: u32,
    digest: [u32; 12],
    finish: Option<u64>,
    valid: bool,
    dual: bool,
    link: Rc<CombinerLink>,
    integrity: Option<crate::boot_integrity::SharedBootIntegrity>,
    lock: u32,
    runtime_lock: Cell<bool>,
    notification: u32,
    kat_starts: u64,
}

impl EntropyCombiner {
    pub fn new(clock: Rc<Clock>, present: bool) -> Self {
        Self {
            clock,
            present,
            message: [0; 96],
            length: 0,
            digest: [0; 12],
            finish: None,
            valid: false,
            dual: false,
            link: Rc::default(),
            integrity: None,
            lock: 9,
            runtime_lock: Cell::new(false),
            notification: 0,
            kat_starts: 0,
        }
    }

    pub(crate) fn set_dual(&mut self) {
        self.dual = true;
    }
    pub(crate) fn kat_starts(&self) -> u64 {
        self.kat_starts
    }
    pub(crate) fn link(&self) -> Rc<CombinerLink> {
        self.link.clone()
    }
    pub(crate) fn attach_boot_integrity(
        &mut self,
        integrity: crate::boot_integrity::SharedBootIntegrity,
    ) {
        self.integrity = Some(integrity);
    }

    fn locked(&self) -> bool {
        if self
            .integrity
            .as_ref()
            .is_some_and(|state| state.borrow().entered_firmware())
        {
            self.runtime_lock.set(true);
        }
        self.lock != 9 || self.runtime_lock.get()
    }

    fn clear_result(&mut self) {
        self.digest.fill(0);
        self.finish = None;
        self.valid = false;
    }

    fn status(&mut self) -> RvData {
        if self.locked() {
            self.clear_result();
            return 0;
        }
        match self.finish {
            Some(finish) if self.clock.now() < finish => 1,
            Some(_) => {
                self.finish = None;
                self.valid = true;
                self.notification = 1;
                2
            }
            None => u32::from(self.valid) << 1,
        }
    }
}

impl Bus for EntropyCombiner {
    fn read(&mut self, size: RvSize, addr: RvAddr) -> Result<RvData, BusError> {
        if !self.present || size != RvSize::Word || !addr.is_multiple_of(4) {
            return Err(BusError::LoadAccessFault);
        }
        let status = self.status();
        Ok(match addr {
            0x00 => 0x61337368,
            0x04 => 0x6d62636f,
            0x08 => 0x3032322e,
            0x0c => 0,
            0x14 => self.length,
            0x18 => status,
            0x7c..=0xa8 if status == 2 => self.digest[((addr - 0x7c) / 4) as usize],
            0x7c..=0xa8 => 0,
            0xac => self.link.policy.get(),
            0xb0 => self.lock,
            0xb4 => u32::from(self.dual),
            0x414 => self.link.errors.get(),
            0x418 => self.notification,
            _ => return Err(BusError::LoadAccessFault),
        })
    }

    fn write(&mut self, size: RvSize, addr: RvAddr, val: RvData) -> Result<(), BusError> {
        if !self.present || size != RvSize::Word || !addr.is_multiple_of(4) {
            return Err(BusError::StoreAccessFault);
        }
        let busy = self.status() == 1;
        match addr {
            0x10 if !self.locked() && !busy && val & 1 != 0 => {
                let length = ((self.length / 8).min(12) * 8) as usize;
                let digest = Sha3_384::digest(&self.message[..length]);
                for (word, bytes) in self.digest.iter_mut().zip(digest.chunks_exact(4)) {
                    *word = u32::from_le_bytes(bytes.try_into().unwrap());
                }
                self.valid = false;
                self.kat_starts += 1;
                self.finish = Some(self.clock.now() + 64);
            }
            0x10 => {}
            // Raw input registers are not cleared by the lock; only KAT's
            // snapshot and result are cleared. Explicit zeroize clears both.
            0x14 => self.length = val,
            0x1c..=0x78 => {
                let start = (addr - 0x1c) as usize;
                self.message[start..start + 4].copy_from_slice(&val.to_le_bytes());
            }
            0xac => {
                if !self.locked() {
                    self.link.policy.set(val & 0x103);
                }
                if val & (1 << 16) != 0 {
                    self.clear_result();
                    self.length = 0;
                    self.message.fill(0);
                    self.link
                        .zeroize_epoch
                        .set(self.link.zeroize_epoch.get().wrapping_add(1));
                }
            }
            0xb0 if self.lock == 9 => {
                self.lock = val & 0xf;
                if self.locked() {
                    self.clear_result();
                }
            }
            0xb0 => {}
            0x414 => self.link.errors.set(self.link.errors.get() & !val),
            0x418 => self.notification &= !val,
            0x41c => self.link.errors.set(self.link.errors.get() | (val & 0x1f)),
            _ => return Err(BusError::StoreAccessFault),
        }
        Ok(())
    }

    fn warm_reset(&mut self) {
        self.clear_result();
        self.message.fill(0);
        self.length = 0;
        self.lock = 9;
        self.runtime_lock.set(false);
        self.notification = 0;
        self.link.policy.set(0);
        // The error status is in the power-good reset domain.
    }

    // Update reset is CPU-only; the combiner and its lock are retained.
    fn update_reset(&mut self) {
        self.locked(); // Sample the backstop before SOC_IFC resets its boot-flow state.
    }
}
