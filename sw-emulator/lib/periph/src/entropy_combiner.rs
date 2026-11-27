// Licensed under the Apache-2.0 license

use crate::{entropy_src::ConditionedSeed, helpers::MultiBitBool};
use caliptra_emu_bus::{Bus, BusError, Clock};
use caliptra_emu_types::{RvAddr, RvData, RvSize};
use sha3::{Digest, Sha3_384};
use std::{cell::Cell, rc::Rc};

// Byte offsets in the generated entropy_combiner::RegisterBlock and
// IntrBlockRfBlock (hw/latest/registers/src/entropy_combiner.rs).
const COMBINER_NAME_LO: RvAddr = 0x00;
const COMBINER_NAME_HI: RvAddr = 0x04;
const COMBINER_VERSION_LO: RvAddr = 0x08;
const COMBINER_VERSION_HI: RvAddr = 0x0c;
const KAT_CTRL: RvAddr = 0x10;
const KAT_MSG_LEN: RvAddr = 0x14;
const KAT_STATUS: RvAddr = 0x18;
const KAT_MSG_FIRST: RvAddr = 0x1c;
const KAT_DIGEST_FIRST: RvAddr = 0x7c;
const COMBINER_CTRL: RvAddr = 0xac;
const AHB_LOCK: RvAddr = 0xb0;
const COMBINER_STATUS: RvAddr = 0xb4;
const INTR_BLOCK: RvAddr = 0x400;
const ERROR_INTERNAL_INTR: RvAddr = INTR_BLOCK + 0x14;
const NOTIF_INTERNAL_INTR: RvAddr = INTR_BLOCK + 0x18;
const ERROR_INTR_TRIG: RvAddr = INTR_BLOCK + 0x1c;

const WORD_BYTES: usize = size_of::<u32>();
const KAT_MSG_WORDS: usize = 24;
const KAT_DIGEST_WORDS: usize = 12;
const KAT_MSG_LAST: RvAddr = KAT_MSG_FIRST + ((KAT_MSG_WORDS - 1) * WORD_BYTES) as RvAddr;
const KAT_DIGEST_LAST: RvAddr = KAT_DIGEST_FIRST + ((KAT_DIGEST_WORDS - 1) * WORD_BYTES) as RvAddr;
const KAT_MSG_BYTES: usize = KAT_MSG_WORDS * WORD_BYTES;
const KAT_MSG_GRANULARITY_BYTES: usize = 8;
const KAT_LATENCY_CYCLES: u64 = 64;

// Field encodings from the generated entropy_combiner::regs accessors.
const KAT_START: u32 = 1;
const KAT_BUSY: u32 = 1;
const KAT_VALID: u32 = 1 << 1;
const KAT_DONE: u32 = 1;
const ES_FIPS_POLICY_MASK: u32 = 0x3;
const ES_FIPS_POLICY_PRIMARY_ES0_ONLY: u32 = 1;
const ES_FIPS_POLICY_CONFIG_VALUE: u32 = 2;
const ES_FIPS_CFG_MASK: u32 = 1 << 8;
const WRITABLE_POLICY_MASK: u32 = ES_FIPS_POLICY_MASK | ES_FIPS_CFG_MASK;
const ZEROIZE: u32 = 1 << 16;
const AHB_LOCK_MASK: u32 = 0xf;
// Only strict MuBi4 false is unlocked. Invalid encodings also lock the KAT.
const AHB_UNLOCKED: u32 = MultiBitBool::False as u32;
const ERROR_INTR_TRIG_MASK: u32 = 0x1f;

const COMBINER_NAME: [u32; 2] = [0x61337368, 0x6d62636f];
const COMBINER_VERSION: [u32; 2] = [0x3032322e, 0];

#[derive(Default)]
pub(crate) struct CombinerLink {
    policy: Cell<u32>,
    errors: Cell<u32>,
    zeroize_epoch: Cell<u64>,
}

impl CombinerLink {
    pub(crate) fn zeroize_epoch(&self) -> u64 {
        self.zeroize_epoch.get()
    }

    pub(crate) fn combine(&self, es0: ConditionedSeed, es1: ConditionedSeed) -> ConditionedSeed {
        let mut hash = Sha3_384::new();
        hash.update(es0.bytes);
        hash.update(es1.bytes);
        ConditionedSeed {
            bytes: hash.finalize().into(),
            fips: self.output_fips(es0.fips, es1.fips),
        }
    }

    fn output_fips(&self, es0: bool, es1: bool) -> bool {
        let policy = self.policy.get();
        match policy & ES_FIPS_POLICY_MASK {
            ES_FIPS_POLICY_PRIMARY_ES0_ONLY => es0,
            ES_FIPS_POLICY_CONFIG_VALUE => policy & ES_FIPS_CFG_MASK != 0,
            _ => es0 && es1,
        }
    }

    pub(crate) fn has_error(&self) -> bool {
        self.errors.get() != 0
    }
}

/// Functional model of the ROM KAT and policy registers. Operational seeds
/// are assembled through the combiner link using the same policy and zeroize state.
pub struct EntropyCombiner {
    clock: Rc<Clock>,
    present: bool,
    message: [u8; KAT_MSG_BYTES],
    length: u32,
    digest: [u32; KAT_DIGEST_WORDS],
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
            message: [0; KAT_MSG_BYTES],
            length: 0,
            digest: [0; KAT_DIGEST_WORDS],
            finish: None,
            valid: false,
            dual: false,
            link: Rc::default(),
            integrity: None,
            lock: AHB_UNLOCKED,
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
    pub(crate) fn inject_error(&mut self, mask: u32) {
        self.write(RvSize::Word, ERROR_INTR_TRIG, mask).unwrap();
    }
    pub(crate) fn zeroize_count(&self) -> u64 {
        self.link.zeroize_epoch()
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
        self.lock != AHB_UNLOCKED || self.runtime_lock.get()
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
            Some(finish) if self.clock.now() < finish => KAT_BUSY,
            Some(_) => {
                self.finish = None;
                self.valid = true;
                self.notification = KAT_DONE;
                KAT_VALID
            }
            None => {
                if self.valid {
                    KAT_VALID
                } else {
                    0
                }
            }
        }
    }
}

// Even accesses to unmapped word offsets advance KAT status and sample the
// firmware-entry lock. Keep that shared pre-dispatch behavior here.
impl Bus for EntropyCombiner {
    fn read(&mut self, size: RvSize, addr: RvAddr) -> Result<RvData, BusError> {
        if !self.present || size != RvSize::Word || !addr.is_multiple_of(WORD_BYTES as RvAddr) {
            return Err(BusError::LoadAccessFault);
        }
        let status = self.status();
        Ok(match addr {
            COMBINER_NAME_LO => COMBINER_NAME[0],
            COMBINER_NAME_HI => COMBINER_NAME[1],
            COMBINER_VERSION_LO => COMBINER_VERSION[0],
            COMBINER_VERSION_HI => COMBINER_VERSION[1],
            KAT_MSG_LEN => self.length,
            KAT_STATUS => status,
            KAT_DIGEST_FIRST..=KAT_DIGEST_LAST if status == KAT_VALID => {
                self.digest[(addr - KAT_DIGEST_FIRST) as usize / WORD_BYTES]
            }
            KAT_DIGEST_FIRST..=KAT_DIGEST_LAST => 0,
            COMBINER_CTRL => self.link.policy.get(),
            AHB_LOCK => self.lock,
            COMBINER_STATUS => u32::from(self.dual),
            ERROR_INTERNAL_INTR => self.link.errors.get(),
            NOTIF_INTERNAL_INTR => self.notification,
            _ => return Err(BusError::LoadAccessFault),
        })
    }

    fn write(&mut self, size: RvSize, addr: RvAddr, val: RvData) -> Result<(), BusError> {
        if !self.present || size != RvSize::Word || !addr.is_multiple_of(WORD_BYTES as RvAddr) {
            return Err(BusError::StoreAccessFault);
        }
        let busy = self.status() == KAT_BUSY;
        match addr {
            KAT_CTRL if !self.locked() && !busy && val & KAT_START != 0 => {
                let length = (self.length as usize).min(KAT_MSG_BYTES) / KAT_MSG_GRANULARITY_BYTES
                    * KAT_MSG_GRANULARITY_BYTES;
                let digest = Sha3_384::digest(&self.message[..length]);
                for (word, bytes) in self.digest.iter_mut().zip(digest.chunks_exact(WORD_BYTES)) {
                    *word = u32::from_le_bytes(bytes.try_into().unwrap());
                }
                self.valid = false;
                self.kat_starts += 1;
                self.finish = Some(self.clock.now() + KAT_LATENCY_CYCLES);
            }
            KAT_CTRL => {}
            // Raw input registers are not cleared by the lock; only KAT's
            // snapshot and result are cleared. Explicit zeroize clears both.
            KAT_MSG_LEN => self.length = val,
            KAT_MSG_FIRST..=KAT_MSG_LAST => {
                let start = (addr - KAT_MSG_FIRST) as usize;
                self.message[start..start + WORD_BYTES].copy_from_slice(&val.to_le_bytes());
            }
            COMBINER_CTRL => {
                if !self.locked() {
                    self.link.policy.set(val & WRITABLE_POLICY_MASK);
                }
                if val & ZEROIZE != 0 {
                    self.clear_result();
                    self.length = 0;
                    self.message.fill(0);
                    self.link
                        .zeroize_epoch
                        .set(self.link.zeroize_epoch.get().wrapping_add(1));
                }
            }
            AHB_LOCK if self.lock == AHB_UNLOCKED => {
                self.lock = val & AHB_LOCK_MASK;
                if self.locked() {
                    self.clear_result();
                }
            }
            AHB_LOCK => {}
            ERROR_INTERNAL_INTR => self.link.errors.set(self.link.errors.get() & !val),
            NOTIF_INTERNAL_INTR => self.notification &= !val,
            ERROR_INTR_TRIG => self
                .link
                .errors
                .set(self.link.errors.get() | (val & ERROR_INTR_TRIG_MASK)),
            _ => return Err(BusError::StoreAccessFault),
        }
        Ok(())
    }

    fn warm_reset(&mut self) {
        self.clear_result();
        self.message.fill(0);
        self.length = 0;
        self.lock = AHB_UNLOCKED;
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
