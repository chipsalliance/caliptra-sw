// Licensed under the Apache-2.0 license

use caliptra_registers::entropy_combiner::{EntropyCombinerReg, RegisterBlock};
use caliptra_ureg::{Mmio, MmioMut};

use crate::csrng::{MULTIBIT_FALSE, MULTIBIT_TRUE};
use crate::{CaliptraError, CaliptraResult};

const BOTH_SOURCES_FIPS: u32 = 0;
// A single SHA3-384 block takes far fewer cycles than this, including MMIO.
const KAT_POLL_LIMIT: usize = 4096;
const KAT_MSG_BYTES: u32 = 96;
const KAT_MSG_WORDS: usize = KAT_MSG_BYTES as usize / size_of::<u32>();
const KAT_DIGEST_WORDS: usize = 12;
// Asymmetric 96-byte input (00..5f), in ascending register word order.
const KAT_DIGEST: [u32; KAT_DIGEST_WORDS] = [
    0x9766e2d6, 0xd4dc3f0a, 0x86da33a8, 0x9a179915, 0x69570b06, 0xb493e959, 0x30298569, 0x238ce34e,
    0x702a10c7, 0x68d5c484, 0x2355d9b1, 0xe77740d1,
];

/// ROM startup driver borrowing the combiner token before CSRNG takes ownership.
pub struct EntropyCombiner<'a> {
    reg: &'a mut EntropyCombinerReg,
}

impl<'a> EntropyCombiner<'a> {
    pub fn new(reg: &'a mut EntropyCombinerReg) -> Self {
        Self { reg }
    }

    /// Returns true if the combiner AHB lock is currently set.
    pub fn is_locked(&self) -> bool {
        self.reg.regs().ahb_lock().read().lock() == MULTIBIT_TRUE
    }

    /// Run the startup KAT, select the conjunctive FIPS flag, and lock the combiner.
    /// Call only from Core ROM on internal-TRNG hardware, before requesting entropy.
    /// The shared CSRNG driver verifies the lock without opening the KAT interface.
    pub fn kat_and_lock(&mut self) -> CaliptraResult<()> {
        kat_and_lock(self.reg.regs_mut())
    }

    /// Run the startup KAT unless the combiner is already locked.
    ///
    /// The lock survives a firmware-update reset and closes the KAT interface.
    /// A warm reset clears the lock, so the KAT must run again. CSRNG still
    /// verifies the lock, FIPS policy, and error state before requesting entropy.
    pub fn kat_and_lock_if_needed(&mut self) -> CaliptraResult<()> {
        if self.is_locked() {
            Ok(())
        } else {
            self.kat_and_lock()
        }
    }
}

fn has_fault<M: Mmio>(regs: &RegisterBlock<M>) -> bool {
    u32::from(regs.intr_block_rf().error_internal_intr_r().read()) != 0
}

pub(crate) fn check_locked<M: Mmio>(regs: &RegisterBlock<M>) -> CaliptraResult<()> {
    if has_fault(regs) {
        return Err(CaliptraError::DRIVER_ENTROPY_COMBINER_HW_FAULT);
    }
    if regs.ahb_lock().read().lock() != MULTIBIT_TRUE
        || regs.combiner_ctrl().read().es_fips_policy() != BOTH_SOURCES_FIPS
        || !regs.combiner_status().read().combine_en()
    {
        return Err(CaliptraError::DRIVER_ENTROPY_COMBINER_BAD_STATE);
    }
    Ok(())
}

fn kat_and_lock<M: MmioMut>(regs: RegisterBlock<M>) -> CaliptraResult<()> {
    if has_fault(&regs) {
        return Err(CaliptraError::DRIVER_ENTROPY_COMBINER_HW_FAULT);
    }
    if regs.ahb_lock().read().lock() != MULTIBIT_FALSE || regs.kat_status().read().busy() {
        return Err(CaliptraError::DRIVER_ENTROPY_COMBINER_BAD_STATE);
    }
    for i in 0..KAT_MSG_WORDS {
        let b = i as u8 * 4;
        regs.kat_msg()
            .at(i)
            .write(|_| u32::from_le_bytes([b, b + 1, b + 2, b + 3]));
    }
    regs.kat_msg_len().write(|_| KAT_MSG_BYTES);
    regs.kat_ctrl().write(|w| w.start(true));
    wait_for_kat(&regs)?;

    let mut difference = 0;
    for (i, expected) in KAT_DIGEST.into_iter().enumerate() {
        difference |= regs.kat_digest().at(i).read() ^ expected;
    }
    if difference != 0 {
        return Err(CaliptraError::DRIVER_ENTROPY_COMBINER_KAT_MISMATCH);
    }
    regs.combiner_ctrl()
        .write(|w| w.es_fips_policy(BOTH_SOURCES_FIPS).es_fips_cfg(false));
    regs.ahb_lock().write(|w| w.lock(MULTIBIT_TRUE));
    if regs.ahb_lock().read().lock() != MULTIBIT_TRUE
        || regs.combiner_ctrl().read().es_fips_policy() != BOTH_SOURCES_FIPS
    {
        return Err(CaliptraError::DRIVER_ENTROPY_COMBINER_BAD_STATE);
    }
    if has_fault(&regs) {
        return Err(CaliptraError::DRIVER_ENTROPY_COMBINER_HW_FAULT);
    }
    Ok(())
}

fn wait_for_kat<M: Mmio>(regs: &RegisterBlock<M>) -> CaliptraResult<()> {
    for _ in 0..KAT_POLL_LIMIT {
        if has_fault(regs) {
            return Err(CaliptraError::DRIVER_ENTROPY_COMBINER_HW_FAULT);
        }
        let status = regs.kat_status().read();
        if !status.busy() && status.valid() {
            return Ok(());
        }
    }
    Err(CaliptraError::DRIVER_ENTROPY_COMBINER_KAT_TIMEOUT)
}

#[cfg(test)]
mod tests {
    use super::*;
    use caliptra_ureg::{Mmio, Uint};
    use core::cell::Cell;

    const KAT_CTRL_OFFSET: usize = 0x10;
    const KAT_STATUS_OFFSET: usize = 0x18;
    const AHB_LOCK_OFFSET: usize = 0xb0;

    struct KatMmio {
        started: Cell<bool>,
        wrote_lock: Cell<bool>,
        complete: bool,
    }

    impl Mmio for KatMmio {
        // SAFETY: required by the trait; the fake only interprets the address.
        unsafe fn read_volatile<T: Uint>(&self, src: *const T) -> T {
            let val = match src as usize - EntropyCombinerReg::PTR as usize {
                KAT_STATUS_OFFSET if self.started.get() => {
                    if self.complete {
                        2u32
                    } else {
                        1
                    }
                }
                AHB_LOCK_OFFSET => MULTIBIT_FALSE,
                // All-zero digest is a mismatch for the actual reference vector.
                _ => 0,
            };
            T::try_from(val).ok().unwrap()
        }
    }

    impl MmioMut for KatMmio {
        // SAFETY: required by the trait; the fake does not dereference the address.
        unsafe fn write_volatile<T: Uint>(&self, dst: *mut T, _: T) {
            match dst as usize - EntropyCombinerReg::PTR as usize {
                KAT_CTRL_OFFSET => self.started.set(true),
                AHB_LOCK_OFFSET => self.wrote_lock.set(true),
                _ => (),
            }
        }
    }

    #[test]
    fn kat_failure_does_not_lock() {
        for (complete, expected) in [
            (true, CaliptraError::DRIVER_ENTROPY_COMBINER_KAT_MISMATCH),
            (false, CaliptraError::DRIVER_ENTROPY_COMBINER_KAT_TIMEOUT),
        ] {
            let mmio = KatMmio {
                started: Cell::new(false),
                wrote_lock: Cell::new(false),
                complete,
            };
            let regs = unsafe { RegisterBlock::new_with_mmio(EntropyCombinerReg::PTR, &mmio) };
            assert_eq!(kat_and_lock(regs), Err(expected));
            assert!(mmio.started.get());
            assert!(!mmio.wrote_lock.get());
        }
    }
}
