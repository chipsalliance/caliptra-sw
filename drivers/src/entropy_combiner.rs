// Licensed under the Apache-2.0 license

use caliptra_registers::entropy_combiner::{EntropyCombinerReg, RegisterBlock};
use caliptra_ureg::MmioMut;

use crate::{CaliptraError, CaliptraResult};

const UNLOCKED: u32 = 0x9;
const LOCKED: u32 = 0x6;
const BOTH_SOURCES_FIPS: u32 = 0;
// A single SHA3-384 block takes far fewer cycles than this, including MMIO.
const KAT_POLL_LIMIT: usize = 4096;
// Asymmetric 96-byte input (00..5f), in ascending register word order.
const KAT_DIGEST: [u32; 12] = [
    0x9766e2d6, 0xd4dc3f0a, 0x86da33a8, 0x9a179915, 0x69570b06, 0xb493e959, 0x30298569, 0x238ce34e,
    0x702a10c7, 0x68d5c484, 0x2355d9b1, 0xe77740d1,
];

/// Run the startup KAT, select the conjunctive FIPS flag, and lock the combiner.
/// Call only from Core ROM on internal-TRNG hardware, before requesting entropy.
/// The shared CSRNG driver verifies the lock without opening the KAT interface.
pub fn entropy_combiner_kat_and_lock(combiner: &mut EntropyCombinerReg) -> CaliptraResult<()> {
    kat_and_lock(combiner.regs_mut())
}

pub(crate) fn check_locked(combiner: &EntropyCombinerReg) -> CaliptraResult<()> {
    let regs = combiner.regs();
    if u32::from(regs.intr_block_rf().error_internal_intr_r().read()) != 0 {
        return Err(CaliptraError::DRIVER_ENTROPY_COMBINER_HW_FAULT);
    }
    if regs.ahb_lock().read().lock() != LOCKED
        || regs.combiner_ctrl().read().es_fips_policy() != BOTH_SOURCES_FIPS
        || !regs.combiner_status().read().combine_en()
    {
        return Err(CaliptraError::DRIVER_ENTROPY_COMBINER_BAD_STATE);
    }
    Ok(())
}

fn kat_and_lock<M: MmioMut>(regs: RegisterBlock<M>) -> CaliptraResult<()> {
    let has_fault = || u32::from(regs.intr_block_rf().error_internal_intr_r().read()) != 0;
    if has_fault() {
        return Err(CaliptraError::DRIVER_ENTROPY_COMBINER_HW_FAULT);
    }
    if regs.ahb_lock().read().lock() != UNLOCKED || regs.kat_status().read().busy() {
        return Err(CaliptraError::DRIVER_ENTROPY_COMBINER_BAD_STATE);
    }
    for i in 0..24 {
        let b = i as u8 * 4;
        regs.kat_msg()
            .at(i)
            .write(|_| u32::from_le_bytes([b, b + 1, b + 2, b + 3]));
    }
    regs.kat_msg_len().write(|_| 96);
    regs.kat_ctrl().write(|w| w.start(true));
    for _ in 0..KAT_POLL_LIMIT {
        if has_fault() {
            return Err(CaliptraError::DRIVER_ENTROPY_COMBINER_HW_FAULT);
        }
        let status = regs.kat_status().read();
        if status.busy() || !status.valid() {
            continue;
        }
        let mut difference = 0;
        for (i, expected) in KAT_DIGEST.into_iter().enumerate() {
            difference |= regs.kat_digest().at(i).read() ^ expected;
        }
        if difference != 0 {
            return Err(CaliptraError::DRIVER_ENTROPY_COMBINER_KAT_MISMATCH);
        }
        regs.combiner_ctrl()
            .write(|w| w.es_fips_policy(BOTH_SOURCES_FIPS).es_fips_cfg(false));
        regs.ahb_lock().write(|w| w.lock(LOCKED));
        if regs.ahb_lock().read().lock() != LOCKED
            || regs.combiner_ctrl().read().es_fips_policy() != BOTH_SOURCES_FIPS
        {
            return Err(CaliptraError::DRIVER_ENTROPY_COMBINER_BAD_STATE);
        }
        if has_fault() {
            return Err(CaliptraError::DRIVER_ENTROPY_COMBINER_HW_FAULT);
        }
        return Ok(());
    }
    Err(CaliptraError::DRIVER_ENTROPY_COMBINER_KAT_TIMEOUT)
}

#[cfg(test)]
mod tests {
    use super::*;
    use caliptra_ureg::{Mmio, Uint};
    use core::cell::Cell;

    struct KatMmio {
        started: Cell<bool>,
        wrote_lock: Cell<bool>,
        complete: bool,
    }

    impl Mmio for KatMmio {
        // SAFETY: required by the trait; the fake only interprets the address.
        unsafe fn read_volatile<T: Uint>(&self, src: *const T) -> T {
            let val = match src as usize - EntropyCombinerReg::PTR as usize {
                0x18 if self.started.get() => {
                    if self.complete {
                        2u32
                    } else {
                        1
                    }
                }
                0xb0 => UNLOCKED,
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
                0x10 => self.started.set(true),
                0xb0 => self.wrote_lock.set(true),
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
