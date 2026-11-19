// Licensed under the Apache-2.0 license

#![no_std]
#![no_main]

use caliptra_drivers::{Csrng, CsrngSeed, EntropyCombiner, EntropyRegs, PersistentDataAccessor};
use caliptra_registers::{csrng::CsrngReg, soc_ifc::SocIfcReg};
use caliptra_test_harness::test_suite;

fn kat_and_lock() {
    // The KAT intentionally works in bypass mode as well.
    let mut entropy = unsafe { EntropyRegs::new() };
    let combiner = entropy.combiner_mut();
    for bit in [0u32, 4] {
        let regs = combiner.regs_mut();
        regs.intr_block_rf()
            .error_intr_trig_r()
            .write(|_| (1u32 << bit).into());
        assert_eq!(
            u32::from(regs.intr_block_rf().error_internal_intr_r().read()),
            1 << bit
        );
        let mut driver = EntropyCombiner::new(combiner);
        assert_eq!(
            driver.kat_and_lock(),
            Err(caliptra_drivers::CaliptraError::DRIVER_ENTROPY_COMBINER_HW_FAULT)
        );
        assert!(!driver.is_locked());
        combiner
            .regs_mut()
            .intr_block_rf()
            .error_internal_intr_r()
            .write(|_| (1u32 << bit).into());
    }
    let mut driver = EntropyCombiner::new(combiner);
    driver.kat_and_lock().unwrap();
    assert!(driver.is_locked());
    let regs = combiner.regs();
    assert!(!regs.kat_status().read().busy());
    assert!(!regs.kat_status().read().valid());
    assert!((0..12).all(|i| regs.kat_digest().at(i).read() == 0));
    assert_eq!(regs.kat_msg_len().read(), 96);
    let regs = combiner.regs_mut();
    regs.ahb_lock().write(|w| w.lock(9));
    regs.combiner_ctrl()
        .write(|w| w.es_fips_policy(1).es_fips_cfg(true));
    regs.kat_ctrl().write(|w| w.start(true));
    assert_eq!(u32::from(regs.kat_status().read()), 0);
    assert!(EntropyCombiner::new(combiner).is_locked());
    assert_eq!(combiner.regs().combiner_ctrl().read().es_fips_policy(), 0);
    assert!(!combiner.regs().combiner_ctrl().read().es_fips_cfg());
    combiner
        .regs_mut()
        .combiner_ctrl()
        .write(|w| w.zeroize(true));
    assert_eq!(combiner.regs().kat_msg_len().read(), 0);
    assert!(EntropyCombiner::new(combiner).is_locked());

    let soc = unsafe { SocIfcReg::new() };
    if soc.regs().cptra_hw_config().read().dual_i_trng_en() {
        // The host provisions ES0 in single-bit mode on lane 2 and ES1 in
        // multi-channel mode; see run_entropy_combiner_dual.
        let persistent = unsafe { PersistentDataAccessor::new() };
        let result = Csrng::new(unsafe { CsrngReg::new() }, entropy, &soc, persistent);
        // Fault fixture: this marker is set before boot by the host test only.
        if soc.regs().cptra_dbg_manuf_service_reg().read() & (1 << 15) != 0 {
            assert_eq!(
                result.err(),
                Some(caliptra_drivers::CaliptraError::DRIVER_CSRNG_REPCNT_HEALTH_CHECK_FAILED)
            );
            return;
        }
        // Generate and reseed from both sources after lockdown, including an
        // automatic reseed.
        let mut csrng = result.unwrap();
        csrng.generate12().unwrap();
        csrng.reseed(CsrngSeed::EntropySrc).unwrap();
        unsafe { CsrngReg::new() }
            .regs_mut()
            .reseed_interval()
            .write(|_| 1);
        csrng.generate12().unwrap();
        csrng.generate12().unwrap();
    }
}

test_suite! { kat_and_lock, }
