// Licensed under the Apache-2.0 license

#![no_std]
#![no_main]

use caliptra_drivers::{entropy_combiner_kat_and_lock, Csrng, CsrngSeed, PersistentDataAccessor};
use caliptra_registers::{
    csrng::CsrngReg, entropy_combiner::EntropyCombinerReg, entropy_src::EntropySrcReg,
    soc_ifc::SocIfcReg,
};
use caliptra_test_harness::test_suite;

fn kat_and_lock() {
    // The KAT intentionally works in bypass mode as well.
    let mut combiner = unsafe { EntropyCombinerReg::new() };
    for bit in 0..5 {
        let regs = combiner.regs_mut();
        regs.intr_block_rf()
            .error_intr_trig_r()
            .write(|_| (1u32 << bit).into());
        assert_eq!(
            u32::from(regs.intr_block_rf().error_internal_intr_r().read()),
            1 << bit
        );
        assert_eq!(
            entropy_combiner_kat_and_lock(&mut combiner),
            Err(caliptra_drivers::CaliptraError::DRIVER_ENTROPY_COMBINER_HW_FAULT)
        );
        assert_eq!(combiner.regs().ahb_lock().read().lock(), 9);
        combiner
            .regs_mut()
            .intr_block_rf()
            .error_internal_intr_r()
            .write(|_| (1u32 << bit).into());
    }
    entropy_combiner_kat_and_lock(&mut combiner).unwrap();
    let regs = combiner.regs();
    assert_eq!(regs.ahb_lock().read().lock(), 6);
    assert!(!regs.kat_status().read().busy());
    assert!(!regs.kat_status().read().valid());
    assert!((0..12).all(|i| regs.kat_digest().at(i).read() == 0));
    assert_eq!(regs.kat_msg_len().read(), 96);
    let regs = combiner.regs_mut();
    regs.ahb_lock().write(|w| w.lock(9));
    regs.combiner_ctrl()
        .write(|w| w.es_fips_policy(1).es_fips_cfg(true));
    regs.kat_ctrl().write(|w| w.start(true));
    for _ in 0..128 {
        assert_eq!(u32::from(regs.kat_status().read()), 0);
    }
    assert_eq!(regs.ahb_lock().read().lock(), 6);
    assert_eq!(regs.combiner_ctrl().read().es_fips_policy(), 0);
    assert!(!regs.combiner_ctrl().read().es_fips_cfg());
    regs.combiner_ctrl().write(|w| w.zeroize(true));
    assert_eq!(regs.kat_msg_len().read(), 0);
    assert_eq!(regs.ahb_lock().read().lock(), 6);

    let soc = unsafe { SocIfcReg::new() };
    if soc.regs().cptra_hw_config().read().dual_i_trng_en() {
        // The host provisions ES0 in single-bit mode on lane 2 and ES1 in
        // multi-channel mode; see run_entropy_combiner_dual.
        let persistent = unsafe { PersistentDataAccessor::new() };
        let result = Csrng::new(
            unsafe { CsrngReg::new() },
            unsafe { EntropySrcReg::new() },
            &soc,
            persistent,
        );
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
