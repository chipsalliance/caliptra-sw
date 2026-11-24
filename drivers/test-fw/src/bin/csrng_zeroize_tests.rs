// Licensed under the Apache-2.0 license

#![no_std]
#![no_main]

use caliptra_drivers::{
    CaliptraError, Csrng, EntropyCombiner, EntropyRegs, PersistentDataAccessor,
};
use caliptra_registers::{
    csrng::CsrngReg,
    entropy_combiner::EntropyCombinerReg,
    entropy_src::{self, EntropySrc1Reg, EntropySrcReg},
    soc_ifc::SocIfcReg,
};
use caliptra_test_harness::test_suite;

const MULTIBIT_TRUE: u32 = 6;
const MULTIBIT_FALSE: u32 = 9;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SourceConfigSnapshot {
    conf: u32,
    health_test_windows: u32,
    repcnt_threshold: u32,
    repcnts_threshold: u32,
    adaptp_hi_threshold: u32,
    adaptp_lo_threshold: u32,
    adaptps_threshold: u32,
    alert_threshold: u32,
    sw_regupd: bool,
}

fn make_csrng(soc: &SocIfcReg) -> Csrng {
    Csrng::new(
        unsafe { CsrngReg::new() },
        unsafe { EntropyRegs::new() },
        soc,
        unsafe { PersistentDataAccessor::new() },
    )
    .expect("construct CSRNG")
}

fn disable_sources(dual: bool) {
    let mut es0 = unsafe { EntropySrcReg::new() };
    es0.regs_mut()
        .module_enable()
        .write(|w| w.module_enable(MULTIBIT_FALSE));
    if dual {
        let mut es1 = unsafe { EntropySrc1Reg::new() };
        es1.regs_mut()
            .module_enable()
            .write(|w| w.module_enable(MULTIBIT_FALSE));
    }
}

fn test_csrng_zeroize_flow() {
    let soc = unsafe { SocIfcReg::new() };
    let dual = soc.regs().cptra_hw_config().read().dual_i_trng_en();
    if dual {
        let mut combiner = unsafe { EntropyCombinerReg::new() };
        EntropyCombiner::new(&mut combiner)
            .kat_and_lock_if_needed()
            .unwrap();
    }

    let es0 = unsafe { EntropySrcReg::new() };
    let es1 = unsafe { EntropySrc1Reg::new() };
    let active_sources = [(true, es0.regs()), (dual, es1.regs())];
    let snapshot_config = |e: &entropy_src::RegisterBlock<_>| SourceConfigSnapshot {
        conf: u32::from(e.conf().read()),
        health_test_windows: u32::from(e.health_test_windows().read()),
        repcnt_threshold: e.repcnt_threshold().read().repcnt_threshold(),
        repcnts_threshold: e.repcnts_threshold().read().repcnts_threshold(),
        adaptp_hi_threshold: e.adaptp_hi_threshold().read().adaptp_hi_threshold(),
        adaptp_lo_threshold: e.adaptp_lo_threshold().read().adaptp_lo_threshold(),
        adaptps_threshold: e.adaptps_threshold().read().adaptps_threshold(),
        alert_threshold: u32::from(e.alert_threshold().read()),
        sw_regupd: e.sw_regupd().read().sw_regupd(),
    };
    let assert_source_state = |e: &entropy_src::RegisterBlock<_>,
                               expected_cfg,
                               expected_enable,
                               expect_watermark_zero| {
        assert_eq!(snapshot_config(e), expected_cfg);
        assert_eq!(e.module_enable().read().module_enable(), expected_enable);
        if expect_watermark_zero {
            assert_eq!(e.ht_watermark().read().ht_watermark(), 0);
        }
    };

    // 1. Enabled sources: generate, zeroize, verify config retention, automatic
    //    startup restart, and fresh post-zeroize seed without toggling enable.
    let mut csrng = make_csrng(&soc);
    let before = csrng.generate12().expect("pre-zeroize generate12");

    let mut cfgs = [snapshot_config(&active_sources[0].1); 2];
    for (i, (active, e)) in active_sources.iter().enumerate() {
        if *active {
            cfgs[i] = snapshot_config(e);
            assert_eq!(e.module_enable().read().module_enable(), MULTIBIT_TRUE);
            assert!(e.ht_watermark().read().ht_watermark() > 0);
        }
    }

    csrng.zeroize().expect("zeroize enabled sources");

    for (i, (active, e)) in active_sources.iter().enumerate() {
        if *active {
            assert_source_state(e, cfgs[i], MULTIBIT_TRUE, false);
        }
    }
    if dual {
        let mut combiner = unsafe { EntropyCombinerReg::new() };
        assert!(EntropyCombiner::new(&mut combiner).is_locked());
        assert_eq!(combiner.regs().combiner_ctrl().read().es_fips_policy(), 0);
    }

    let mut csrng = make_csrng(&soc);
    let after_enabled = csrng.generate12().expect("post-zeroize generate12");
    assert_ne!(after_enabled, before);

    // 2. Disabled sources: disable alone retains HT_WATERMARK; zeroize must
    //    scrub HT_WATERMARK to 0 while keeping disabled sources disabled.
    disable_sources(dual);
    for (active, e) in &active_sources {
        if *active {
            assert_eq!(e.module_enable().read().module_enable(), MULTIBIT_FALSE);
            assert!(e.ht_watermark().read().ht_watermark() > 0);
        }
    }

    csrng.zeroize().expect("zeroize disabled sources");

    for (i, (active, e)) in active_sources.iter().enumerate() {
        if *active {
            assert_source_state(e, cfgs[i], MULTIBIT_FALSE, true);
        }
    }

    // 3. Re-enable after disabled zeroize and confirm fresh seeds.
    let mut csrng = make_csrng(&soc);
    let after_disabled = csrng
        .generate12()
        .expect("generate12 after disabled zeroize");
    assert_ne!(after_disabled, after_enabled);

    // 4. Fault resilience: a sticky combiner HW fault must not prevent
    //    `zeroize` from uninstantiating CSRNG and scrubbing active entropy
    //    sources, while still reporting the fault.
    if dual {
        let csrng_reg = unsafe { CsrngReg::new() };
        let mut combiner = unsafe { EntropyCombinerReg::new() };

        disable_sources(true);
        assert!(csrng_reg.regs().reseed_counter_2().read() > 0);

        combiner
            .regs_mut()
            .intr_block_rf()
            .error_intr_trig_r()
            .write(|_| 1u32.into());

        assert_eq!(
            csrng.zeroize(),
            Err(CaliptraError::DRIVER_ENTROPY_COMBINER_HW_FAULT)
        );
        assert_eq!(csrng_reg.regs().reseed_counter_2().read(), 0);
        for (i, (_, e)) in active_sources.iter().enumerate() {
            assert_source_state(e, cfgs[i], MULTIBIT_FALSE, true);
        }

        // Clear the injected combiner fault before exiting.
        combiner
            .regs_mut()
            .intr_block_rf()
            .error_internal_intr_r()
            .write(|_| 1u32.into());
    }
}

test_suite! { test_csrng_zeroize_flow, }
