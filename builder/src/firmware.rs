// Licensed under the Apache-2.0 license

// Centralized list of all firmware targets. This allows us to compile them all
// ahead of time for executing tests on hosts that can't compile rust code.

use crate::FwId;

pub fn rom_from_env() -> &'static FwId<'static> {
    match std::env::var("CPTRA_ROM_TYPE").as_ref().map(|s| s.as_str()) {
        Ok("ROM") | Ok("ROM_WITHOUT_UART") => &ROM,
        Ok("ROM_WITH_UART") | Err(_) => &ROM_WITH_UART,
        Ok(s) => panic!("unexpected CPRTA_TEST_ROM env-var value: {s:?}"),
    }
}

/// Define a firmware target by their features and crate names.
///
/// <div class="warning">The defined FwID struct is `pub`.</div>
macro_rules! fwid {
    ($name:ident, $crate_name:expr, $bin_name:expr, $features:expr) => {
        pub const $name: FwId = FwId {
            crate_name: $crate_name,
            bin_name: $bin_name,
            features: $features,
        };
    };
}

/// Define a firmware target by their features and crate names, with a base FwId.
///
/// <div class="warning">The defined FwID struct is `pub`.</div>
macro_rules! fwid_base {
    ($name:ident, $bin_name:expr, $base:expr) => {
        pub const $name: FwId = FwId {
            bin_name: $bin_name,
            ..$base
        };
    };
}

fwid!(ROM, "caliptra-rom", "caliptra-rom", &[]);
fwid!(ROM_WITH_UART, "caliptra-rom", "caliptra-rom", &["emu"]);
fwid!(
    ROM_FAKE_WITH_UART,
    "caliptra-rom",
    "caliptra-rom",
    &["emu", "fake-rom"]
);
fwid!(
    ROM_WITH_FIPS_TEST_HOOKS,
    "caliptra-rom",
    "caliptra-rom",
    &["fips-test-hooks"]
);
fwid!(FMC_WITH_UART, "caliptra-fmc", "caliptra-fmc", &["emu"]);
fwid!(
    FMC_FAKE_WITH_UART,
    "caliptra-fmc",
    "caliptra-fmc",
    &["emu", "fake-fmc"]
);
fwid!(
    APP,
    "caliptra-runtime",
    "caliptra-runtime",
    &["fips_self_test"]
);
fwid!(
    APP_WITH_UART,
    "caliptra-runtime",
    "caliptra-runtime",
    &["emu", "fips_self_test"]
);
fwid!(
    APP_WITH_UART_FIPS_TEST_HOOKS,
    "caliptra-runtime",
    "caliptra-runtime",
    &["emu", "fips_self_test", "fips-test-hooks"]
);
fwid!(
    APP_WITH_UART_FPGA,
    "caliptra-runtime",
    "caliptra-runtime",
    &["emu", "fips_self_test", "fpga_realtime"]
);
fwid!(APP_ZEROS, "caliptra-zeros", "caliptra-zeros", &[]);
fwid!(FMC_ZEROS, "caliptra-zeros", "caliptra-zeros", &["fmc"]);

pub mod caliptra_builder_tests {
    use super::*;

    pub const FWID: FwId = FwId {
        crate_name: "caliptra-drivers-test-bin",
        bin_name: "test_success",
        features: &[],
    };
}

pub mod hw_model_tests {
    use super::*;

    const BASE_FWID: FwId = FwId {
        crate_name: "caliptra-hw-model-test-fw",
        bin_name: "",
        features: &["emu"],
    };

    fwid_base!(MAILBOX_RESPONDER, "mailbox_responder", BASE_FWID);
    fwid_base!(MAILBOX_SENDER, "mailbox_sender", BASE_FWID);
    fwid_base!(TEST_ICCM_BYTE_WRITE, "test_iccm_byte_write", BASE_FWID);
    fwid_base!(
        TEST_ICCM_UNALIGNED_WRITE,
        "test_iccm_unaligned_write",
        BASE_FWID
    );
    fwid_base!(TEST_ICCM_WRITE_LOCKED, "test_iccm_write_locked", BASE_FWID);
    fwid_base!(
        TEST_INVALID_INSTRUCTION,
        "test_invalid_instruction",
        BASE_FWID
    );
    fwid_base!(TEST_WRITE_TO_ROM, "test_write_to_rom", BASE_FWID);
    fwid_base!(
        TEST_ICCM_DOUBLE_BIT_ECC,
        "test_iccm_double_bit_ecc",
        BASE_FWID
    );
    fwid_base!(
        TEST_DCCM_DOUBLE_BIT_ECC,
        "test_dccm_double_bit_ecc",
        BASE_FWID
    );
    fwid_base!(TEST_UNITIALIZED_READ, "test_uninitialized_read", BASE_FWID);
    fwid_base!(TEST_PCR_EXTEND, "test_pcr_extend", BASE_FWID);
}

pub mod driver_tests {
    use super::*;

    const BASE_FWID: FwId = FwId {
        crate_name: "caliptra-drivers-test-bin",
        bin_name: "",
        features: &["emu"],
    };

    fwid_base!(DOE, "doe", BASE_FWID);
    fwid_base!(ECC384, "ecc384", BASE_FWID);
    fwid_base!(
        ECC384_SIGN_VALIDATION_FAILURE,
        "ecc384_sign_validation_failure",
        BASE_FWID
    );
    fwid_base!(ERROR_REPORTER, "error_reporter", BASE_FWID);
    fwid_base!(HMAC384, "hmac384", BASE_FWID);
    fwid_base!(KEYVAULT, "keyvault", BASE_FWID);

    pub const KEYVAULT_FPGA: FwId = FwId {
        bin_name: "keyvault",
        features: &["fpga_realtime"],
        ..BASE_FWID
    };

    fwid_base!(
        MAILBOX_DRIVER_RESPONDER,
        "mailbox_driver_responder",
        BASE_FWID
    );
    fwid_base!(MAILBOX_DRIVER_SENDER, "mailbox_driver_sender", BASE_FWID);
    fwid_base!(
        MAILBOX_DRIVER_NEGATIVE_TESTS,
        "mailbox_driver_negative_tests",
        BASE_FWID
    );
    fwid_base!(MBOX_SEND_TXN_DROP, "mbox_send_txn_drop", BASE_FWID);
    fwid_base!(PCRBANK, "pcrbank", BASE_FWID);
    fwid_base!(SHA1, "sha1", BASE_FWID);
    fwid_base!(SHA256, "sha256", BASE_FWID);
    fwid_base!(SHA384, "sha384", BASE_FWID);
    fwid_base!(SHA2_512_384ACC, "sha2_512_384acc", BASE_FWID);
    fwid_base!(STATUS_REPORTER, "status_reporter", BASE_FWID);
    fwid_base!(TEST_LMS_24, "test_lms_24", BASE_FWID);
    fwid_base!(TEST_LMS_32, "test_lms_32", BASE_FWID);
    fwid_base!(TEST_NEGATIVE_LMS, "test_negative_lms", BASE_FWID);
    fwid_base!(TEST_UART, "test_uart", BASE_FWID);
    fwid_base!(CSRNG, "csrng", BASE_FWID);
    fwid_base!(CSRNG2, "csrng2", BASE_FWID);
    fwid_base!(
        CSRNG_PASS_HEALTH_TESTS,
        "csrng_pass_health_tests",
        BASE_FWID
    );
    fwid_base!(
        CSRNG_FAIL_REPCNT_TESTS,
        "csrng_fail_repcnt_tests",
        BASE_FWID
    );
    fwid_base!(
        CSRNG_FAIL_ADAPTP_TESTS,
        "csrng_fail_adaptp_tests",
        BASE_FWID
    );
    fwid_base!(TRNG_DRIVER_RESPONDER, "trng_driver_responder", BASE_FWID);
    fwid_base!(PERSISTENT, "persistent", BASE_FWID);
}

pub mod rom_tests {
    use super::*;

    const BASE_FWID: FwId = FwId {
        crate_name: "caliptra-rom",
        bin_name: "",
        features: &["emu"],
    };

    fwid_base!(ASM_TESTS, "asm_tests", BASE_FWID);
    fwid!(
        TEST_FMC_WITH_UART,
        "caliptra-rom-test-fmc",
        "caliptra-rom-test-fmc",
        &["emu"]
    );
    fwid!(
        TEST_RT_WITH_UART,
        "caliptra-rom-test-rt",
        "caliptra-rom-test-rt",
        &["emu"]
    );
    fwid!(
        FAKE_TEST_FMC_WITH_UART,
        "caliptra-rom-test-fmc",
        "caliptra-rom-test-fmc",
        &["emu", "fake-fmc"]
    );
    fwid!(
        TEST_FMC_INTERACTIVE,
        "caliptra-rom-test-fmc",
        "caliptra-rom-test-fmc",
        &["emu", "interactive_test_fmc"]
    );
    fwid!(
        FAKE_TEST_FMC_INTERACTIVE,
        "caliptra-rom-test-fmc",
        "caliptra-rom-test-fmc",
        &["emu", "interactive_test_fmc", "fake-fmc"]
    );
}

pub mod runtime_tests {
    use super::*;

    const RUNTIME_TEST_FWID_BASE: FwId = FwId {
        crate_name: "caliptra-runtime-test-bin",
        bin_name: "",
        features: &["emu", "riscv", "runtime"],
    };

    fwid_base!(BOOT, "boot", RUNTIME_TEST_FWID_BASE);
    fwid_base!(MBOX, "mbox", RUNTIME_TEST_FWID_BASE);
    fwid_base!(PERSISTENT_RT, "persistent_rt", RUNTIME_TEST_FWID_BASE);
    fwid_base!(
        MOCK_RT_INTERACTIVE,
        "mock_rt_interact",
        RUNTIME_TEST_FWID_BASE
    );
}

pub const REGISTERED_FW: &[&FwId] = &[
    &ROM,
    &ROM_WITH_UART,
    &ROM_FAKE_WITH_UART,
    &ROM_WITH_FIPS_TEST_HOOKS,
    &FMC_WITH_UART,
    &FMC_FAKE_WITH_UART,
    &APP,
    &APP_WITH_UART,
    &APP_WITH_UART_FIPS_TEST_HOOKS,
    &APP_WITH_UART_FPGA,
    &APP_ZEROS,
    &FMC_ZEROS,
    &caliptra_builder_tests::FWID,
    &hw_model_tests::MAILBOX_RESPONDER,
    &hw_model_tests::MAILBOX_SENDER,
    &hw_model_tests::TEST_ICCM_BYTE_WRITE,
    &hw_model_tests::TEST_ICCM_UNALIGNED_WRITE,
    &hw_model_tests::TEST_ICCM_WRITE_LOCKED,
    &hw_model_tests::TEST_INVALID_INSTRUCTION,
    &hw_model_tests::TEST_WRITE_TO_ROM,
    &hw_model_tests::TEST_ICCM_DOUBLE_BIT_ECC,
    &hw_model_tests::TEST_DCCM_DOUBLE_BIT_ECC,
    &hw_model_tests::TEST_UNITIALIZED_READ,
    &hw_model_tests::TEST_PCR_EXTEND,
    &driver_tests::DOE,
    &driver_tests::ECC384,
    &driver_tests::ECC384_SIGN_VALIDATION_FAILURE,
    &driver_tests::ERROR_REPORTER,
    &driver_tests::HMAC384,
    &driver_tests::KEYVAULT,
    &driver_tests::KEYVAULT_FPGA,
    &driver_tests::MAILBOX_DRIVER_RESPONDER,
    &driver_tests::MAILBOX_DRIVER_SENDER,
    &driver_tests::MAILBOX_DRIVER_NEGATIVE_TESTS,
    &driver_tests::MBOX_SEND_TXN_DROP,
    &driver_tests::PCRBANK,
    &driver_tests::SHA1,
    &driver_tests::SHA256,
    &driver_tests::SHA384,
    &driver_tests::SHA2_512_384ACC,
    &driver_tests::STATUS_REPORTER,
    &driver_tests::TEST_LMS_24,
    &driver_tests::TEST_LMS_32,
    &driver_tests::TEST_NEGATIVE_LMS,
    &driver_tests::TEST_UART,
    &driver_tests::CSRNG,
    &driver_tests::CSRNG2,
    &driver_tests::CSRNG_PASS_HEALTH_TESTS,
    &driver_tests::CSRNG_FAIL_REPCNT_TESTS,
    &driver_tests::CSRNG_FAIL_ADAPTP_TESTS,
    &driver_tests::TRNG_DRIVER_RESPONDER,
    &driver_tests::PERSISTENT,
    &rom_tests::ASM_TESTS,
    &rom_tests::TEST_FMC_WITH_UART,
    &rom_tests::FAKE_TEST_FMC_WITH_UART,
    &rom_tests::TEST_FMC_INTERACTIVE,
    &rom_tests::FAKE_TEST_FMC_INTERACTIVE,
    &rom_tests::TEST_RT_WITH_UART,
    &runtime_tests::BOOT,
    &runtime_tests::MBOX,
    &runtime_tests::PERSISTENT_RT,
    &runtime_tests::MOCK_RT_INTERACTIVE,
];
