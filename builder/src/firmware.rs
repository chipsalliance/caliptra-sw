// Licensed under the Apache-2.0 license

// Centralized list of all firmware targets. This allows us to compile them all
// ahead of time for executing tests on hosts that can't compile rust code.

use crate::FwId;

pub fn rom_from_env() -> &'static FwId<'static> {
    match std::env::var("CPTRA_ROM_TYPE").as_ref().map(|s| s.as_str()) {
        Ok("ROM") => &ROM,
        Ok("ROM_WITHOUT_UART") => &ROM,
        Ok("ROM_WITH_UART") => &ROM_WITH_UART,
        Ok(s) => panic!("unexpected CPRTA_TEST_ROM env-var value: {s:?}"),
        Err(_) => &ROM_WITH_UART,
    }
}

pub const ROM: FwId = FwId {
    crate_name: "caliptra-rom",
    bin_name: "caliptra-rom",
    features: &[],
};

pub const ROM_WITH_UART: FwId = FwId {
    crate_name: "caliptra-rom",
    bin_name: "caliptra-rom",
    features: &["emu"],
};

pub const ROM_FAKE_WITH_UART: FwId = FwId {
    crate_name: "caliptra-rom",
    bin_name: "caliptra-rom",
    features: &["emu", "fake-rom"],
};

pub const FMC_WITH_UART: FwId = FwId {
    crate_name: "caliptra-fmc",
    bin_name: "caliptra-fmc",
    features: &["emu"],
};

pub const FMC_FAKE_WITH_UART: FwId = FwId {
    crate_name: "caliptra-fmc",
    bin_name: "caliptra-fmc",
    features: &["emu", "fake-fmc"],
};

pub const APP: FwId = FwId {
    crate_name: "caliptra-runtime",
    bin_name: "caliptra-runtime",
    features: &["fips_self_test"],
};

pub const APP_WITH_UART: FwId = FwId {
    crate_name: "caliptra-runtime",
    bin_name: "caliptra-runtime",
    features: &["emu", "test_only_commands", "fips_self_test"],
};

pub const APP_WITH_UART_FPGA: FwId = FwId {
    crate_name: "caliptra-runtime",
    bin_name: "caliptra-runtime",
    features: &[
        "emu",
        "test_only_commands",
        "fips_self_test",
        "fpga_realtime",
    ],
};

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

    pub const MAILBOX_RESPONDER: FwId = FwId {
        bin_name: "mailbox_responder",
        ..BASE_FWID
    };

    pub const MAILBOX_SENDER: FwId = FwId {
        bin_name: "mailbox_sender",
        ..BASE_FWID
    };

    pub const TEST_ICCM_BYTE_WRITE: FwId = FwId {
        bin_name: "test_iccm_byte_write",
        ..BASE_FWID
    };

    pub const TEST_ICCM_UNALIGNED_WRITE: FwId = FwId {
        bin_name: "test_iccm_unaligned_write",
        ..BASE_FWID
    };

    pub const TEST_ICCM_WRITE_LOCKED: FwId = FwId {
        bin_name: "test_iccm_write_locked",
        ..BASE_FWID
    };

    pub const TEST_INVALID_INSTRUCTION: FwId = FwId {
        bin_name: "test_invalid_instruction",
        ..BASE_FWID
    };

    pub const TEST_WRITE_TO_ROM: FwId = FwId {
        bin_name: "test_write_to_rom",
        ..BASE_FWID
    };

    pub const TEST_ICCM_DOUBLE_BIT_ECC: FwId = FwId {
        bin_name: "test_iccm_double_bit_ecc",
        ..BASE_FWID
    };

    pub const TEST_DCCM_DOUBLE_BIT_ECC: FwId = FwId {
        bin_name: "test_dccm_double_bit_ecc",
        ..BASE_FWID
    };

    pub const TEST_UNITIALIZED_READ: FwId = FwId {
        bin_name: "test_uninitialized_read",
        ..BASE_FWID
    };

    pub const TEST_PCR_EXTEND: FwId = FwId {
        bin_name: "test_pcr_extend",
        ..BASE_FWID
    };
}

pub mod driver_tests {
    use super::*;

    const BASE_FWID: FwId = FwId {
        crate_name: "caliptra-drivers-test-bin",
        bin_name: "",
        features: &["emu"],
    };

    const HW_LATEST_FWID: FwId = FwId {
        crate_name: "caliptra-drivers-test-bin",
        bin_name: "",
        features: &["emu", "hw-latest"],
    };

    pub const DOE: FwId = FwId {
        bin_name: "doe",
        ..BASE_FWID
    };

    pub const ECC384: FwId = FwId {
        bin_name: "ecc384",
        ..BASE_FWID
    };

    pub const ECC384_SIGN_VALIDATION_FAILURE: FwId = FwId {
        bin_name: "ecc384_sign_validation_failure",
        ..BASE_FWID
    };

    pub const ERROR_REPORTER: FwId = FwId {
        bin_name: "error_reporter",
        ..BASE_FWID
    };

    pub const HMAC384: FwId = FwId {
        bin_name: "hmac384",
        ..BASE_FWID
    };

    pub const HMAC384_HW_LATEST: FwId = FwId {
        bin_name: "hmac384_hw_latest",
        ..HW_LATEST_FWID
    };

    pub const KEYVAULT: FwId = FwId {
        bin_name: "keyvault",
        ..BASE_FWID
    };

    pub const KEYVAULT_FPGA: FwId = FwId {
        bin_name: "keyvault",
        features: &["fpga_realtime"],
        ..BASE_FWID
    };

    pub const MAILBOX_DRIVER_RESPONDER: FwId = FwId {
        bin_name: "mailbox_driver_responder",
        ..BASE_FWID
    };

    pub const MAILBOX_DRIVER_SENDER: FwId = FwId {
        bin_name: "mailbox_driver_sender",
        ..BASE_FWID
    };

    pub const MAILBOX_DRIVER_NEGATIVE_TESTS: FwId = FwId {
        bin_name: "mailbox_driver_negative_tests",
        ..BASE_FWID
    };

    pub const MBOX_SEND_TXN_DROP: FwId = FwId {
        bin_name: "mbox_send_txn_drop",
        ..BASE_FWID
    };

    pub const PCRBANK: FwId = FwId {
        bin_name: "pcrbank",
        ..BASE_FWID
    };

    pub const SHA1: FwId = FwId {
        bin_name: "sha1",
        ..BASE_FWID
    };

    pub const SHA256: FwId = FwId {
        bin_name: "sha256",
        ..BASE_FWID
    };

    pub const SHA384: FwId = FwId {
        bin_name: "sha384",
        ..BASE_FWID
    };

    pub const SHA384ACC: FwId = FwId {
        bin_name: "sha384acc",
        ..BASE_FWID
    };

    pub const STATUS_REPORTER: FwId = FwId {
        bin_name: "status_reporter",
        ..BASE_FWID
    };

    pub const TEST_LMS_24: FwId = FwId {
        bin_name: "test_lms_24",
        ..BASE_FWID
    };

    pub const TEST_LMS_24_HW_LATEST: FwId = FwId {
        bin_name: "test_lms_24_hw_latest",
        ..HW_LATEST_FWID
    };

    pub const TEST_LMS_32: FwId = FwId {
        bin_name: "test_lms_32",
        ..BASE_FWID
    };

    pub const TEST_LMS_32_HW_LATEST: FwId = FwId {
        bin_name: "test_lms_32_hw_latest",
        ..HW_LATEST_FWID
    };

    pub const TEST_NEGATIVE_LMS: FwId = FwId {
        bin_name: "test_negative_lms",
        ..BASE_FWID
    };

    pub const TEST_NEGATIVE_LMS_HW_LATEST: FwId = FwId {
        bin_name: "test_negative_lms_hw_latest",
        ..HW_LATEST_FWID
    };

    pub const TEST_UART: FwId = FwId {
        bin_name: "test_uart",
        ..BASE_FWID
    };

    pub const CSRNG: FwId = FwId {
        bin_name: "csrng",
        ..BASE_FWID
    };

    pub const CSRNG2: FwId = FwId {
        bin_name: "csrng2",
        ..BASE_FWID
    };

    pub const CSRNG_PASS_HEALTH_TESTS: FwId = FwId {
        bin_name: "csrng_pass_health_tests",
        ..BASE_FWID
    };

    pub const CSRNG_FAIL_REPCNT_TESTS: FwId = FwId {
        bin_name: "csrng_fail_repcnt_tests",
        ..BASE_FWID
    };

    pub const CSRNG_FAIL_ADAPTP_TESTS: FwId = FwId {
        bin_name: "csrng_fail_adaptp_tests",
        ..BASE_FWID
    };

    pub const TRNG_DRIVER_RESPONDER: FwId = FwId {
        bin_name: "trng_driver_responder",
        ..BASE_FWID
    };

    pub const PERSISTENT: FwId = FwId {
        bin_name: "persistent",
        ..BASE_FWID
    };
}

pub mod rom_tests {
    use super::*;

    const BASE_FWID: FwId = FwId {
        crate_name: "caliptra-rom",
        bin_name: "",
        features: &["emu"],
    };

    pub const ASM_TESTS: FwId = FwId {
        bin_name: "asm_tests",
        ..BASE_FWID
    };

    pub const TEST_FMC_WITH_UART: FwId = FwId {
        crate_name: "caliptra-rom-test-fmc",
        bin_name: "caliptra-rom-test-fmc",
        features: &["emu"],
    };

    pub const TEST_RT_WITH_UART: FwId = FwId {
        crate_name: "caliptra-rom-test-rt",
        bin_name: "caliptra-rom-test-rt",
        features: &["emu"],
    };

    pub const FAKE_TEST_FMC_WITH_UART: FwId = FwId {
        crate_name: "caliptra-rom-test-fmc",
        bin_name: "caliptra-rom-test-fmc",
        features: &["emu", "fake-fmc"],
    };

    pub const TEST_FMC_INTERACTIVE: FwId = FwId {
        crate_name: "caliptra-rom-test-fmc",
        bin_name: "caliptra-rom-test-fmc",
        features: &["emu", "interactive_test_fmc"],
    };

    pub const FAKE_TEST_FMC_INTERACTIVE: FwId = FwId {
        crate_name: "caliptra-rom-test-fmc",
        bin_name: "caliptra-rom-test-fmc",
        features: &["emu", "interactive_test_fmc", "fake-fmc"],
    };
}

pub mod runtime_tests {
    use super::*;

    const RUNTIME_TEST_FWID_BASE: FwId = FwId {
        crate_name: "caliptra-runtime-test-bin",
        bin_name: "",
        features: &["emu", "riscv", "runtime"],
    };

    pub const BOOT: FwId = FwId {
        bin_name: "boot",
        ..RUNTIME_TEST_FWID_BASE
    };

    pub const MBOX: FwId = FwId {
        bin_name: "mbox",
        ..RUNTIME_TEST_FWID_BASE
    };

    pub const PERSISTENT_RT: FwId = FwId {
        bin_name: "persistent_rt",
        ..RUNTIME_TEST_FWID_BASE
    };

    pub const MOCK_RT_INTERACTIVE: FwId = FwId {
        bin_name: "mock_rt_interact",
        ..RUNTIME_TEST_FWID_BASE
    };
}

pub const REGISTERED_FW: &[&FwId] = &[
    &ROM,
    &ROM_WITH_UART,
    &ROM_FAKE_WITH_UART,
    &FMC_WITH_UART,
    &FMC_FAKE_WITH_UART,
    &APP,
    &APP_WITH_UART,
    &APP_WITH_UART_FPGA,
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
    &driver_tests::HMAC384_HW_LATEST,
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
    &driver_tests::SHA384ACC,
    &driver_tests::STATUS_REPORTER,
    &driver_tests::TEST_LMS_24,
    &driver_tests::TEST_LMS_24_HW_LATEST,
    &driver_tests::TEST_LMS_32,
    &driver_tests::TEST_LMS_32_HW_LATEST,
    &driver_tests::TEST_NEGATIVE_LMS,
    &driver_tests::TEST_NEGATIVE_LMS_HW_LATEST,
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
