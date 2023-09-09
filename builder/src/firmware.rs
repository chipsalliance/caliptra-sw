// Licensed under the Apache-2.0 license

// Centralized list of all firmware targets. This allows us to compile them all
// ahead of time for executing tests on hosts that can't compile rust code.

use crate::FwId;

pub const ROM: FwId = FwId {
    crate_name: "caliptra-rom",
    bin_name: "caliptra-rom",
    features: &[],
    workspace_dir: None,
};

pub const ROM_WITH_UART: FwId = FwId {
    crate_name: "caliptra-rom",
    bin_name: "caliptra-rom",
    features: &["emu"],
    workspace_dir: None,
};

pub const ROM_FAKE_WITH_UART: FwId = FwId {
    crate_name: "caliptra-rom",
    bin_name: "caliptra-rom",
    features: &["emu", "fake-rom"],
    workspace_dir: None,
};

pub const FMC_WITH_UART: FwId = FwId {
    crate_name: "caliptra-fmc",
    bin_name: "caliptra-fmc",
    features: &["emu"],
    workspace_dir: None,
};

pub const FMC_FAKE_WITH_UART: FwId = FwId {
    crate_name: "caliptra-fmc",
    bin_name: "caliptra-fmc",
    features: &["emu", "fake-fmc"],
    workspace_dir: None,
};

pub const APP_WITH_UART: FwId = FwId {
    crate_name: "caliptra-runtime",
    bin_name: "caliptra-runtime",
    features: &["emu", "test_only_commands", "fips_self_test"],
    workspace_dir: None,
};

pub mod caliptra_builder_tests {
    use super::*;

    pub const FWID: FwId = FwId {
        crate_name: "caliptra-drivers-test-bin",
        bin_name: "test_success",
        features: &[],
        workspace_dir: None,
    };
}

pub mod hw_model_tests {
    use super::*;

    const BASE_FWID: FwId = FwId {
        crate_name: "caliptra-hw-model-test-fw",
        bin_name: "",
        features: &["emu"],
        workspace_dir: None,
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
        workspace_dir: None,
    };

    pub const DOE: FwId = FwId {
        bin_name: "doe",
        ..BASE_FWID
    };

    pub const ECC384: FwId = FwId {
        bin_name: "ecc384",
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

    pub const KEYVAULT: FwId = FwId {
        bin_name: "keyvault",
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

    pub const TEST_LMS_32: FwId = FwId {
        bin_name: "test_lms_32",
        ..BASE_FWID
    };

    pub const TEST_NEGATIVE_LMS: FwId = FwId {
        bin_name: "test_negative_lms",
        ..BASE_FWID
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
        workspace_dir: None,
    };

    pub const ASM_TESTS: FwId = FwId {
        bin_name: "asm_tests",
        ..BASE_FWID
    };

    pub const TEST_FMC_WITH_UART: FwId = FwId {
        crate_name: "caliptra-rom-test-fmc",
        bin_name: "caliptra-rom-test-fmc",
        features: &["emu"],
        workspace_dir: None,
    };

    pub const FAKE_TEST_FMC_WITH_UART: FwId = FwId {
        crate_name: "caliptra-rom-test-fmc",
        bin_name: "caliptra-rom-test-fmc",
        features: &["emu", "fake-fmc"],
        workspace_dir: None,
    };

    pub const TEST_FMC_INTERACTIVE: FwId = FwId {
        crate_name: "caliptra-rom-test-fmc",
        bin_name: "caliptra-rom-test-fmc",
        features: &["emu", "interactive_test_fmc"],
        workspace_dir: None,
    };
}

pub mod fmc_tests {
    use super::*;

    pub const MOCK_RT_WITH_UART: FwId = FwId {
        crate_name: "caliptra-fmc-mock-rt",
        bin_name: "caliptra-fmc-mock-rt",
        features: &["emu"],
        workspace_dir: None,
    };
    pub const MOCK_RT_INTERACTIVE: FwId = FwId {
        crate_name: "caliptra-fmc-mock-rt",
        bin_name: "caliptra-fmc-mock-rt",
        features: &["emu", "interactive_test"],
        workspace_dir: None,
    };
}

pub mod runtime_tests {
    use super::*;

    const RUNTIME_TEST_FWID_BASE: FwId = FwId {
        crate_name: "caliptra-runtime-test-bin",
        bin_name: "",
        features: &["emu", "riscv", "runtime"],
        workspace_dir: None,
    };

    pub const BOOT: FwId = FwId {
        bin_name: "boot",
        ..RUNTIME_TEST_FWID_BASE
    };

    pub const KEYVAULT: FwId = FwId {
        bin_name: "keyvault",
        ..RUNTIME_TEST_FWID_BASE
    };

    pub const LOCKED_DV: FwId = FwId {
        bin_name: "locked_dv",
        ..RUNTIME_TEST_FWID_BASE
    };

    pub const CERT: FwId = FwId {
        bin_name: "cert",
        ..RUNTIME_TEST_FWID_BASE
    };

    pub const WDT: FwId = FwId {
        bin_name: "wdt",
        ..RUNTIME_TEST_FWID_BASE
    };
}

pub const REGISTERED_FW: &[&FwId] = &[
    &ROM,
    &ROM_WITH_UART,
    &ROM_FAKE_WITH_UART,
    &FMC_WITH_UART,
    &FMC_FAKE_WITH_UART,
    &APP_WITH_UART,
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
    &hw_model_tests::TEST_PCR_EXTEND,
    &driver_tests::DOE,
    &driver_tests::ECC384,
    &driver_tests::ERROR_REPORTER,
    &driver_tests::HMAC384,
    &driver_tests::KEYVAULT,
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
    &fmc_tests::MOCK_RT_WITH_UART,
    &fmc_tests::MOCK_RT_INTERACTIVE,
    &runtime_tests::BOOT,
    &runtime_tests::KEYVAULT,
    &runtime_tests::LOCKED_DV,
    &runtime_tests::CERT,
    &runtime_tests::WDT,
];
