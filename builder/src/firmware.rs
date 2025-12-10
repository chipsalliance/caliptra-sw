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

pub fn rom_from_env_fpga(fpga: bool) -> &'static FwId<'static> {
    match (
        std::env::var("CPTRA_ROM_TYPE").as_ref().map(|s| s.as_str()),
        fpga,
    ) {
        (Ok("ROM"), _) => &ROM,
        (Ok("ROM_WITHOUT_UART"), true) => &ROM_FPGA,
        (Ok("ROM_WITHOUT_UART"), false) => &ROM,
        (Ok("ROM_WITH_UART"), true) => &ROM_FPGA_WITH_UART,
        (Ok("ROM_WITH_UART"), false) => &ROM_WITH_UART,
        (Ok(s), _) => panic!("unexpected CPRTA_TEST_ROM env-var value: {s:?}"),
        (Err(_), true) => &ROM_FPGA_WITH_UART,
        (Err(_), false) => &ROM_WITH_UART,
    }
}

pub fn fake_rom(fpga: bool) -> &'static FwId<'static> {
    if fpga {
        &ROM_FAKE_WITH_UART_FPGA
    } else {
        &ROM_FAKE_WITH_UART
    }
}

pub const ROM: FwId = FwId {
    crate_name: "caliptra-rom",
    bin_name: "caliptra-rom",
    features: &[],
};

pub const ROM_FPGA: FwId = FwId {
    crate_name: "caliptra-rom",
    bin_name: "caliptra-rom",
    features: &["fpga_realtime"],
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

pub const ROM_FAKE_WITH_UART_FPGA: FwId = FwId {
    crate_name: "caliptra-rom",
    bin_name: "caliptra-rom",
    features: &["emu", "fake-rom", "fpga_realtime"],
};

pub const ROM_WITH_FIPS_TEST_HOOKS: FwId = FwId {
    crate_name: "caliptra-rom",
    bin_name: "caliptra-rom",
    features: &["fips-test-hooks"],
};

pub const ROM_WITH_FIPS_TEST_HOOKS_FPGA: FwId = FwId {
    crate_name: "caliptra-rom",
    bin_name: "caliptra-rom",
    features: &["fips-test-hooks", "fpga_realtime"],
};

// TODO: delete this when AXI DMA is fixed in the FPGA
pub const ROM_FPGA_WITH_UART: FwId = FwId {
    crate_name: "caliptra-rom",
    bin_name: "caliptra-rom",
    features: &["emu", "fpga_realtime"],
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

// TODO: delete this when AXI DMA is fixed in the FPGA
pub const FMC_FPGA_WITH_UART: FwId = FwId {
    crate_name: "caliptra-fmc",
    bin_name: "caliptra-fmc",
    features: &["emu", "fpga_realtime"],
};

pub const APP: FwId = FwId {
    crate_name: "caliptra-runtime",
    bin_name: "caliptra-runtime",
    features: &["fips_self_test"],
};

pub const APP_WITH_UART: FwId = FwId {
    crate_name: "caliptra-runtime",
    bin_name: "caliptra-runtime",
    features: &["emu", "fips_self_test"],
};

pub const APP_WITH_UART_OCP_LOCK: FwId = FwId {
    crate_name: "caliptra-runtime",
    bin_name: "caliptra-runtime",
    features: &["emu", "fips_self_test", "ocp-lock"],
};

pub const APP_WITH_UART_FIPS_TEST_HOOKS: FwId = FwId {
    crate_name: "caliptra-runtime",
    bin_name: "caliptra-runtime",
    features: &["emu", "fips_self_test", "fips-test-hooks"],
};

pub const APP_WITH_UART_FPGA: FwId = FwId {
    crate_name: "caliptra-runtime",
    bin_name: "caliptra-runtime",
    features: &["emu", "fips_self_test", "fpga_realtime"],
};

pub const APP_WITH_UART_OCP_LOCK_FPGA: FwId = FwId {
    crate_name: "caliptra-runtime",
    bin_name: "caliptra-runtime",
    features: &["emu", "fips_self_test", "fpga_realtime", "ocp-lock"],
};

pub const APP_ZEROS: FwId = FwId {
    crate_name: "caliptra-zeros",
    bin_name: "caliptra-zeros",
    features: &[],
};

pub const FMC_ZEROS: FwId = FwId {
    crate_name: "caliptra-zeros",
    bin_name: "caliptra-zeros",
    features: &["fmc"],
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

    pub const MCU_HITLESS_UPDATE_FLOW: FwId = FwId {
        bin_name: "mcu_hitless_update_flow",
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

    pub const DOE: FwId = FwId {
        bin_name: "doe",
        ..BASE_FWID
    };

    pub const AES: FwId = FwId {
        bin_name: "aes",
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

    pub const HMAC: FwId = FwId {
        bin_name: "hmac",
        ..BASE_FWID
    };

    pub const KEYVAULT: FwId = FwId {
        bin_name: "keyvault",
        ..BASE_FWID
    };

    pub const KEYVAULT_FPGA: FwId = FwId {
        bin_name: "keyvault",
        features: &["emu", "fpga_realtime"],
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

    pub const ML_DSA87: FwId = FwId {
        bin_name: "ml_dsa87",
        ..BASE_FWID
    };

    pub const ML_DSA87_EXTERNAL_MU: FwId = FwId {
        bin_name: "ml_dsa87_external_mu",
        ..BASE_FWID
    };

    pub const ML_KEM: FwId = FwId {
        bin_name: "ml_kem",
        ..BASE_FWID
    };

    pub const PCRBANK: FwId = FwId {
        bin_name: "pcrbank",
        ..BASE_FWID
    };

    pub const PRECONDITIONED_KEYS: FwId = FwId {
        bin_name: "preconditioned_keys",
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

    pub const SHA3: FwId = FwId {
        bin_name: "sha3",
        ..BASE_FWID
    };

    pub const SHA512: FwId = FwId {
        bin_name: "sha512",
        ..BASE_FWID
    };

    pub const SHA2_512_384ACC: FwId = FwId {
        bin_name: "sha2_512_384acc",
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

    pub const DMA_SHA384: FwId = FwId {
        bin_name: "dma_sha384",
        ..BASE_FWID
    };

    // TODO: delete this when AXI DMA is fixed in the FPGA
    pub const DMA_SHA384_FPGA: FwId = FwId {
        bin_name: "dma_sha384",
        features: &["emu", "fpga_subsystem"],
        ..BASE_FWID
    };

    pub const OCP_LOCK: FwId = FwId {
        bin_name: "ocp_lock",
        features: &["fpga_realtime"],
        ..BASE_FWID
    };

    pub const OCP_LOCK_WARM_RESET: FwId = FwId {
        bin_name: "ocp_lock_warm_reset",
        features: &["fpga_realtime"],
        ..BASE_FWID
    };

    pub const DMA_AES: FwId = FwId {
        bin_name: "dma_aes",
        features: &["emu", "fpga_subsystem"],
        ..BASE_FWID
    };

    pub const AXI_BYPASS: FwId = FwId {
        bin_name: "axi_bypass",
        features: &["emu", "fpga_subsystem"],
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

    pub const TEST_PMP_TESTS: FwId = FwId {
        bin_name: "pmp_tests",
        ..BASE_FWID
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

    pub const MBOX_FPGA: FwId = FwId {
        bin_name: "mbox",
        features: &["emu", "riscv", "runtime", "fpga_realtime"],
        ..RUNTIME_TEST_FWID_BASE
    };

    // Used to test updates between RT FW images.
    pub const MBOX_WITHOUT_UART: FwId = FwId {
        bin_name: "mbox",
        features: &["riscv", "runtime"],
        ..RUNTIME_TEST_FWID_BASE
    };

    pub const MBOX_WITHOUT_UART_FPGA: FwId = FwId {
        bin_name: "mbox",
        features: &["riscv", "runtime", "fpga_realtime"],
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

    pub const MOCK_RT_INTERACTIVE_FPGA: FwId = FwId {
        bin_name: "mock_rt_interact",
        features: &["emu", "riscv", "runtime", "fpga_realtime"],
        ..RUNTIME_TEST_FWID_BASE
    };
}

pub const REGISTERED_FW: &[&FwId] = &[
    &ROM,
    &ROM_FPGA,
    &ROM_WITH_UART,
    &ROM_FAKE_WITH_UART,
    &ROM_FAKE_WITH_UART_FPGA,
    &ROM_WITH_FIPS_TEST_HOOKS,
    &ROM_WITH_FIPS_TEST_HOOKS_FPGA,
    &ROM_FPGA_WITH_UART,
    &FMC_WITH_UART,
    &FMC_FAKE_WITH_UART,
    &FMC_FPGA_WITH_UART,
    &APP,
    &APP_WITH_UART,
    &APP_WITH_UART_OCP_LOCK,
    &APP_WITH_UART_FIPS_TEST_HOOKS,
    &APP_WITH_UART_OCP_LOCK_FPGA,
    &APP_WITH_UART_FPGA,
    &APP_ZEROS,
    &FMC_ZEROS,
    &caliptra_builder_tests::FWID,
    &hw_model_tests::MAILBOX_RESPONDER,
    &hw_model_tests::MAILBOX_SENDER,
    &hw_model_tests::MCU_HITLESS_UPDATE_FLOW,
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
    &driver_tests::AES,
    &driver_tests::ECC384,
    &driver_tests::ECC384_SIGN_VALIDATION_FAILURE,
    &driver_tests::ERROR_REPORTER,
    &driver_tests::HMAC,
    &driver_tests::KEYVAULT,
    &driver_tests::KEYVAULT_FPGA,
    &driver_tests::MAILBOX_DRIVER_RESPONDER,
    &driver_tests::MAILBOX_DRIVER_SENDER,
    &driver_tests::MAILBOX_DRIVER_NEGATIVE_TESTS,
    &driver_tests::MBOX_SEND_TXN_DROP,
    &driver_tests::ML_DSA87,
    &driver_tests::ML_DSA87_EXTERNAL_MU,
    &driver_tests::ML_KEM,
    &driver_tests::PCRBANK,
    &driver_tests::PRECONDITIONED_KEYS,
    &driver_tests::SHA1,
    &driver_tests::SHA256,
    &driver_tests::SHA384,
    &driver_tests::SHA3,
    &driver_tests::SHA512,
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
    &driver_tests::DMA_SHA384,
    &driver_tests::DMA_SHA384_FPGA,
    &driver_tests::OCP_LOCK,
    &driver_tests::OCP_LOCK_WARM_RESET,
    &driver_tests::DMA_AES,
    &driver_tests::AXI_BYPASS,
    &rom_tests::ASM_TESTS,
    &rom_tests::TEST_FMC_WITH_UART,
    &rom_tests::FAKE_TEST_FMC_WITH_UART,
    &rom_tests::TEST_FMC_INTERACTIVE,
    &rom_tests::FAKE_TEST_FMC_INTERACTIVE,
    &rom_tests::TEST_RT_WITH_UART,
    &rom_tests::TEST_PMP_TESTS,
    &runtime_tests::BOOT,
    &runtime_tests::MBOX,
    &runtime_tests::MBOX_FPGA,
    &runtime_tests::MBOX_WITHOUT_UART,
    &runtime_tests::MBOX_WITHOUT_UART_FPGA,
    &runtime_tests::PERSISTENT_RT,
    &runtime_tests::MOCK_RT_INTERACTIVE,
    &runtime_tests::MOCK_RT_INTERACTIVE_FPGA,
];
