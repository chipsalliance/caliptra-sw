// Licensed under the Apache-2.0 license

use caliptra_error::CaliptraResult;
use caliptra_registers::soc_ifc::SocIfcReg;

pub struct FipsTestHook;

impl FipsTestHook {
    pub const RSVD: u8 = 0x0;
    // Set by Caliptra
    pub const COMPLETE: u8 = 0x1;
    // Set by external test
    pub const CONTINUE: u8 = 0x10;
    pub const HALT_SELF_TESTS: u8 = 0x21;
    pub const SHA1_CORRUPT_DIGEST: u8 = 0x22;
    pub const SHA256_CORRUPT_DIGEST: u8 = 0x23;
    pub const SHA384_CORRUPT_DIGEST: u8 = 0x24;
    pub const SHA2_512_384_ACC_CORRUPT_DIGEST_512: u8 = 0x25;
    pub const ECC384_CORRUPT_SIGNATURE: u8 = 0x26;
    pub const HMAC384_CORRUPT_TAG: u8 = 0x27;
    pub const LMS_CORRUPT_INPUT: u8 = 0x28;
    pub const ECC384_PAIRWISE_CONSISTENCY_ERROR: u8 = 0x29;
    pub const HALT_FW_LOAD: u8 = 0x2A;
    pub const HALT_SHUTDOWN_RT: u8 = 0x2B;

    pub const SHA1_DIGEST_FAILURE: u8 = 0x40;
    pub const SHA256_DIGEST_FAILURE: u8 = 0x41;
    pub const SHA384_DIGEST_FAILURE: u8 = 0x42;
    pub const SHA2_512_384_ACC_DIGEST_512_FAILURE: u8 = 0x43;
    pub const SHA2_512_384_ACC_START_OP_FAILURE: u8 = 0x44;
    pub const ECC384_SIGNATURE_GENERATE_FAILURE: u8 = 0x45;
    pub const ECC384_VERIFY_FAILURE: u8 = 0x46;
    pub const HMAC384_FAILURE: u8 = 0x47;
    pub const LMS_VERIFY_FAILURE: u8 = 0x48;

    // FW Load Errors
    pub const FW_LOAD_VENDOR_PUB_KEY_DIGEST_FAILURE: u8 = 0x50;
    pub const FW_LOAD_OWNER_PUB_KEY_DIGEST_FAILURE: u8 = 0x51;
    pub const FW_LOAD_HEADER_DIGEST_FAILURE: u8 = 0x52;
    pub const FW_LOAD_VENDOR_ECC_VERIFY_FAILURE: u8 = 0x53;
    pub const FW_LOAD_OWNER_ECC_VERIFY_FAILURE: u8 = 0x54;
    pub const FW_LOAD_OWNER_TOC_DIGEST_FAILURE: u8 = 0x55;
    pub const FW_LOAD_FMC_DIGEST_FAILURE: u8 = 0x56;
    pub const FW_LOAD_RUNTIME_DIGEST_FAILURE: u8 = 0x57;
    pub const FW_LOAD_VENDOR_LMS_VERIFY_FAILURE: u8 = 0x58;
    pub const FW_LOAD_OWNER_LMS_VERIFY_FAILURE: u8 = 0x59;

    /// # Safety
    ///
    /// This function interrupts normal flow and halts operation of the ROM or FW
    /// (Only when the hook_cmd matches the value from get_fips_test_hook_code)
    pub unsafe fn halt_if_hook_set(hook_cmd: u8) {
        if get_fips_test_hook_code() == hook_cmd {
            // Report that we've reached this point
            set_fips_test_hook_code(FipsTestHook::COMPLETE);

            // Wait for the CONTINUE command
            while get_fips_test_hook_code() != FipsTestHook::CONTINUE {}

            // Write COMPLETE
            set_fips_test_hook_code(FipsTestHook::COMPLETE);
        }
    }

    /// # Safety
    ///
    /// This function returns an intentionally corrupted version of the data provided
    /// (Only when the hook_cmd matches the value from get_fips_test_hook_code)
    pub unsafe fn corrupt_data_if_hook_set<T: core::marker::Copy>(hook_cmd: u8, data: &T) -> T {
        if get_fips_test_hook_code() == hook_cmd {
            let mut mut_data = *data;
            let ptr_t = &mut mut_data as *mut T;
            let mut_u8 = ptr_t as *mut u8;
            let byte_0 = unsafe { &mut *mut_u8 };

            // Corrupt (invert) the first byte
            *byte_0 = !*byte_0;

            return mut_data;
        }

        *data
    }

    /// # Safety
    ///
    /// This function enables a different test hook to allow for basic state machines
    /// (Only when the hook_cmd matches the value from get_fips_test_hook_code)
    pub unsafe fn update_hook_cmd_if_hook_set(hook_cmd: u8, new_hook_cmd: u8) {
        if get_fips_test_hook_code() == hook_cmd {
            set_fips_test_hook_code(new_hook_cmd);
        }
    }

    /// # Safety
    ///
    /// This function calls other unsafe functions to check the test hook code
    pub unsafe fn hook_cmd_is_set(hook_cmd: u8) -> bool {
        get_fips_test_hook_code() == hook_cmd
    }

    /// # Safety
    ///
    /// This function checks the current hook code and returns the
    /// FIPS_HOOKS_INJECTED_ERROR if enabled
    pub unsafe fn error_if_hook_set(hook_cmd: u8) -> CaliptraResult<()> {
        if get_fips_test_hook_code() == hook_cmd {
            Err(caliptra_error::CaliptraError::FIPS_HOOKS_INJECTED_ERROR)
        } else {
            Ok(())
        }
    }
}

/// # Safety
///
/// Temporarily creates a new instance of SocIfcReg instead of following the
/// normal convention of sharing one instance
unsafe fn get_fips_test_hook_code() -> u8 {
    // Bits 23:16 indicate the 8 bit code for the enabled FIPS test hook
    const CODE_MASK: u32 = 0x00FF0000;
    const CODE_OFFSET: u32 = 16;
    let soc_ifc = unsafe { SocIfcReg::new() };
    let soc_ifc_regs = soc_ifc.regs();
    let val = soc_ifc_regs.cptra_dbg_manuf_service_reg().read();
    ((val & CODE_MASK) >> CODE_OFFSET) as u8
}

/// # Safety
///
/// Temporarily creates a new instance of SocIfcReg instead of following the
/// normal convention of sharing one instance
unsafe fn set_fips_test_hook_code(code: u8) {
    // Bits 23:16 indicate the 8 bit code for the enabled FIPS test hook
    const CODE_MASK: u32 = 0x00FF0000;
    const CODE_OFFSET: u32 = 16;
    let mut soc_ifc = unsafe { SocIfcReg::new() };
    let soc_ifc_regs = soc_ifc.regs_mut();
    let val = (soc_ifc_regs.cptra_dbg_manuf_service_reg().read() & !(CODE_MASK))
        | ((code as u32) << CODE_OFFSET);
    soc_ifc_regs.cptra_dbg_manuf_service_reg().write(|_| val);
}
