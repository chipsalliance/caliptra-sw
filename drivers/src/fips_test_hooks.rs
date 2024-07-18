// Licensed under the Apache-2.0 license

use caliptra_registers::soc_ifc::SocIfcReg;

pub struct FipsTestHook;

impl FipsTestHook {
    pub const RSVD: u8 = 0x0;
    // Set by Caliptra
    pub const COMPLETE: u8 = 0x1;
    // Set by external test
    pub const CONTINUE: u8 = 0x10;
    pub const HALT_SELF_TESTS: u8 = 0x21;
    pub const SHA384_ERROR: u8 = 0x22;
    pub const LMS_ERROR: u8 = 0x23;

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
