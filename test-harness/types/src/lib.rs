// Licensed under the Apache-2.0 license

/// Errors codes placed into CPTRA_FW_ERROR_NON_FATAL
/// by the test harness.
pub const ERROR_EXCEPTION: u32 = 0x0300_0002;
pub const ERROR_NMI: u32 = 0x0300_0003;

// From RISC-V_VeeR_EL2_PRM.pdf
pub const NMI_CAUSE_PIN_ASSERTION: u32 = 0x0000_0000;
pub const NMI_CAUSE_DBUS_STORE_ERROR: u32 = 0xf000_0000;
pub const NMI_CAUSE_DBUS_NON_BLOCKING_LOAD_ERROR: u32 = 0xf000_0001;
pub const NMI_CAUSE_FAST_INTERRUPT_DOUBLE_BIT_ECC_ERROR: u32 = 0xf000_1000;
pub const NMI_CAUSE_FAST_INTERRUPT_DCCM_REGION_ACCESS_ERROR: u32 = 0xf000_1001;
pub const NMI_CAUSE_FAST_INTERRUPT_NON_DCCM_REGION: u32 = 0xf000_1002;

/// Error info collected by the test-harness's trap/NMI handlers and placed into
/// CPTRA_FW_EXTENDED_ERROR_INFO. See `test-harness/start.S` for more
/// information.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExtErrorInfo {
    pub sp: u32,
    pub mepc: u32,
    pub mcause: u32,
    pub mscause: u32,
    pub mstatus: u32,
    pub mtval: u32,
}
impl From<[u32; 8]> for ExtErrorInfo {
    fn from(value: [u32; 8]) -> Self {
        ExtErrorInfo {
            sp: value[0],
            mepc: value[1],
            mcause: value[2],
            mscause: value[3],
            mstatus: value[4],
            mtval: value[5],
        }
    }
}
