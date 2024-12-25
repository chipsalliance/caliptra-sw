/*++

Licensed under the Apache-2.0 license.

File Name:

    state.rs

Abstract:

    File contains Device state related API

--*/

use caliptra_cfi_derive::Launder;
use caliptra_error::{CaliptraError, CaliptraResult};
use caliptra_registers::soc_ifc::enums::DeviceLifecycleE;
use caliptra_registers::soc_ifc::{self, SocIfcReg};

use crate::{memory_layout, FuseBank};

pub type Lifecycle = DeviceLifecycleE;

pub fn report_boot_status(val: u32) {
    let mut soc_ifc = unsafe { soc_ifc::SocIfcReg::new() };

    // Save the boot status in DCCM.
    unsafe {
        let ptr = memory_layout::BOOT_STATUS_ORG as *mut u32;
        *ptr = val;
    };

    // For testability, save the boot status in the boot status register only if debugging is enabled.
    if !soc_ifc.regs().cptra_security_state().read().debug_locked() {
        soc_ifc.regs_mut().cptra_boot_status().write(|_| val);
    }
}

pub fn reset_reason() -> ResetReason {
    let soc_ifc = unsafe { SocIfcReg::new() };

    let soc_ifc_regs = soc_ifc.regs();
    let bit0 = soc_ifc_regs.cptra_reset_reason().read().fw_upd_reset();
    let bit1 = soc_ifc_regs.cptra_reset_reason().read().warm_reset();

    match (bit0, bit1) {
        (true, true) => ResetReason::Unknown,
        (false, true) => ResetReason::WarmReset,
        (true, false) => ResetReason::UpdateReset,
        (false, false) => ResetReason::ColdReset,
    }
}

/// Device State
pub struct SocIfc {
    soc_ifc: SocIfcReg,
}

impl SocIfc {
    pub fn new(soc_ifc: SocIfcReg) -> Self {
        Self { soc_ifc }
    }
    /// Retrieve the device lifecycle state
    pub fn lifecycle(&self) -> Lifecycle {
        let soc_ifc_regs = self.soc_ifc.regs();
        soc_ifc_regs
            .cptra_security_state()
            .read()
            .device_lifecycle()
    }

    /// Check if device is locked for debug
    pub fn debug_locked(&self) -> bool {
        let soc_ifc_regs = self.soc_ifc.regs();
        soc_ifc_regs.cptra_security_state().read().debug_locked()
    }

    pub fn mbox_valid_pauser(&self) -> [u32; 5] {
        let soc_ifc_regs = self.soc_ifc.regs();
        soc_ifc_regs.cptra_mbox_valid_axi_user().read()
    }

    pub fn mbox_pauser_lock(&self) -> [bool; 5] {
        let soc_ifc_regs = self.soc_ifc.regs();
        let pauser_lock = soc_ifc_regs.cptra_mbox_axi_user_lock();
        [
            pauser_lock.at(0).read().lock(),
            pauser_lock.at(1).read().lock(),
            pauser_lock.at(2).read().lock(),
            pauser_lock.at(3).read().lock(),
            pauser_lock.at(4).read().lock(),
        ]
    }

    /// Locks or unlocks the ICCM.
    ///
    /// # Arguments
    /// * `lock` - Desired lock state of the ICCM
    ///
    pub fn set_iccm_lock(&mut self, lock: bool) {
        let soc_ifc_regs = self.soc_ifc.regs_mut();
        soc_ifc_regs.internal_iccm_lock().modify(|w| w.lock(lock));
    }

    /// Retrieve reset reason
    pub fn reset_reason(&mut self) -> ResetReason {
        reset_reason()
    }

    /// Set IDEVID CSR ready
    ///
    /// # Arguments
    ///
    /// * None
    pub fn flow_status_set_idevid_csr_ready(&mut self) {
        let soc_ifc = self.soc_ifc.regs_mut();
        soc_ifc
            .cptra_flow_status()
            .write(|w| w.idevid_csr_ready(true));
    }

    /// Set ready for Mailbox operations
    ///
    /// # Arguments
    ///
    /// * None
    pub fn flow_status_set_ready_for_mb_processing(&mut self) {
        let soc_ifc = self.soc_ifc.regs_mut();
        soc_ifc
            .cptra_flow_status()
            .write(|w| w.ready_for_mb_processing(true));
    }

    /// Get 'ready for firmware' status
    ///
    /// # Arguments
    ///
    /// * None
    pub fn flow_status_ready_for_mb_processing(&mut self) -> bool {
        let soc_ifc = self.soc_ifc.regs_mut();
        soc_ifc.cptra_flow_status().read().ready_for_mb_processing()
    }

    pub fn fuse_bank(&self) -> FuseBank {
        FuseBank {
            soc_ifc: &self.soc_ifc,
        }
    }

    /// Returns the flag indicating whether to generate Initial Device ID Certificate
    /// Signing Request (CSR)
    pub fn mfg_flag_gen_idev_id_csr(&mut self) -> bool {
        let soc_ifc_regs = self.soc_ifc.regs();
        // Lower 16 bits are for mfg flags
        let flags: MfgFlags = (soc_ifc_regs.cptra_dbg_manuf_service_reg().read() & 0xffff).into();
        flags.contains(MfgFlags::GENERATE_IDEVID_CSR)
    }

    /// Returns the flag indicating whether random number generation is unavailable.
    pub fn mfg_flag_rng_unavailable(&self) -> bool {
        let soc_ifc_regs = self.soc_ifc.regs();
        // Lower 16 bits are for mfg flags
        let flags: MfgFlags = (soc_ifc_regs.cptra_dbg_manuf_service_reg().read() & 0xffff).into();
        flags.contains(MfgFlags::RNG_SUPPORT_UNAVAILABLE)
    }

    /// Check if verification is turned on for fake-rom
    pub fn verify_in_fake_mode(&self) -> bool {
        // Bit 31 indicates to perform verification flow in fake ROM
        const FAKE_ROM_VERIFY_EN_BIT: u32 = 31;
        let soc_ifc_regs = self.soc_ifc.regs();
        let val = soc_ifc_regs.cptra_dbg_manuf_service_reg().read();
        ((val >> FAKE_ROM_VERIFY_EN_BIT) & 1) != 0
    }

    /// Check if production mode is enabled for fake-rom
    pub fn prod_en_in_fake_mode(&self) -> bool {
        // Bit 30 indicates production mode is allowed in fake ROM
        const FAKE_ROM_PROD_EN_BIT: u32 = 30;
        let soc_ifc_regs = self.soc_ifc.regs();
        let val = soc_ifc_regs.cptra_dbg_manuf_service_reg().read();
        ((val >> FAKE_ROM_PROD_EN_BIT) & 1) != 0
    }

    #[inline(always)]
    pub fn hw_config_internal_trng(&mut self) -> bool {
        self.soc_ifc.regs().cptra_hw_config().read().i_trng_en()
    }

    #[inline(always)]
    pub fn cptra_dbg_manuf_service_flags(&mut self) -> MfgFlags {
        (self.soc_ifc.regs().cptra_dbg_manuf_service_reg().read() & 0xffff).into()
    }

    /// Enable or disable WDT1
    ///
    /// # Arguments
    /// * `enable` - Enable or disable WDT1
    ///
    pub fn configure_wdt1(&mut self, enable: bool) {
        let soc_ifc_regs = self.soc_ifc.regs_mut();
        soc_ifc_regs
            .cptra_wdt_timer1_en()
            .write(|w| w.timer1_en(enable));
    }

    /// Stop WDT1.
    ///
    /// This is useful to call from a fatal-error-handling routine.
    ///
    ///  # Safety
    ///
    /// The caller must be certain that it is safe to stop the WDT1.
    ///
    /// This function is safe to call from a trap handler.
    pub unsafe fn stop_wdt1() {
        let mut soc_ifc = SocIfcReg::new();
        soc_ifc
            .regs_mut()
            .cptra_wdt_timer1_en()
            .write(|w| w.timer1_en(false));
    }

    pub fn get_cycle_count(&self, seconds: u32) -> CaliptraResult<u64> {
        const GIGA_UNIT: u32 = 1_000_000_000;
        let clock_period_picosecs = self.soc_ifc.regs().cptra_timer_config().read();
        if clock_period_picosecs == 0 {
            Err(CaliptraError::DRIVER_SOC_IFC_INVALID_TIMER_CONFIG)
        } else {
            // Dividing GIGA_UNIT by clock_period_picosecs gives frequency in KHz.
            // This is being done to avoid 64-bit division (at the loss of precision)
            Ok((seconds as u64) * ((GIGA_UNIT / clock_period_picosecs) as u64) * 1000)
        }
    }

    /// Sets WDT1 timeout
    ///
    /// # Arguments
    /// * `cycle_count` - Timeout period in cycles
    ///
    pub fn set_wdt1_timeout(&mut self, cycle_count: u64) {
        let soc_ifc_regs = self.soc_ifc.regs_mut();
        soc_ifc_regs
            .cptra_wdt_timer1_timeout_period()
            .at(0)
            .write(|_| cycle_count as u32);
        soc_ifc_regs
            .cptra_wdt_timer1_timeout_period()
            .at(1)
            .write(|_| (cycle_count >> 32) as u32);
    }

    /// Sets WDT2 timeout
    ///
    /// # Arguments
    /// * `cycle_count` - Timeout period in cycles
    ///
    pub fn set_wdt2_timeout(&mut self, cycle_count: u64) {
        let soc_ifc_regs = self.soc_ifc.regs_mut();
        soc_ifc_regs
            .cptra_wdt_timer2_timeout_period()
            .at(0)
            .write(|_| cycle_count as u32);
        soc_ifc_regs
            .cptra_wdt_timer2_timeout_period()
            .at(1)
            .write(|_| (cycle_count >> 32) as u32);
    }

    pub fn reset_wdt1(&mut self) {
        let soc_ifc_regs = self.soc_ifc.regs_mut();
        soc_ifc_regs
            .cptra_wdt_timer1_ctrl()
            .write(|w| w.timer1_restart(true));
    }

    pub fn wdt1_timeout_cycle_count(&self) -> u64 {
        let soc_ifc_regs = self.soc_ifc.regs();
        soc_ifc_regs.cptra_wdt_cfg().at(0).read() as u64
            | ((soc_ifc_regs.cptra_wdt_cfg().at(1).read() as u64) << 32)
    }

    pub fn internal_fw_update_reset_wait_cycles(&self) -> u32 {
        self.soc_ifc
            .regs()
            .internal_fw_update_reset_wait_cycles()
            .read()
            .into()
    }
    pub fn assert_fw_update_reset(&mut self) {
        self.soc_ifc
            .regs_mut()
            .internal_fw_update_reset()
            .write(|w| w.core_rst(true));
    }

    pub fn assert_ready_for_runtime(&mut self) {
        self.soc_ifc
            .regs_mut()
            .cptra_flow_status()
            .write(|w| w.ready_for_runtime(true));
    }

    pub fn set_rom_fw_rev_id(&mut self, rom_version: u16) {
        // ROM version is [15:0] of CPTRA_FW_REV_ID[0]
        const ROM_VERSION_MASK: u32 = 0xFFFF;
        let soc_ifc_regs = self.soc_ifc.regs_mut();
        let version = (soc_ifc_regs.cptra_fw_rev_id().at(0).read() & !(ROM_VERSION_MASK))
            | (rom_version as u32);
        soc_ifc_regs.cptra_fw_rev_id().at(0).write(|_| version);
    }

    pub fn set_fmc_fw_rev_id(&mut self, fmc_version: u16) {
        // FMC version is [31:16] of CPTRA_FW_REV_ID[0]
        const FMC_VERSION_MASK: u32 = 0xFFFF0000;
        const FMC_VERSION_OFFSET: u32 = 16;
        let soc_ifc_regs = self.soc_ifc.regs_mut();
        let version = (soc_ifc_regs.cptra_fw_rev_id().at(0).read() & !(FMC_VERSION_MASK))
            | ((fmc_version as u32) << FMC_VERSION_OFFSET);
        soc_ifc_regs.cptra_fw_rev_id().at(0).write(|_| version);
    }

    pub fn set_rt_fw_rev_id(&mut self, rt_version: u32) {
        let soc_ifc_regs = self.soc_ifc.regs_mut();
        soc_ifc_regs.cptra_fw_rev_id().at(1).write(|_| rt_version);
    }

    pub fn get_version(&self) -> [u32; 3] {
        [
            u32::from(self.soc_ifc.regs().cptra_hw_rev_id().read()),
            self.soc_ifc.regs().cptra_fw_rev_id().at(0).read(),
            self.soc_ifc.regs().cptra_fw_rev_id().at(1).read(),
        ]
    }

    pub fn set_fw_extended_error(&mut self, err: u32) {
        let soc_ifc_regs = self.soc_ifc.regs_mut();
        let ext_info = soc_ifc_regs.cptra_fw_extended_error_info();
        ext_info.at(0).write(|_| err);
    }

    pub fn enable_mbox_notif_interrupts(&mut self) {
        let soc_ifc_regs = self.soc_ifc.regs_mut();
        let intr_block = soc_ifc_regs.intr_block_rf();

        intr_block
            .notif_intr_en_r()
            .write(|w| w.notif_cmd_avail_en(true));
        intr_block.global_intr_en_r().write(|w| w.notif_en(true));
    }

    pub fn has_mbox_notif_status(&self) -> bool {
        let soc_ifc = self.soc_ifc.regs();
        soc_ifc
            .intr_block_rf()
            .notif_internal_intr_r()
            .read()
            .notif_cmd_avail_sts()
    }

    pub fn clear_mbox_notif_status(&mut self) {
        let soc_ifc = self.soc_ifc.regs_mut();
        soc_ifc
            .intr_block_rf()
            .notif_internal_intr_r()
            .write(|w| w.notif_cmd_avail_sts(true));
    }

    pub fn active_mode(&self) -> bool {
        self.soc_ifc
            .regs()
            .cptra_hw_config()
            .read()
            .active_mode_en()
    }

    pub fn recovery_interface_base_addr(&self) -> u64 {
        let low = self.soc_ifc.regs().ss_recovery_ifc_base_addr_l().read();
        let high = self.soc_ifc.regs().ss_recovery_ifc_base_addr_h().read();
        (high as u64) << 32 | low as u64
    }
}

bitflags::bitflags! {
    /// Manufacturing State
    pub struct MfgFlags : u32 {
        /// Generate Initial Device Id Certificate Signing Request
       const GENERATE_IDEVID_CSR = 0x01;
       /// RNG functionality unavailable
       const RNG_SUPPORT_UNAVAILABLE = 0x2;
    }
}

impl From<u32> for MfgFlags {
    /// Converts to this type from the input type.
    fn from(value: u32) -> Self {
        MfgFlags::from_bits_truncate(value)
    }
}

/// Reset Reason
#[derive(Debug, Eq, PartialEq, Copy, Clone, Launder)]
pub enum ResetReason {
    /// Cold Reset
    ColdReset,

    /// Warm Reset
    WarmReset,

    /// Update Reset
    UpdateReset,

    /// Unknown Reset
    Unknown,
}
