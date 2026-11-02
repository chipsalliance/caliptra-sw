/*++

Licensed under the Apache-2.0 license.

File Name:

    otp_lock.rs

Abstract:

    File contains the fuse controller Direct Access Interface (DAI) lock that
    is applied when the active SoC auth manifest carries
    `AuthManifestFlags::DISABLE_OTP_ACCESS`.

    Clearing `DIRECT_ACCESS_REGWEN` (RW0C) makes the fuse controller drop
    every DAI CMD / ADDRESS / WDATA / *_READ_LOCK write until the next
    subsystem reset (`cptra_ss_rst_b_o`). Caliptra update resets and MCU
    hitless updates do not reset the fuse controller; subsystem warm resets
    do, so the lock is re-applied on every path that releases MCU Runtime
    firmware.

--*/

use crate::Drivers;
use caliptra_drivers::{CaliptraError, CaliptraResult, Dma, OtpDai, SocIfc};

pub struct OtpLock;

impl OtpLock {
    /// Locks the fuse controller DAI if the active SoC auth manifest asked
    /// for it. Must be called immediately before every point where MCU
    /// Runtime firmware can start executing.
    #[inline(never)]
    pub fn apply_if_required(drivers: &Drivers) -> CaliptraResult<()> {
        if !drivers.persistent_data.get().fw.otp_access_disabled.get() {
            return Ok(());
        }
        if !drivers.soc_ifc.subsystem_mode() {
            return Err(CaliptraError::RUNTIME_OTP_LOCK_FAILED);
        }
        if !OtpDai::new(&drivers.soc_ifc, &drivers.dma).lock() {
            return Err(CaliptraError::RUNTIME_OTP_LOCK_FAILED);
        }
        Ok(())
    }

    /// Returns true if the DAI is locked until the next subsystem reset.
    pub fn is_locked(soc_ifc: &SocIfc, dma: &Dma) -> bool {
        soc_ifc.subsystem_mode() && OtpDai::new(soc_ifc, dma).is_locked()
    }
}
