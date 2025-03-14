/*++

Licensed under the Apache-2.0 license.

File Name:

    recovery_flow.rs

Abstract:

    File contains the implementation of the recovery flow for MCU firmware and SoC manifest.

--*/

use crate::{Drivers, SetAuthManifestCmd, set_auth_manifest::AuthManifestSource};
use caliptra_cfi_derive_git::cfi_impl_fn;
use caliptra_drivers::DmaRecovery;
use caliptra_kat::{CaliptraError, CaliptraResult};

pub enum RecoveryFlow {}

impl RecoveryFlow {
    /// Load the SoC Manifest and MCU firwmare
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    pub(crate) fn recovery_flow(drivers: &mut Drivers) -> CaliptraResult<()> {
        const SOC_MANIFEST_INDEX: u32 = 1;
        const MCU_FIRMWARE_INDEX: u32 = 2;

        // we need to hold the mailbox lock since we are downloading to it
        if drivers.mbox.lock() {
            return Err(CaliptraError::DRIVER_MAILBOX_INVALID_STATE);
        }
        // use different scopes since we need to borrow drivers mutably and immutably
        let result = {
            let dma = &drivers.dma;
            let dma_recovery = DmaRecovery::new(
                drivers.soc_ifc.recovery_interface_base_addr().into(),
                drivers.soc_ifc.mci_base_addr().into(),
                dma,
            );

            // download SoC manifest
            dma_recovery.download_image_to_mbox(SOC_MANIFEST_INDEX, false)
        };
        drivers.mbox.unlock();
        result?;

        SetAuthManifestCmd::set_auth_manifest(drivers, AuthManifestSource::Mailbox)?;

        {
            let dma = &drivers.dma;
            let dma_recovery = DmaRecovery::new(
                drivers.soc_ifc.recovery_interface_base_addr().into(),
                drivers.soc_ifc.mci_base_addr().into(),
                dma,
            );
            let _mcu_size_bytes = dma_recovery.download_image_to_mcu(MCU_FIRMWARE_INDEX, false)?;
            // [TODO][CAP2]: instruct Caliptra HW to read MCU SRAM and generate the hash (using HW SHA accelerator and AXI mastering capabilities to do this)
            // [TODO][CAP2]: use this hash and verify it against the hash in the SOC manifest
            // [TODO][CAP2]: after verifying/authorizing the image and if it passes, it will set EXEC/GO bit into the register as specified in the previous command. This register write will also assert a Caliptra interface wire

            // notify MCU that it can boot
            // TODO: get the correct value for this
            dma_recovery.set_mci_flow_status(123)?;

            // we're done with recovery
            dma_recovery.set_recovery_status(DmaRecovery::RECOVERY_STATUS_SUCCESSFUL, 0)?;
        }

        Ok(())
    }
}
