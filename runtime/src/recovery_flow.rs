/*++

Licensed under the Apache-2.0 license.

File Name:

    recovery_flow.rs

Abstract:

    File contains the implementation of the recovery flow for MCU firmware and SoC manifest.

--*/

use crate::Drivers;
use caliptra_auth_man_types::{
    AuthManifestImageMetadataCollection, AuthManifestPreamble, AuthorizationManifest,
    AUTH_MANIFEST_PREAMBLE_SIZE,
};
use caliptra_cfi_derive_git::{cfi_impl_fn, cfi_mod_fn};
use caliptra_drivers::{AxiAddr, Dma, DmaReadTarget, DmaReadTransaction, DmaRecovery};
use caliptra_kat::{CaliptraError, CaliptraResult};
use caliptra_registers::i3ccsr::RegisterBlock;
use core::{
    any::TypeId,
    cell::{Cell, RefCell},
};
use ureg::{Mmio, MmioMut, Uint, UintType};
use zerocopy::{FromBytes, IntoBytes};

pub enum RecoveryFlow {}

impl RecoveryFlow {
    /// Load the SoC Manifest and MCU firwmare
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    pub(crate) fn recovery_flow(drivers: &mut Drivers) -> CaliptraResult<()> {
        const SOC_MANIFEST_INDEX: u32 = 1;
        const MCU_FIRMWARE_INDEX: u32 = 2;

        let dma = &drivers.dma;
        let dma_recovery =
            DmaRecovery::new(drivers.soc_ifc.recovery_interface_base_addr().into(), dma);

        // // download SoC manifest
        let _soc_size_bytes = dma_recovery.download_image_to_mbox(SOC_MANIFEST_INDEX)?;
        let Ok((manifest, _)) = AuthorizationManifest::read_from_prefix(drivers.mbox.raw_mailbox_contents()) else {
            return Err(CaliptraError::IMAGE_VERIFIER_ERR_MANIFEST_SIZE_MISMATCH);
        };
        // [TODO][CAP2]: authenticate SoC manifest using keys available through Caliptra Image
        // TODO: switch to ref_from method when we upgrade zerocopy
        // [TODO][CAP2]: replace this copy with set_manifest
        drivers
            .persistent_data
            .get_mut()
            .auth_manifest_image_metadata_col = manifest.image_metadata_col;
        // [TODO][CAP2]: capture measurement of Soc manifest?
        // [TODO][CAP2]: this should be writing to MCU SRAM directly via AXI
        let _mcu_size_bytes = dma_recovery.download_image_to_mbox(MCU_FIRMWARE_INDEX)?;
        // [TODO][CAP2]: instruct Caliptra HW to read MCU SRAM and generate the hash (using HW SHA accelerator and AXI mastering capabilities to do this)
        // [TODO][CAP2]: use this hash and verify it against the hash in the SOC manifest
        // [TODO][CAP2]: after verifying/authorizing the image and if it passes, it will set EXEC/GO bit into the register as specified in the previous command. This register write will also assert a Caliptra interface wire
        // [TODO][CAP2]: set recovery flow is completed
        Ok(())
    }
}
