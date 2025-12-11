/*++

Licensed under the Apache-2.0 license.

File Name:

    ri_download_firmware.rs

Abstract:

    File contains RI_DOWNLOAD_FIRMWARE mailbox command.

--*/

use caliptra_common::RomBootStatus::FwProcessorDownloadImageComplete;
use caliptra_drivers::{cprintln, report_boot_status, CaliptraResult, Dma, SocIfc};

use super::FirmwareProcessor;

pub struct RiDownloadFirmwareCmd;
impl RiDownloadFirmwareCmd {
    #[inline(always)]
    pub(crate) fn execute(dma: &mut Dma, soc_ifc: &mut SocIfc) -> CaliptraResult<u32> {
        // Download the firmware image from the recovery interface.
        cprintln!("[fwproc] Downloading image from RRI to MCU SRAM");
        let image_size_bytes =
            FirmwareProcessor::retrieve_image_from_recovery_interface_to_mcu(dma, soc_ifc)?;
        cprintln!(
            "[fwproc] Received image from the Recovery Interface of size {} bytes",
            image_size_bytes
        );
        report_boot_status(FwProcessorDownloadImageComplete.into());
        Ok(image_size_bytes)
    }
}
