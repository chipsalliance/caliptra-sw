/*++

Licensed under the Apache-2.0 license.

File Name:

    firmware_verify.rs

Abstract:

    File contains FIRMWARE_VERIFY mailbox command.

--*/

use crate::mutrefbytes;
use crate::Drivers;
use caliptra_cfi_derive_git::cfi_impl_fn;
use caliptra_common::mailbox_api::populate_checksum;
use caliptra_common::mailbox_api::MailboxRespHeader;
use caliptra_common::mailbox_api::{FirmwareVerifyResp, FirmwareVerifyResult};
use caliptra_common::verifier::FirmwareImageVerificationEnv;
use caliptra_drivers::{AxiAddr, CaliptraError, CaliptraResult, PersistentData, ResetReason};
use caliptra_image_types::ImageManifest;
use caliptra_image_verify::ImageVerifier;
use caliptra_registers::mbox::enums::MboxStatusE;
use core::mem::size_of;
use zerocopy::{FromBytes, IntoBytes};

/// Source of the firmware image for verification
pub enum VerifySrc {
    /// Firmware image is in mailbox SRAM
    Mbox,
    /// Firmware image is in external memory (MCU SRAM)
    External {
        /// AXI address where the firmware image is located
        axi_address: AxiAddr,
        /// Size of the firmware image in bytes
        image_size: u32,
    },
}

pub struct FirmwareVerifyCmd;
impl FirmwareVerifyCmd {
    #[inline(never)]
    pub(crate) fn execute(drivers: &mut Drivers, src: VerifySrc) -> CaliptraResult<MboxStatusE> {
        let (image_size, image_source) = match src {
            VerifySrc::Mbox => {
                let raw_data = drivers.mbox.raw_mailbox_contents();
                Self::load_manifest_from_mbox(drivers.persistent_data.get_mut(), raw_data)?;
                (
                    drivers.mbox.dlen(),
                    caliptra_common::verifier::ImageSource::MboxMemory(raw_data),
                )
            }
            VerifySrc::External {
                axi_address,
                image_size,
            } => {
                Self::load_manifest_from_external(
                    drivers.persistent_data.get_mut(),
                    &mut drivers.dma,
                    axi_address,
                )?;
                (
                    image_size,
                    caliptra_common::verifier::ImageSource::Axi {
                        dma: &drivers.dma,
                        axi_start: axi_address,
                    },
                )
            }
        };

        let mut venv = FirmwareImageVerificationEnv {
            sha256: &mut drivers.sha256,
            sha2_512_384: &mut drivers.sha2_512_384,
            sha2_512_384_acc: &mut drivers.sha2_512_384_acc,
            soc_ifc: &mut drivers.soc_ifc,
            ecc384: &mut drivers.ecc384,
            mldsa87: &mut drivers.mldsa87,
            data_vault: &drivers.persistent_data.get().rom.data_vault,
            pcr_bank: &mut drivers.pcr_bank,
            image_source,
            persistent_data: drivers.persistent_data.get(),
        };
        let mut verifier = ImageVerifier::new(&mut venv);

        let manifest = drivers.persistent_data.get().rom.manifest2;
        let resp = &mut [0u8; core::mem::size_of::<FirmwareVerifyResp>()][..];
        let resp = mutrefbytes::<FirmwareVerifyResp>(resp)?;
        resp.hdr = MailboxRespHeader::default();
        match verifier.verify(&manifest, image_size, ResetReason::UpdateReset) {
            Ok(_) => {
                // Verification succeeded
                resp.verify_result = FirmwareVerifyResult::Success as u32;
            }
            Err(_) => {
                // Verification failed
                resp.verify_result = FirmwareVerifyResult::Failure as u32;
            }
        }

        populate_checksum(resp.as_mut_bytes());
        // Send the payload
        drivers.mbox.write_response(resp.as_bytes())?;
        // zero the original resp buffer so as not to leak sensitive data
        resp.as_mut_bytes().fill(0);
        drivers
            .persistent_data
            .get_mut()
            .rom
            .manifest2
            .as_mut_bytes()
            .fill(0);

        Ok(MboxStatusE::DataReady)
    }

    /// Load manifest from mailbox SRAM
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    fn load_manifest_from_mbox(
        persistent_data: &mut PersistentData,
        fw_payload: &[u8],
    ) -> CaliptraResult<()> {
        if fw_payload.len() < size_of::<ImageManifest>() {
            return Err(CaliptraError::IMAGE_VERIFIER_ERR_MANIFEST_SIZE_MISMATCH);
        }
        persistent_data
            .rom
            .manifest2
            .as_mut_bytes()
            .copy_from_slice(fw_payload[..size_of::<ImageManifest>()].as_ref());
        Ok(())
    }

    /// Load manifest from external memory (MCU SRAM) using DMA
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    fn load_manifest_from_external(
        persistent_data: &mut PersistentData,
        dma: &mut caliptra_drivers::Dma,
        axi_address: AxiAddr,
    ) -> CaliptraResult<()> {
        let manifest = &mut persistent_data.rom.manifest2;
        let manifest_buf = manifest.as_mut_bytes();

        // Read manifest from external memory using DMA directly into manifest buffer
        let (manifest_words, _) = <[u32]>::mut_from_prefix(manifest_buf).unwrap();
        dma.read_buffer(axi_address, manifest_words);

        Ok(())
    }
}
