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
use caliptra_drivers::{CaliptraError, CaliptraResult, PersistentData, ResetReason};
use caliptra_image_types::ImageManifest;
use caliptra_image_verify::ImageVerifier;
use caliptra_registers::mbox::enums::MboxStatusE;
use zerocopy::IntoBytes;

pub struct FirmwareVerifyCmd;
impl FirmwareVerifyCmd {
    #[inline(never)]
    pub(crate) fn execute(drivers: &mut Drivers) -> CaliptraResult<MboxStatusE> {
        let raw_data = drivers.mbox.raw_mailbox_contents();

        Self::load_manifest(drivers.persistent_data.get_mut(), raw_data)?;
        let mut venv = FirmwareImageVerificationEnv {
            sha256: &mut drivers.sha256,
            sha2_512_384: &mut drivers.sha2_512_384,
            sha2_512_384_acc: &mut drivers.sha2_512_384_acc,
            soc_ifc: &mut drivers.soc_ifc,
            ecc384: &mut drivers.ecc384,
            mldsa87: &mut drivers.mldsa87,
            data_vault: &drivers.persistent_data.get().data_vault,
            pcr_bank: &mut drivers.pcr_bank,
            image: raw_data,
            dma: &drivers.dma,
            persistent_data: drivers.persistent_data.get(),
        };
        let mut verifier = ImageVerifier::new(&mut venv);

        let manifest = drivers.persistent_data.get().manifest2;
        let resp = &mut [0u8; core::mem::size_of::<FirmwareVerifyResp>()][..];
        let resp = mutrefbytes::<FirmwareVerifyResp>(resp)?;
        resp.hdr = MailboxRespHeader::default();
        match verifier.verify(&manifest, drivers.mbox.dlen(), ResetReason::UpdateReset) {
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

        Ok(MboxStatusE::DataReady)
    }

    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    fn load_manifest(
        persistent_data: &mut PersistentData,
        fw_payload: &[u8],
    ) -> CaliptraResult<()> {
        if fw_payload.len() < core::mem::size_of::<ImageManifest>() {
            return Err(CaliptraError::IMAGE_VERIFIER_ERR_MANIFEST_SIZE_MISMATCH);
        }
        persistent_data
            .manifest2
            .as_mut_bytes()
            .copy_from_slice(fw_payload[..core::mem::size_of::<ImageManifest>()].as_ref());
        Ok(())
    }
}
