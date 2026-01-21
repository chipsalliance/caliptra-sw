/*++

Licensed under the Apache-2.0 license.

File Name:

    cm_sha.rs

Abstract:

    File contains CM_SHA mailbox command.

--*/

use caliptra_api::mailbox::{CmHashAlgorithm, CmShaReq, CmShaResp};
use caliptra_common::mailbox_api::ResponseVarSize;
use caliptra_drivers::{CaliptraError, CaliptraResult, Sha2_512_384};
use caliptra_image_types::{SHA384_DIGEST_BYTE_SIZE, SHA512_DIGEST_BYTE_SIZE};
use zerocopy::FromBytes;

pub struct CmShaCmd;
impl CmShaCmd {
    #[inline(always)]
    pub(crate) fn execute(
        cmd_bytes: &[u8],
        sha2_512_384: &mut Sha2_512_384,
        resp: &mut [u8],
    ) -> CaliptraResult<usize> {
        let req = CmShaReq::ref_from_prefix(cmd_bytes)
            .map_err(|_| CaliptraError::FW_PROC_MAILBOX_INVALID_REQUEST_LENGTH)?
            .0;

        // Use the response buffer directly as CmShaResp.
        let resp_buffer_size = core::mem::size_of::<CmShaResp>();
        let resp = resp
            .get_mut(..resp_buffer_size)
            .ok_or(CaliptraError::FW_PROC_MAILBOX_INVALID_REQUEST_LENGTH)?;
        let sha_resp = CmShaResp::mut_from_bytes(resp)
            .map_err(|_| CaliptraError::FW_PROC_MAILBOX_INVALID_REQUEST_LENGTH)?;

        let input_size = req.input_size as usize;
        if input_size > req.input.len() {
            return Err(CaliptraError::FW_PROC_MAILBOX_INVALID_REQUEST_LENGTH);
        }

        let input = &req.input[..input_size];
        let hash_algorithm = CmHashAlgorithm::from(req.hash_algorithm);

        match hash_algorithm {
            CmHashAlgorithm::Sha384 => {
                let digest = sha2_512_384.sha384_digest(input)?;
                let digest_bytes: [u8; SHA384_DIGEST_BYTE_SIZE] = digest.into();
                sha_resp.hash[..SHA384_DIGEST_BYTE_SIZE].copy_from_slice(&digest_bytes);
                sha_resp.hdr.data_len = SHA384_DIGEST_BYTE_SIZE as u32;
            }
            CmHashAlgorithm::Sha512 => {
                let digest = sha2_512_384.sha512_digest(input)?;
                let digest_bytes: [u8; SHA512_DIGEST_BYTE_SIZE] = digest.into();
                sha_resp.hash[..SHA512_DIGEST_BYTE_SIZE].copy_from_slice(&digest_bytes);
                sha_resp.hdr.data_len = SHA512_DIGEST_BYTE_SIZE as u32;
            }
            CmHashAlgorithm::Reserved => {
                return Err(CaliptraError::FW_PROC_MAILBOX_INVALID_PARAMS);
            }
        }

        let resp_bytes = sha_resp.as_bytes_partial()?;
        Ok(resp_bytes.len())
    }
}
