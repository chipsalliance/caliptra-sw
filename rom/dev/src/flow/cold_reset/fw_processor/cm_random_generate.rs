/*++

Licensed under the Apache-2.0 license.

File Name:

    cm_random_generate.rs

Abstract:

    File contains CM_RANDOM_GENERATE mailbox command.

--*/

use caliptra_api::mailbox::{CmRandomGenerateReq, CmRandomGenerateResp};
use caliptra_common::mailbox_api::ResponseVarSize;
use caliptra_drivers::CaliptraResult;
use caliptra_drivers::Trng;
use zerocopy::FromBytes;

pub struct CmRandomGenerateCmd;
impl CmRandomGenerateCmd {
    #[inline(always)]
    pub(crate) fn execute(
        cmd_bytes: &[u8],
        trng: &mut Trng,
        resp: &mut [u8],
    ) -> CaliptraResult<usize> {
        let request = CmRandomGenerateReq::ref_from_bytes(cmd_bytes)
            .map_err(|_| caliptra_drivers::CaliptraError::FW_PROC_MAILBOX_INVALID_REQUEST_LENGTH)?;

        let size = request.size as usize;

        // Use the response buffer directly as CmRandomGenerateResp.
        // The buffer is zeroized at the start of the loop
        let resp_buffer_size = core::mem::size_of::<CmRandomGenerateResp>();
        let resp = resp
            .get_mut(..resp_buffer_size)
            .ok_or(caliptra_drivers::CaliptraError::FW_PROC_MAILBOX_INVALID_REQUEST_LENGTH)?;
        let rand_resp = CmRandomGenerateResp::mut_from_bytes(resp)
            .map_err(|_| caliptra_drivers::CaliptraError::FW_PROC_MAILBOX_INVALID_REQUEST_LENGTH)?;

        if size > rand_resp.data.len() {
            // Return 0 to indicate failure
            return Ok(0);
        }

        for i in (0..size).step_by(48) {
            let rand: [u8; 48] = trng.generate()?.into();
            let len = rand.len().min(rand_resp.data.len() - i);
            // check to prevent panic even though this is impossible
            if i > rand_resp.data.len() {
                break;
            }
            rand_resp.data[i..i + len].copy_from_slice(&rand[..len]);
        }

        rand_resp.hdr.data_len = size as u32;
        let resp_bytes = rand_resp.as_bytes_partial()?;
        Ok(resp_bytes.len())
    }
}
