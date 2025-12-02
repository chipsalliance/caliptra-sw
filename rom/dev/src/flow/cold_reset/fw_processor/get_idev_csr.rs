/*++

Licensed under the Apache-2.0 license.

File Name:

    get_idev_csr.rs

Abstract:

    File contains GET_IDEV_ECC384_CSR and GET_IDEV_MLDSA87_CSR mailbox commands.

--*/

use caliptra_common::mailbox_api::{GetIdevCsrResp, MailboxReqHeader, Response, ResponseVarSize};
use caliptra_drivers::{CaliptraError, CaliptraResult, PersistentData};
use zerocopy::FromBytes;

pub struct GetIdevEcc384CsrCmd;
impl GetIdevEcc384CsrCmd {
    #[inline(always)]
    pub(crate) fn execute(
        cmd_bytes: &[u8],
        persistent_data: &mut PersistentData,
        resp: &mut [u8],
    ) -> CaliptraResult<usize> {
        MailboxReqHeader::ref_from_bytes(cmd_bytes)
            .map_err(|_| CaliptraError::FW_PROC_MAILBOX_INVALID_REQUEST_LENGTH)?;

        // Use the response buffer directly as GetIdevCsrResp.
        // The buffer is zeroized at the start of the loop
        let resp_buffer_size = core::mem::size_of::<GetIdevCsrResp>();
        let resp = resp
            .get_mut(..resp_buffer_size)
            .ok_or(CaliptraError::FW_PROC_MAILBOX_INVALID_REQUEST_LENGTH)?;
        let csr_resp = GetIdevCsrResp::mut_from_bytes(resp)
            .map_err(|_| CaliptraError::FW_PROC_MAILBOX_INVALID_REQUEST_LENGTH)?;

        let csr_persistent_mem = &persistent_data.idevid_csr_envelop.ecc_csr;

        if csr_persistent_mem.is_unprovisioned() {
            // CSR was never written to DCCM. This means the gen_idev_id_csr
            // manufacturing flag was not set before booting into ROM.
            return Err(CaliptraError::FW_PROC_MAILBOX_GET_IDEV_CSR_UNPROVISIONED_CSR);
        }

        let csr = csr_persistent_mem
            .get()
            .ok_or(CaliptraError::ROM_IDEVID_INVALID_CSR)?;

        csr_resp.data_size = csr_persistent_mem.get_csr_len();
        csr_resp.data[..csr_resp.data_size as usize].copy_from_slice(csr);

        csr_resp.populate_chksum();
        let resp_bytes = csr_resp.as_bytes_partial()?;
        Ok(resp_bytes.len())
    }
}

pub struct GetIdevMldsa87CsrCmd;
impl GetIdevMldsa87CsrCmd {
    #[inline(always)]
    pub(crate) fn execute(
        cmd_bytes: &[u8],
        persistent_data: &mut PersistentData,
        resp: &mut [u8],
    ) -> CaliptraResult<usize> {
        MailboxReqHeader::ref_from_bytes(cmd_bytes)
            .map_err(|_| CaliptraError::FW_PROC_MAILBOX_INVALID_REQUEST_LENGTH)?;

        // Use the response buffer directly as GetIdevCsrResp.
        // The buffer is zeroized at the start of the loop
        let resp_buffer_size = core::mem::size_of::<GetIdevCsrResp>();
        let resp = resp
            .get_mut(..resp_buffer_size)
            .ok_or(CaliptraError::FW_PROC_MAILBOX_INVALID_REQUEST_LENGTH)?;
        let csr_resp = GetIdevCsrResp::mut_from_bytes(resp)
            .map_err(|_| CaliptraError::FW_PROC_MAILBOX_INVALID_REQUEST_LENGTH)?;

        let csr_persistent_mem = &persistent_data.idevid_csr_envelop.mldsa_csr;

        if csr_persistent_mem.is_unprovisioned() {
            // CSR was never written to DCCM. This means the gen_idev_id_csr
            // manufacturing flag was not set before booting into ROM.
            return Err(CaliptraError::FW_PROC_MAILBOX_GET_IDEV_CSR_UNPROVISIONED_CSR);
        }

        let csr = csr_persistent_mem
            .get()
            .ok_or(CaliptraError::ROM_IDEVID_INVALID_CSR)?;

        csr_resp.data_size = csr_persistent_mem.get_csr_len();
        csr_resp.data[..csr_resp.data_size as usize].copy_from_slice(csr);

        csr_resp.populate_chksum();
        let resp_bytes = csr_resp.as_bytes_partial()?;
        Ok(resp_bytes.len())
    }
}
