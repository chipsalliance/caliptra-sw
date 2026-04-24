/*++

Licensed under the Apache-2.0 license.

File Name:

    populate_idev.rs

Abstract:

    File contains CertifyKeyExtended mailbox command.

--*/

use crate::{
    invoke_dpe::invoke_dpe_cmd, mutrefbytes, CaliptraDpeProfile, Drivers, PauserPrivileges,
};
use arrayvec::ArrayVec;
use caliptra_api::mailbox::{
    populate_checksum, CertifyKeyExtendedMldsa87Req, SUBSYSTEM_MAILBOX_SIZE_LIMIT,
};
use caliptra_common::mailbox_api::{
    CertifyKeyExtendedEcc384Req, CertifyKeyExtendedFlags, CertifyKeyExtendedResp, MailboxRespHeader,
};
use caliptra_drivers::AxiAddr;
use caliptra_error::{CaliptraError, CaliptraResult};
use dpe::commands::{CertifyKeyMldsa87Cmd, CertifyKeyP384Cmd, Command};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

pub struct CertifyKeyExtendedCmd;
impl CertifyKeyExtendedCmd {
    #[inline(never)]
    pub(crate) fn execute_ecc384(
        drivers: &mut Drivers,
        cmd_args: &[u8],
        mbox_resp: &mut [u8],
    ) -> CaliptraResult<usize> {
        let cmd = CertifyKeyExtendedEcc384Req::ref_from_bytes(cmd_args)
            .map_err(|_| CaliptraError::RUNTIME_INSUFFICIENT_MEMORY)?;
        Self::execute(
            drivers,
            CaliptraDpeProfile::Ecc384,
            &cmd.flags,
            &cmd.certify_key_req,
            mbox_resp,
        )
    }

    #[inline(never)]
    pub(crate) fn execute_mldsa87(
        drivers: &mut Drivers,
        cmd_args: &[u8],
        mbox_resp: &mut [u8],
    ) -> CaliptraResult<usize> {
        let cmd = CertifyKeyExtendedMldsa87Req::ref_from_bytes(cmd_args)
            .map_err(|_| CaliptraError::RUNTIME_INSUFFICIENT_MEMORY)?;
        // External responses can only be done in subsystem mode
        if cmd.flags.external_axi_response() && !drivers.soc_ifc.subsystem_mode() {
            return Err(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS);
        }

        // Trim the response buffer to the correct size. If the response doesn't fit, it will fail
        // during DPE execution and not at the transport layer. This is especially important for DPE
        // handle rotation so the caller doesn't lose the handle.
        let mbox_resp = if drivers.soc_ifc.subsystem_mode() {
            let len = if cmd.flags.external_axi_response() {
                usize::min(mbox_resp.len(), cmd.axi_response.max_size as usize)
            } else {
                // The mailbox size is smaller when subsystem is enabled
                usize::min(mbox_resp.len(), SUBSYSTEM_MAILBOX_SIZE_LIMIT)
            };
            mbox_resp
                .get_mut(..len)
                .ok_or(CaliptraError::RUNTIME_INSUFFICIENT_MEMORY)?
        } else {
            mbox_resp
        };

        let len = Self::execute(
            drivers,
            CaliptraDpeProfile::Mldsa87,
            &cmd.flags,
            &cmd.certify_key_req,
            mbox_resp,
        )?;

        // We are done if the response is going over the mailbox
        let respond_to_mailbox = !cmd.flags.external_axi_response();
        if respond_to_mailbox {
            return Ok(len);
        }

        // Populate the checksum so the full response can be checked at the destination
        // Make sure there is at least enough space for the response header
        let len = usize::max(len, size_of::<MailboxRespHeader>());
        populate_checksum(
            mbox_resp
                .get_mut(..len)
                .ok_or(CaliptraError::RUNTIME_INSUFFICIENT_MEMORY)?,
        );

        // Get the number of words to send by rounding up to nearest word
        let num_words = len.next_multiple_of(4) / 4;
        let len = num_words * 4;
        if len > cmd.axi_response.max_size as usize {
            return Err(CaliptraError::RUNTIME_INSUFFICIENT_MEMORY);
        }

        // Get the buffer that will be sent over DMA. The DMA only supports sending words so we need
        // to convert the response buffer to a &[u32].
        let buffer = mbox_resp
            .get(..len)
            .ok_or(CaliptraError::RUNTIME_INSUFFICIENT_MEMORY)?;
        let buffer: &[u32] =
            FromBytes::ref_from_bytes(buffer).map_err(|_| CaliptraError::ADDRESS_MISALIGNED)?;

        // Send the response over DMA to the specified AXI address
        let axi_addr = AxiAddr {
            lo: cmd.axi_response.addr_lo,
            hi: cmd.axi_response.addr_hi,
        };
        for (i, word) in buffer.iter().enumerate() {
            drivers.dma.write_dword(
                AxiAddr {
                    lo: axi_addr.lo + (i as u32 * 4),
                    hi: axi_addr.hi,
                },
                *word,
            );
        }

        // Response is sent over DMA instead of the mailbox, so return 0 length
        Ok(0)
    }

    #[inline(never)]
    fn execute(
        drivers: &mut Drivers,
        profile: CaliptraDpeProfile,
        flags: &CertifyKeyExtendedFlags,
        certify_key_req: &[u8; CertifyKeyExtendedEcc384Req::CERTIFY_KEY_REQ_SIZE],
        mbox_resp: &mut [u8],
    ) -> CaliptraResult<usize> {
        match drivers.caller_privilege_level() {
            // CERTIFY_KEY_EXTENDED MUST only be called from PL0
            PauserPrivileges::PL0 => (),
            PauserPrivileges::PL1 => {
                return Err(CaliptraError::RUNTIME_INCORRECT_PAUSER_PRIVILEGE_LEVEL);
            }
        }

        // Populate the otherName only if requested and provided by ADD_SUBJECT_ALT_NAME
        let dmtf_device_info = if flags.contains(CertifyKeyExtendedFlags::DMTF_OTHER_NAME) {
            drivers.dmtf_device_info.as_ref().and_then(|info| {
                let mut dmtf_device_info = ArrayVec::new();
                dmtf_device_info.try_extend_from_slice(info).ok()?;
                Some(dmtf_device_info)
            })
        } else {
            None
        };

        let certify_key_cmd = match profile {
            CaliptraDpeProfile::Ecc384 => Command::from(
                CertifyKeyP384Cmd::ref_from_bytes(&certify_key_req[..]).or(Err(
                    CaliptraError::RUNTIME_DPE_COMMAND_DESERIALIZATION_FAILED,
                ))?,
            ),
            CaliptraDpeProfile::Mldsa87 => Command::from(
                CertifyKeyMldsa87Cmd::ref_from_bytes(&certify_key_req[..]).or(Err(
                    CaliptraError::RUNTIME_DPE_COMMAND_DESERIALIZATION_FAILED,
                ))?,
            ),
        };
        let resp = mutrefbytes::<CertifyKeyExtendedResp>(mbox_resp)?;
        resp.hdr = MailboxRespHeader::default();
        let cmd = &certify_key_cmd;
        let result = invoke_dpe_cmd(
            profile,
            drivers,
            cmd,
            dmtf_device_info,
            None,
            None,
            &mut resp.certify_key_resp,
        );

        match result {
            Ok(dpe_resp_len) => {
                let len = size_of::<CertifyKeyExtendedResp>()
                    - CertifyKeyExtendedResp::CERTIFY_KEY_RESP_SIZE
                    + dpe_resp_len;
                resp.size = len as u32;
                Ok(len)
            }
            Err(e) => {
                // If there is extended error info, populate CPTRA_FW_EXTENDED_ERROR_INFO
                if let Some(ext_err) = e.get_error_detail() {
                    drivers.soc_ifc.set_fw_extended_error(ext_err);
                }
                Err(CaliptraError::RUNTIME_CERTIFY_KEY_EXTENDED_FAILED)
            }
        }
    }
}

#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, Immutable, KnownLayout, PartialEq, Eq)]
pub struct CertifyKeyExtendedRespHeader {
    pub hdr: MailboxRespHeader,
    pub size: u32,
}

const _: () = assert!(
    size_of::<CertifyKeyExtendedRespHeader>()
        == size_of::<CertifyKeyExtendedResp>() - CertifyKeyExtendedResp::CERTIFY_KEY_RESP_SIZE
);
