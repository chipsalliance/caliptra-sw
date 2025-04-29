/*++

Licensed under the Apache-2.0 license.

File Name:

    debug_unlock.rs

Abstract:

    File contains code to handle production debug unlock in the runtime.

--*/

use caliptra_cfi_lib_git::CfiCounter;
use caliptra_common::{
    cprintln,
    mailbox_api::{
        MailboxResp, MailboxRespHeader, ProductionAuthDebugUnlockChallenge,
        ProductionAuthDebugUnlockReq, ProductionAuthDebugUnlockToken,
    },
};
use caliptra_drivers::{CaliptraResult, Lifecycle};
use caliptra_error::CaliptraError;
use zerocopy::FromBytes;

/// Handle production debug unlock for runtime firmware
pub struct ProductionDebugUnlock {
    // Store the last challenge for token validation
    last_challenge: Option<ProductionAuthDebugUnlockChallenge>,
    // Store the original request for token validation
    last_request: Option<ProductionAuthDebugUnlockReq>,
}

impl Default for ProductionDebugUnlock {
    fn default() -> Self {
        Self::new()
    }
}

impl ProductionDebugUnlock {
    /// Create a new instance of the debug unlock handler
    pub fn new() -> Self {
        Self {
            last_challenge: None,
            last_request: None,
        }
    }

    /// Handle the production debug unlock request
    pub fn handle_request(
        &mut self,
        trng: &mut caliptra_drivers::Trng,
        soc_ifc: &caliptra_drivers::SocIfc,
        cmd_bytes: &[u8],
    ) -> CaliptraResult<MailboxResp> {
        if !soc_ifc.ss_debug_unlock_req()? {
            Err(CaliptraError::SS_DBG_UNLOCK_REQ_BIT_NOT_SET)?;
        }

        // Parse the request
        let req = ProductionAuthDebugUnlockReq::read_from_bytes(cmd_bytes)
            .map_err(|_| CaliptraError::RUNTIME_MAILBOX_API_REQUEST_DATA_LEN_TOO_LARGE)?;

        cprintln!("[rt] Starting production debug unlock request");

        // Check if the device is in Production lifecycle
        if soc_ifc.lifecycle() != Lifecycle::Production {
            cprintln!("[rt] Debug unlock request failed: Not in Production lifecycle");
            return Err(CaliptraError::RUNTIME_DEBUG_UNLOCK_INVALID_LIFECYCLE);
        }

        // Use common function to create challenge
        let challenge =
            caliptra_common::debug_unlock::create_debug_unlock_challenge(trng, soc_ifc, &req)?;

        // Store the challenge for future token validation
        let stored_challenge = challenge.clone();
        self.last_challenge = Some(stored_challenge);
        self.last_request = Some(req);

        cprintln!("[rt] Production debug unlock challenge generated");

        Ok(MailboxResp::ProductionAuthDebugUnlockChallenge(challenge))
    }

    /// Handle the production debug unlock token verification
    #[allow(clippy::too_many_arguments)]
    pub fn handle_token(
        &mut self,
        soc_ifc: &mut caliptra_drivers::SocIfc,
        sha2_512_384: &mut caliptra_drivers::Sha2_512_384,
        sha2_512_384_acc: &mut caliptra_drivers::Sha2_512_384Acc,
        ecc384: &mut caliptra_drivers::Ecc384,
        mldsa87: &mut caliptra_drivers::Mldsa87,
        dma: &mut caliptra_drivers::Dma,
        cmd_bytes: &[u8],
    ) -> CaliptraResult<MailboxResp> {
        // Parse the token
        let token = ProductionAuthDebugUnlockToken::read_from_bytes(cmd_bytes)
            .map_err(|_| CaliptraError::RUNTIME_MAILBOX_API_REQUEST_DATA_LEN_TOO_LARGE)?;

        cprintln!("[rt] Starting production debug unlock token validation");

        // Random delay for CFI glitch protection.
        CfiCounter::delay();

        // Check if the device is in Production lifecycle
        if soc_ifc.lifecycle() != Lifecycle::Production {
            cprintln!("[rt] Debug unlock token validation failed: Not in Production lifecycle");
            return Err(CaliptraError::RUNTIME_DEBUG_UNLOCK_INVALID_LIFECYCLE);
        }

        // Get the stored challenge and request
        let challenge = self
            .last_challenge
            .take()
            .ok_or(CaliptraError::RUNTIME_DEBUG_UNLOCK_NO_CHALLENGE)?;

        let request = self
            .last_request
            .take()
            .ok_or(CaliptraError::RUNTIME_DEBUG_UNLOCK_NO_REQUEST)?;

        // Set debug unlock in progress
        soc_ifc.set_ss_dbg_unlock_in_progress(true);

        // Use the common validation logic
        let result = caliptra_common::debug_unlock::validate_debug_unlock_token(
            soc_ifc,
            sha2_512_384,
            sha2_512_384_acc,
            ecc384,
            mldsa87,
            dma,
            &request,
            &challenge,
            &token,
        );

        let ret = match result {
            Ok(()) => {
                soc_ifc.set_ss_dbg_unlock_level(request.unlock_level);
                cprintln!("[rt] Debug unlock successful");
                soc_ifc.set_ss_dbg_unlock_result(true);
                Ok(MailboxResp::Header(MailboxRespHeader::default()))
            }
            Err(e) => {
                cprintln!("[rt] Debug unlock failed: {}", e.0);
                soc_ifc.set_ss_dbg_unlock_result(false);
                Err(e)
            }
        };
        soc_ifc.set_ss_dbg_unlock_in_progress(false);
        ret
    }
}
