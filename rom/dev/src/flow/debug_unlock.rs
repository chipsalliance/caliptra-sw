/*++

Licensed under the Apache-2.0 license.

File Name:

    debug_unlock.rs

Abstract:

    File contains the code to handle debug unlock

--*/

use core::mem::ManuallyDrop;

use crate::flow::cold_reset::fw_processor::FirmwareProcessor;
use crate::CaliptraResult;
use caliptra_api::mailbox::{
    MailboxRespHeader, ManufDebugUnlockTokenReq, ProductionAuthDebugUnlockChallenge,
    ProductionAuthDebugUnlockReq, ProductionAuthDebugUnlockToken,
};
use caliptra_cfi_lib::{cfi_launder, CfiCounter};
use caliptra_common::{cprintln, debug_unlock, mailbox_api::CommandId};
use caliptra_drivers::Lifecycle;
use caliptra_error::CaliptraError;
use zerocopy::IntoBytes;

use crate::rom_env::RomEnv;

/// Debug Unlock Flow
///
/// # Arguments
///
/// * `env` - ROM Environment
pub fn debug_unlock(env: &mut RomEnv) -> CaliptraResult<()> {
    if env.soc_ifc.ss_debug_intent() {
        // Clear the device secrets if debug intent is set.
        env.doe.clear_secrets()?;
    }

    if !env.soc_ifc.ss_debug_unlock_req()? {
        return Ok(());
    }

    if !env.soc_ifc.subsystem_mode() {
        Err(CaliptraError::SS_DBG_UNLOCK_REQ_IN_PASSIVE_MODE)?;
    }

    let lifecycle = env.soc_ifc.lifecycle();
    match lifecycle {
        Lifecycle::Production => handle_production(env),
        Lifecycle::Manufacturing => handle_manufacturing(env),
        _ => Ok(()),
    }
}

fn handle_manufacturing(env: &mut RomEnv) -> CaliptraResult<()> {
    cprintln!("[dbg_manuf] ++");

    // Set debug unlock in progress and unlock the mailbox for tap access.
    env.soc_ifc.set_ss_dbg_unlock_in_progress(true);

    let mbox = &mut env.mbox;
    let txn = loop {
        // Random delay for CFI glitch protection.
        CfiCounter::delay();

        match mbox.peek_recv() {
            Some(txn) => break txn,
            None => continue,
        }
    };

    if CommandId::from(txn.cmd()) != CommandId::MANUF_DEBUG_UNLOCK_REQ_TOKEN {
        env.soc_ifc.set_ss_dbg_unlock_in_progress(false);
        Err(CaliptraError::SS_DBG_UNLOCK_MANUF_INVALID_MBOX_CMD)?;
    }

    let mut txn = ManuallyDrop::new(txn.start_txn());

    let result = (|| {
        // Get command bytes and verify checksum
        let cmd_bytes = FirmwareProcessor::get_and_verify_cmd_bytes(&txn)?;

        // Copy request data since it needs to persist
        let mut request = ManufDebugUnlockTokenReq::default();
        let request_bytes = request.as_mut_bytes();
        if cmd_bytes.len() != request_bytes.len() {
            return Err(CaliptraError::FW_PROC_MAILBOX_INVALID_REQUEST_LENGTH);
        }
        request_bytes.copy_from_slice(cmd_bytes);

        // Hash the token.
        let input_token_digest = env.sha2_512_384.sha512_digest(&request.token)?;

        let fuse_token_digest = env.soc_ifc.fuse_bank().manuf_dbg_unlock_token();

        if cfi_launder(input_token_digest) != fuse_token_digest {
            Err(CaliptraError::SS_DBG_UNLOCK_MANUF_INVALID_TOKEN)?;
        } else {
            caliptra_cfi_lib::cfi_assert_eq_16_words(&input_token_digest.0, &fuse_token_digest.0);
        }
        Ok(())
    })();

    let resp = MailboxRespHeader::default();
    txn.send_response(resp.as_bytes())?;
    match result {
        Ok(()) => {
            env.soc_ifc.set_ss_dbg_unlock_result(true);
        }
        Err(_) => {
            env.soc_ifc.set_ss_dbg_unlock_result(false);
        }
    }

    env.soc_ifc.set_ss_dbg_unlock_in_progress(false);

    cprintln!("[dbg_manuf] --");
    result
}

fn handle_auth_debug_unlock_request(
    env: &mut RomEnv,
) -> CaliptraResult<(
    ProductionAuthDebugUnlockReq,
    ProductionAuthDebugUnlockChallenge,
)> {
    let mbox = &mut env.mbox;
    let txn = loop {
        // Random delay for CFI glitch protection.
        CfiCounter::delay();

        match mbox.peek_recv() {
            Some(txn) => break txn,
            None => continue,
        }
    };

    if CommandId::from(txn.cmd()) != CommandId::PRODUCTION_AUTH_DEBUG_UNLOCK_REQ {
        cprintln!(
            "Invalid command: {:?}, was expecting PRODUCTION_AUTH_DEBUG_UNLOCK_REQ",
            txn.cmd()
        );
        Err(CaliptraError::SS_DBG_UNLOCK_PROD_INVALID_REQ_MBOX_CMD)?
    }

    let mut txn = ManuallyDrop::new(txn.start_txn());

    // Get command bytes and verify checksum
    let cmd_bytes = FirmwareProcessor::get_and_verify_cmd_bytes(&txn)?;

    // Copy request data since it needs to persist
    let mut request = ProductionAuthDebugUnlockReq::default();
    let request_bytes = request.as_mut_bytes();
    if cmd_bytes.len() != request_bytes.len() {
        return Err(CaliptraError::FW_PROC_MAILBOX_INVALID_REQUEST_LENGTH);
    }
    request_bytes.copy_from_slice(cmd_bytes);

    // Use common function to create challenge
    let challenge =
        debug_unlock::create_debug_unlock_challenge(&mut env.trng, &env.soc_ifc, &request);

    // Send response
    match challenge {
        Err(err) => {
            txn.send_response(MailboxRespHeader::default().as_bytes())?;
            Err(err)
        }
        Ok(challenge_resp) => {
            txn.send_response(challenge_resp.as_bytes())?;
            Ok((request, challenge_resp))
        }
    }
}

fn handle_auth_debug_unlock_token(
    env: &mut RomEnv,
    request: &ProductionAuthDebugUnlockReq,
    challenge: &ProductionAuthDebugUnlockChallenge,
) -> CaliptraResult<()> {
    let mbox = &mut env.mbox;
    let txn = loop {
        // Random delay for CFI glitch protection.
        CfiCounter::delay();

        match mbox.peek_recv() {
            Some(txn) => break txn,
            None => continue,
        }
    };

    if CommandId::from(txn.cmd()) != CommandId::PRODUCTION_AUTH_DEBUG_UNLOCK_TOKEN {
        cprintln!(
            "Invalid command: {:?}, was expecting PRODUCTION_AUTH_DEBUG_UNLOCK_TOKEN",
            txn.cmd()
        );
        Err(CaliptraError::SS_DBG_UNLOCK_PROD_INVALID_TOKEN_MBOX_CMD)?;
    }

    let mut txn = ManuallyDrop::new(txn.start_txn());

    // Get command bytes and verify checksum
    let cmd_bytes = FirmwareProcessor::get_and_verify_cmd_bytes(&txn)?;

    // Copy token data
    let mut token = ProductionAuthDebugUnlockToken::default();
    let token_bytes = token.as_mut_bytes();
    if cmd_bytes.len() != token_bytes.len() {
        return Err(CaliptraError::FW_PROC_MAILBOX_INVALID_REQUEST_LENGTH);
    }
    token_bytes.copy_from_slice(cmd_bytes);

    // Use common validation function
    let result = debug_unlock::validate_debug_unlock_token(
        &env.soc_ifc,
        &mut env.sha2_512_384,
        &mut env.sha2_512_384_acc,
        &mut env.ecc384,
        &mut env.mldsa87,
        &mut env.dma,
        request,
        challenge,
        &token,
    );

    // Send response
    let _ = txn.send_response(MailboxRespHeader::default().as_bytes());
    result
}

fn handle_production(env: &mut RomEnv) -> CaliptraResult<()> {
    cprintln!("[dbg_prod] ++");

    env.soc_ifc.set_ss_dbg_unlock_in_progress(true);

    let mut debug_unlock_op = || -> CaliptraResult<u8> {
        let (request, challenge) = handle_auth_debug_unlock_request(env)?;
        handle_auth_debug_unlock_token(env, &request, &challenge)?;
        Ok(request.unlock_level)
    };

    let result = debug_unlock_op();
    match result {
        Ok(unlock_level) => {
            env.soc_ifc.set_ss_dbg_unlock_level(unlock_level);

            cprintln!("[dbg_prod] Debug unlock successful");
            env.soc_ifc.set_ss_dbg_unlock_result(true);
        }
        Err(_) => {
            cprintln!("[dbg_prod] Debug unlock failed");
            env.soc_ifc.set_ss_dbg_unlock_result(false);
        }
    }
    env.soc_ifc.set_ss_dbg_unlock_in_progress(false);

    cprintln!("[dbg_prod] --");
    result.map(|_| ())
}
