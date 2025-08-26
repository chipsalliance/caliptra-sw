/*++

Licensed under the Apache-2.0 license.

File Name:

    debug_unlock.rs

Abstract:

    File contains the code to handle debug unlock

--*/

use core::mem::ManuallyDrop;

use crate::flow::cold_reset::fw_processor::get_checksummed_payload;
use crate::CaliptraResult;
use caliptra_api::mailbox::{
    MailboxRespHeader, ManufDebugUnlockTokenReq, ProductionAuthDebugUnlockChallenge,
    ProductionAuthDebugUnlockReq, ProductionAuthDebugUnlockToken,
};
use caliptra_cfi_lib::{cfi_launder, CfiCounter};
use caliptra_common::{cprintln, debug_unlock, mailbox_api::CommandId};
use caliptra_drivers::Lifecycle;
use caliptra_error::CaliptraError;
use zerocopy::{FromBytes, IntoBytes};

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
        cprintln!("[state] Error: debug unlock requested in passive mode!");
        Err(CaliptraError::SS_DBG_UNLOCK_REQ_IN_PASSIVE_MODE)?;
    }

    cprintln!("[state] debug unlock requested");

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
        cprintln!("[dbg_manuf] Invalid command: {:?}", txn.cmd());
        env.soc_ifc.set_ss_dbg_unlock_in_progress(false);
        Err(CaliptraError::SS_DBG_UNLOCK_MANUF_INVALID_MBOX_CMD)?;
    }

    let mut txn = ManuallyDrop::new(txn.start_txn());

    let result = (|| {
        let cmd_bytes = get_checksummed_payload(&txn)?;
        let request = ManufDebugUnlockTokenReq::ref_from_bytes(cmd_bytes)
            .map_err(|_| CaliptraError::MBOX_PAYLOAD_INVALID_SIZE)?;

        // Hash the token.
        let input_token_digest = env.sha2_512_384.sha512_digest(&request.token)?;

        let fuse_token_digest = env.soc_ifc.fuse_bank().manuf_dbg_unlock_token();

        if cfi_launder(input_token_digest) != fuse_token_digest {
            cprintln!("[dbg_manuf] Token mismatch!");
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
            cprintln!("[dbg_manuf] Debug unlock successful");
            env.soc_ifc.set_ss_dbg_unlock_result(true);
        }
        Err(_) => {
            cprintln!("[dbg_manuf] Debug unlock failed");
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

    // Process request and create challenge
    let cmd_bytes = get_checksummed_payload(&txn)?;
    let request = ProductionAuthDebugUnlockReq::ref_from_bytes(cmd_bytes)
        .map_err(|_| CaliptraError::MBOX_PAYLOAD_INVALID_SIZE)?;

    // Clone the request to avoid borrowing conflicts
    let request_owned = *request;

    // Use common function to create challenge
    let challenge =
        debug_unlock::create_debug_unlock_challenge(&mut env.trng, &env.soc_ifc, request);

    // Send response
    match challenge {
        Err(err) => {
            txn.send_response(MailboxRespHeader::default().as_bytes())?;
            Err(err)
        }
        Ok(challenge_resp) => {
            txn.send_response(challenge_resp.as_bytes())?;
            Ok((request_owned, challenge_resp))
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

    // Copy token from mailbox
    let cmd_bytes = get_checksummed_payload(&txn)?;
    let token = ProductionAuthDebugUnlockToken::ref_from_bytes(cmd_bytes)
        .map_err(|_| CaliptraError::MBOX_PAYLOAD_INVALID_SIZE)?;

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
        token,
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
