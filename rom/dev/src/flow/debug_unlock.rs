/*++

Licensed under the Apache-2.0 license.

File Name:

    debug_unlock.rs

Abstract:

    File contains the code to handle debug unlock

--*/

use core::mem::{size_of, ManuallyDrop};

use crate::flow::cold_reset::fw_processor::FirmwareProcessor;
use crate::CaliptraResult;
use caliptra_api::mailbox::{
    MailboxReqHeader, MailboxRespHeader, ManufDebugUnlockTokenReq,
    ProductionAuthDebugUnlockChallenge, ProductionAuthDebugUnlockReq,
    ProductionAuthDebugUnlockToken,
};
use caliptra_cfi_lib::{cfi_launder, CfiCounter};
use caliptra_common::{cprintln, mailbox_api::CommandId};
#[allow(unused_imports)]
use caliptra_drivers::{
    sha2_512_384::Sha2DigestOpTrait, Array4x12, Array4x16, AxiAddr, Ecc384PubKey, Ecc384Result,
    Ecc384Scalar, Ecc384Signature, Lifecycle, Mldsa87PubKey, Mldsa87Result, Mldsa87Signature,
    ShaAccLockState,
};
use caliptra_error::CaliptraError;
use zerocopy::IntoBytes;

use crate::rom_env::RomEnv;

/// Debug Unlock Flow
///
/// # Arguments
///
/// * `env` - ROM Environment
pub fn debug_unlock(env: &mut RomEnv) -> CaliptraResult<()> {
    if !env.soc_ifc.ss_debug_unlock_req()? {
        return Ok(());
    }

    if !env.soc_ifc.subsystem_mode() {
        cprintln!("[state] Error: debug unlock requested in passive mode!");
        Err(CaliptraError::ROM_SS_DBG_UNLOCK_REQ_IN_PASSIVE_MODE)?;
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
    // [TODO] Ensure this is always set to false on failure.
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
        return Err(CaliptraError::ROM_SS_DBG_UNLOCK_MANUF_INVALID_MBOX_CMD);
    }

    let mut txn = ManuallyDrop::new(txn.start_txn());

    let result = (|| {
        let mut request = ManufDebugUnlockTokenReq::default();
        let request_bytes = request.as_mut_bytes();
        FirmwareProcessor::copy_req_verify_chksum(&mut txn, request_bytes)?;

        // Hash the token.
        let input_token_digest = env.sha2_512_384.sha512_digest(&request.token)?;

        let fuse_token_digest = env.soc_ifc.fuse_bank().manuf_dbg_unlock_token();

        if cfi_launder(input_token_digest) != fuse_token_digest {
            cprintln!("[dbg_manuf] Token mismatch!");
            return Err(CaliptraError::ROM_SS_DBG_UNLOCK_MANUF_INVALID_TOKEN);
        } else {
            caliptra_cfi_lib::cfi_assert_eq_12_words(
                &input_token_digest.0[..12].try_into().unwrap(),
                &fuse_token_digest.0[..12].try_into().unwrap(),
            );
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
        Err(CaliptraError::ROM_SS_DBG_UNLOCK_PROD_INVALID_REQ_MBOX_CMD)?
    }

    let mut txn = ManuallyDrop::new(txn.start_txn());
    let mut send_mailbox_response = || -> Result<(ProductionAuthDebugUnlockReq, ProductionAuthDebugUnlockChallenge), CaliptraError> {
        let mut request = ProductionAuthDebugUnlockReq::default();
        FirmwareProcessor::copy_req_verify_chksum(&mut txn, request.as_mut_bytes())?;

        // Validate payload
        if request.length as usize * size_of::<u32>()
            != size_of::<ProductionAuthDebugUnlockReq>() - size_of::<MailboxReqHeader>()
        {
            cprintln!("Invalid ProductionAuthDebugUnlockReq payload length: {}", request.length);
            Err(CaliptraError::ROM_SS_DBG_UNLOCK_PROD_INVALID_REQ)?;
        }

        // Check if the debug level is valid.
        let dbg_level = request.unlock_level as u32;
        if dbg_level > env.soc_ifc.debug_unlock_pk_hash_count() {
            cprintln!("Invalid debug level: Received level: {}, Fuse PK Hash Count: {}",
            dbg_level, env.soc_ifc.debug_unlock_pk_hash_count());
            Err(CaliptraError::ROM_SS_DBG_UNLOCK_PROD_INVALID_REQ)?;
        }

        let length = ((size_of::<ProductionAuthDebugUnlockChallenge>()
            - size_of::<MailboxReqHeader>())
            / size_of::<u32>()) as u32;
        //let challenge = env.trng.generate()?.as_bytes().try_into().unwrap();
        // [TODO][CAP2] Review with hardware team for using TRNG to generate nonce.
        let challenge: [u8; 48] = [
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
            25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46,
            47, 48,
        ];
        let challenge_resp: ProductionAuthDebugUnlockChallenge =
            ProductionAuthDebugUnlockChallenge {
                length,
                unique_device_identifier: {
                    let mut id = [0u8; 32];
                    id[..17].copy_from_slice(&env.soc_ifc.fuse_bank().ueid());
                    id
                },
                challenge,
                ..Default::default()
            };
        Ok((request, challenge_resp))
    };

    // Call the closure and handle the result
    let result = send_mailbox_response();
    match &result {
        Ok((_, challenge_resp)) => txn.send_response(challenge_resp.as_bytes())?,
        Err(_) => txn.send_response(MailboxRespHeader::default().as_bytes())?,
    };

    result
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
        Err(CaliptraError::ROM_SS_DBG_UNLOCK_PROD_INVALID_TOKEN_MBOX_CMD)?;
    }

    let mut txn = ManuallyDrop::new(txn.start_txn());
    let mut auth_debug_unlock_token_op = || -> Result<(), CaliptraError> {
        cprintln!("Handling ProductionAuthDebugUnlockToken...");
        // Hash the ECC and MLDSA public keys in the payload.
        let pub_keys_digest = {
            let token = core::mem::MaybeUninit::<ProductionAuthDebugUnlockToken>::uninit();
            let token = unsafe { token.assume_init() };

            let start_offset = {
                let base = token.as_bytes().as_ptr() as usize;
                let field = &token.ecc_public_key as *const _ as usize;
                field - base
            };
            let data_len = core::mem::size_of_val(&token.ecc_public_key)
                + core::mem::size_of_val(&token.mldsa_public_key);
            let mut request_digest = Array4x12::default();
            let mut acc_op = env
                .sha2_512_384_acc
                .try_start_operation(ShaAccLockState::AssumedLocked)?
                .ok_or(CaliptraError::ROM_SS_DBG_UNLOCK_PROD_INVALID_TOKEN_WRONG_PUBLIC_KEYS)?;
            acc_op.digest_384(
                data_len as u32,
                start_offset as u32,
                false,
                &mut request_digest,
            )?;
            request_digest
        };

        let mut token = ProductionAuthDebugUnlockToken::default();
        FirmwareProcessor::copy_req_verify_chksum(&mut txn, token.as_mut_bytes())?;

        // Validate the payload size.
        if token.length as usize * size_of::<u32>()
            != size_of::<ProductionAuthDebugUnlockToken>() - size_of::<MailboxReqHeader>()
        {
            cprintln!(
                "Invalid ProductionAuthDebugUnlockToken payload length: {}",
                token.length
            );
            Err(CaliptraError::ROM_SS_DBG_UNLOCK_PROD_INVALID_TOKEN_CHALLENGE)?
        }

        // Check if the debug level is same as the request.
        if token.unlock_level != request.unlock_level {
            cprintln!("Invalid unlock level: {}", token.unlock_level);
            Err(CaliptraError::ROM_SS_DBG_UNLOCK_PROD_INVALID_TOKEN_CHALLENGE)?;
        }

        // Check if the challenge is same as the request.
        if cfi_launder(token.challenge) != challenge.challenge {
            cprintln!("Challenge mismatch");
            Err(CaliptraError::ROM_SS_DBG_UNLOCK_PROD_INVALID_TOKEN_CHALLENGE)?;
        } else {
            caliptra_cfi_lib::cfi_assert_eq_12_words(
                &Array4x12::from(token.challenge).0,
                &Array4x12::from(challenge.challenge).0,
            );
        }

        let debug_auth_pk_offset =
            env.soc_ifc
                .debug_unlock_pk_hash_offset(token.unlock_level as u32)? as u64;
        let mci_base = env.soc_ifc.ss_mci_axi_base();
        let debug_auth_pk_hash_base = mci_base + AxiAddr::from(debug_auth_pk_offset);

        let dma = &mut env.dma;
        let mut fuse_digest: [u32; 12] = [0; 12];
        dma.read_buffer(debug_auth_pk_hash_base, &mut fuse_digest);

        // Verify the fuse digest matches with the ECC and MLDSA public key digest.
        let fuse_digest = Array4x12::from(fuse_digest);

        if cfi_launder(pub_keys_digest) != fuse_digest {
            cprintln!("Public key hash mismatch");
            Err(CaliptraError::ROM_SS_DBG_UNLOCK_PROD_INVALID_TOKEN_WRONG_PUBLIC_KEYS)?;
        } else {
            caliptra_cfi_lib::cfi_assert_eq_12_words(&pub_keys_digest.0, &fuse_digest.0);
        }

        // Verify that the Unique Device Identifier, Unlock Category and Challenge signature is valid.
        let pubkey = Ecc384PubKey {
            x: Ecc384Scalar::from(<[u32; 12]>::try_from(&token.ecc_public_key[..12]).unwrap()),
            y: Ecc384Scalar::from(<[u32; 12]>::try_from(&token.ecc_public_key[12..]).unwrap()),
        };
        let signature = Ecc384Signature {
            r: Ecc384Scalar::from(<[u32; 12]>::try_from(&token.ecc_signature[..12]).unwrap()),
            s: Ecc384Scalar::from(<[u32; 12]>::try_from(&token.ecc_signature[12..]).unwrap()),
        };
        // [TODO][CAP2] Use the SHA-ACC to hash the data.
        let mut digest_op = env.sha2_512_384.sha384_digest_init()?;
        digest_op.update(&token.unique_device_identifier)?;
        digest_op.update(&[token.unlock_level])?;
        digest_op.update(&token.reserved)?;
        digest_op.update(&token.challenge)?;

        let mut ecc_msg = Array4x12::default();
        digest_op.finalize(&mut ecc_msg)?;
        let result = env.ecc384.verify(&pubkey, &ecc_msg, &signature)?;
        if result == Ecc384Result::SigVerifyFailed {
            cprintln!("ECC Signature verification failed");
            Err(CaliptraError::ROM_SS_DBG_UNLOCK_PROD_INVALID_TOKEN_INVALID_SIGNATURE)?;
        }

        let mut digest_op = env.sha2_512_384.sha512_digest_init()?;
        digest_op.update(&token.unique_device_identifier)?;
        digest_op.update(&[token.unlock_level])?;
        digest_op.update(&token.reserved)?;
        digest_op.update(&token.challenge)?;
        let mut mldsa_msg = Array4x16::default();
        digest_op.finalize(&mut mldsa_msg)?;

        let result = env.mldsa87.verify(
            &Mldsa87PubKey::from(token.mldsa_public_key),
            &mldsa_msg,
            &Mldsa87Signature::from(token.mldsa_signature),
        )?;

        if result == Mldsa87Result::SigVerifyFailed {
            cprintln!("MLDSA Signature verification failed");
            Err(CaliptraError::ROM_SS_DBG_UNLOCK_PROD_INVALID_TOKEN_INVALID_SIGNATURE)?;
        }

        Ok(())
    };

    // Call the closure.
    let result = auth_debug_unlock_token_op();
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
