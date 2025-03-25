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

    if !env.soc_ifc.active_mode() {
        cprintln!("[state] error debug unlock requested in passive mode!");
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

    // Set tap mailbox available.
    env.soc_ifc.set_tap_mailbox_available();

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
        Err(CaliptraError::ROM_SS_DBG_UNLOCK_MANUF_INVALID_MBOX_CMD)?
    }

    let mut txn = ManuallyDrop::new(txn.start_txn());
    let mut request = ManufDebugUnlockTokenReq::default();
    FirmwareProcessor::copy_req_verify_chksum(&mut txn, request.as_mut_bytes())?;

    env.soc_ifc.set_ss_dbg_unlock_in_progress(true);

    let result: CaliptraResult<()> = (|| {
        // Hash the token.
        let input_token_digest = env.sha2_512_384.sha512_digest(&request.token)?;

        let fuse_token_digest = env.soc_ifc.fuse_bank().manuf_dbg_unlock_token();

        if cfi_launder(input_token_digest) != fuse_token_digest {
            cprintln!("[dbg_manuf] Token mismatch!");
            Err(CaliptraError::ROM_SS_DBG_UNLOCK_MANUF_INVALID_TOKEN)?;
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
            env.soc_ifc.finish_ss_dbg_unlock(true);
        }
        Err(_) => {
            cprintln!("[dbg_manuf] Debug unlock failed");
            env.soc_ifc.finish_ss_dbg_unlock(false);
        }
    }

    cprintln!("[dbg_manuf] --");
    result
}

fn bytes_to_usize(input: [u8; 3]) -> usize {
    let mut val: usize = 0;
    val |= input[0] as usize;
    val |= (input[1] as usize) << 8;
    val |= (input[2] as usize) << 16;
    val * size_of::<u32>()
}

fn handle_production_request(
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
        Err(CaliptraError::ROM_SS_DBG_UNLOCK_PROD_INVALID_REQ_MBOX_CMD)?
    }

    let mut txn = ManuallyDrop::new(txn.start_txn());
    let mut request = ProductionAuthDebugUnlockReq::default();
    FirmwareProcessor::copy_req_verify_chksum(&mut txn, request.as_mut_bytes())?;

    // Validate payload
    if bytes_to_usize(request.length)
        != size_of::<ProductionAuthDebugUnlockReq>() - size_of::<MailboxReqHeader>()
    {
        Err(CaliptraError::ROM_SS_DBG_UNLOCK_PROD_INVALID_REQ)?;
    }
    // [TODO][CAP2] what do these 3 bytes mean when only 4 bits are active?
    // Debug level
    let dbg_level = bytes_to_usize(request.unlock_category);
    if dbg_level & 0xf != dbg_level {
        Err(CaliptraError::ROM_SS_DBG_UNLOCK_PROD_INVALID_REQ)?;
    }

    let length = (size_of::<ProductionAuthDebugUnlockChallenge>() - size_of::<MailboxReqHeader>())
        / size_of::<u32>();
    let challenge = env.trng.generate()?.as_bytes().try_into().unwrap();
    let challenge_resp = ProductionAuthDebugUnlockChallenge {
        vendor_id: request.vendor_id,
        object_data_type: request.object_data_type,
        length: length.to_ne_bytes()[..3].try_into().unwrap(),
        unique_device_identifier: {
            let mut id = [0u8; 32];
            id[..17].copy_from_slice(&env.soc_ifc.fuse_bank().ueid());
            id
        },
        challenge,
        ..Default::default()
    };
    txn.send_response(challenge_resp.as_bytes())?;
    Ok((request, challenge_resp))
}

fn handle_production_token(
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
        Err(CaliptraError::ROM_SS_DBG_UNLOCK_PROD_INVALID_TOKEN_MBOX_CMD)?;
    }

    env.soc_ifc.set_ss_dbg_unlock_in_progress(true);

    // We get the digest before emptying the mbox
    let key_digest = {
        let token = core::mem::MaybeUninit::<ProductionAuthDebugUnlockToken>::uninit();
        let token = unsafe { token.assume_init() };

        let start_offset = {
            let base = token.as_bytes().as_ptr() as usize;
            let field = &token.ecc_public_key as *const _ as usize;
            field - base
        };
        let data_len = core::mem::size_of_val(&token.ecc_public_key)
            + core::mem::size_of_val(&token.mldsa_public_key);
        let mut request_digest = Array4x16::default();
        let mut acc_op = env
            .sha2_512_384_acc
            .try_start_operation(ShaAccLockState::AssumedLocked)?
            .ok_or(CaliptraError::ROM_SS_DBG_UNLOCK_PROD_INVALID_TOKEN_WRONG_PUBLIC_KEYS)?;
        acc_op.digest_512(
            data_len as u32,
            start_offset as u32,
            false,
            &mut request_digest,
        )?;
        request_digest
    };

    let mut txn = ManuallyDrop::new(txn.start_txn());
    let mut token = ProductionAuthDebugUnlockToken::default();
    FirmwareProcessor::copy_req_verify_chksum(&mut txn, token.as_mut_bytes())?;

    // Validate payload
    if bytes_to_usize(token.length)
        != size_of::<ProductionAuthDebugUnlockToken>() - size_of::<MailboxReqHeader>()
    {
        Err(CaliptraError::ROM_SS_DBG_UNLOCK_PROD_INVALID_TOKEN_CHALLENGE)?
    }

    // Debug level
    if token.unlock_category != request.unlock_category {
        Err(CaliptraError::ROM_SS_DBG_UNLOCK_PROD_INVALID_TOKEN_CHALLENGE)?;
    }

    if cfi_launder(token.challenge) != challenge.challenge {
        Err(CaliptraError::ROM_SS_DBG_UNLOCK_PROD_INVALID_TOKEN_CHALLENGE)?;
    } else {
        caliptra_cfi_lib::cfi_assert_eq_12_words(
            &Array4x12::from(token.challenge).0,
            &Array4x12::from(challenge.challenge).0,
        );
    }

    let debug_auth_pk_offset =
        env.soc_ifc
            .debug_unlock_pk_hash_offset(bytes_to_usize(token.unlock_category))? as u64;
    let mci_base = env.soc_ifc.ss_mci_axi_base();
    let debug_auth_pk_hash_base = mci_base + AxiAddr::from(debug_auth_pk_offset);

    let dma = &mut env.dma;
    let mut fuse_digest: [u32; 16] = [0; 16];
    dma.read_buffer(debug_auth_pk_hash_base, &mut fuse_digest);
    for n in fuse_digest.iter_mut() {
        *n = n.to_be();
    }

    // Verify that digest of keys match
    let fuse_digest = Array4x16::from(fuse_digest);
    if cfi_launder(key_digest) != fuse_digest {
        env.soc_ifc.finish_ss_dbg_unlock(false);
        txn.set_uc_tap_unlock(false);
        Err(CaliptraError::ROM_SS_DBG_UNLOCK_PROD_INVALID_TOKEN_WRONG_PUBLIC_KEYS)?;
    } else {
        caliptra_cfi_lib::cfi_assert_eq_12_words(
            &key_digest.0[..12].try_into().unwrap(),
            &fuse_digest.0[..12].try_into().unwrap(),
        );
    }

    // Verify that the challenge is properly signed by the keys
    let pubkey = Ecc384PubKey {
        x: Ecc384Scalar::from(<[u8; 48]>::try_from(&token.ecc_public_key[..48]).unwrap()),
        y: Ecc384Scalar::from(<[u8; 48]>::try_from(&token.ecc_public_key[48..]).unwrap()),
    };
    let signature = Ecc384Signature {
        r: Ecc384Scalar::from(<[u8; 48]>::try_from(&token.ecc_signature[..48]).unwrap()),
        s: Ecc384Scalar::from(<[u8; 48]>::try_from(&token.ecc_signature[48..]).unwrap()),
    };
    let mut digest_op = env.sha2_512_384.sha384_digest_init()?;
    digest_op.update(&token.challenge)?;
    digest_op.update(&token.unique_device_identifier)?;
    digest_op.update(&token.unlock_category)?;
    let mut ecc_msg = Array4x12::default();
    digest_op.finalize(&mut ecc_msg)?;
    let result = env.ecc384.verify(&pubkey, &ecc_msg, &signature)?;
    if result == Ecc384Result::SigVerifyFailed {
        env.soc_ifc.finish_ss_dbg_unlock(false);
        txn.set_uc_tap_unlock(false);
        return Err(CaliptraError::ROM_SS_DBG_UNLOCK_PROD_INVALID_TOKEN_INVALID_SIGNATURE);
    }

    let mut digest_op = env.sha2_512_384.sha512_digest_init()?;
    digest_op.update(&token.challenge)?;
    digest_op.update(&token.unique_device_identifier)?;
    digest_op.update(&token.unlock_category)?;
    let mut mldsa_msg = Array4x16::default();
    digest_op.finalize(&mut mldsa_msg)?;

    let result = env.mldsa87.verify(
        &Mldsa87PubKey::from(&token.mldsa_public_key),
        &mldsa_msg,
        &Mldsa87Signature::from(&token.mldsa_signature),
    )?;

    if result == Mldsa87Result::SigVerifyFailed {
        Err(CaliptraError::ROM_SS_DBG_UNLOCK_PROD_INVALID_TOKEN_INVALID_SIGNATURE)?;
    }
    Ok(())
}

fn handle_production(env: &mut RomEnv) -> CaliptraResult<()> {
    let (request, challenge) = handle_production_request(env)?;
    let result = handle_production_token(env, &request, &challenge);

    env.soc_ifc.set_ss_dbg_unlock_in_progress(false);

    let mbox = &mut env.mbox;
    let txn = loop {
        // Random delay for CFI glitch protection.
        CfiCounter::delay();

        match mbox.peek_recv() {
            Some(txn) => break txn,
            None => continue,
        }
    };

    let mut txn = ManuallyDrop::new(txn.start_txn());

    match result {
        Ok(()) => {
            env.soc_ifc.finish_ss_dbg_unlock(true);
            txn.set_uc_tap_unlock(true);
            let resp = MailboxRespHeader::default();
            txn.send_response(resp.as_bytes())?;
        }
        Err(_) => {
            env.soc_ifc.finish_ss_dbg_unlock(false);
            txn.set_uc_tap_unlock(false);
        }
    }
    result
}
