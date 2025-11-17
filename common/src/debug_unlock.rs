/*++

Licensed under the Apache-2.0 license.

File Name:

    debug_unlock.rs

Abstract:

    File contains common code for debug unlock validation.

--*/

use core::mem::size_of;

use caliptra_api::mailbox::{
    MailboxReqHeader, ProductionAuthDebugUnlockChallenge, ProductionAuthDebugUnlockReq,
    ProductionAuthDebugUnlockToken,
};
use caliptra_cfi_lib::{cfi_assert_eq_12_words, cfi_launder};
use caliptra_drivers::{
    sha2_512_384::Sha2DigestOpTrait, Array4x12, Array4x16, AxiAddr, Dma, Ecc384, Ecc384PubKey,
    Ecc384Result, Ecc384Scalar, Ecc384Signature, LEArray4x16, Mldsa87, Mldsa87PubKey,
    Mldsa87Result, Mldsa87Signature, Sha2_512_384, Sha2_512_384Acc, ShaAccLockState, SocIfc, Trng,
};
use caliptra_error::{CaliptraError, CaliptraResult};
use memoffset::{offset_of, span_of};
use zerocopy::IntoBytes;

/// Create a challenge for production debug unlock
///
/// # Arguments
///
/// * `trng` - TRNG driver for generating challenge
/// * `soc_ifc` - SOC interface for accessing fuse bank
/// * `request` - The debug unlock request
///
/// # Returns
///
/// * `CaliptraResult<ProductionAuthDebugUnlockChallenge>` - The challenge response
pub fn create_debug_unlock_challenge(
    trng: &mut Trng,
    soc_ifc: &SocIfc,
    request: &ProductionAuthDebugUnlockReq,
) -> CaliptraResult<ProductionAuthDebugUnlockChallenge> {
    // Validate payload
    if request.length as usize * size_of::<u32>()
        != size_of::<ProductionAuthDebugUnlockReq>() - size_of::<MailboxReqHeader>()
    {
        crate::cprintln!(
            "Invalid ProductionAuthDebugUnlockReq payload length: {}",
            request.length
        );
        Err(CaliptraError::SS_DBG_UNLOCK_PROD_INVALID_REQ)?;
    }

    // Check if the debug level is valid.
    let dbg_level = request.unlock_level as u32;
    if dbg_level > soc_ifc.debug_unlock_pk_hash_count() {
        crate::cprintln!(
            "Invalid debug level: Received level: {}, Fuse PK Hash Count: {}",
            dbg_level,
            soc_ifc.debug_unlock_pk_hash_count()
        );
        Err(CaliptraError::SS_DBG_UNLOCK_PROD_INVALID_REQ)?;
    }

    let length = ((size_of::<ProductionAuthDebugUnlockChallenge>() - size_of::<MailboxReqHeader>())
        / size_of::<u32>()) as u32;
    let challenge = trng.generate()?.as_bytes().try_into().unwrap();

    let challenge_resp: ProductionAuthDebugUnlockChallenge = ProductionAuthDebugUnlockChallenge {
        length,
        unique_device_identifier: {
            let mut id = [0u8; 32];
            id[..17].copy_from_slice(&soc_ifc.fuse_bank().ueid());
            id
        },
        challenge,
        ..Default::default()
    };

    Ok(challenge_resp)
}

/// Validates a production debug unlock token
#[allow(clippy::too_many_arguments)]
pub fn validate_debug_unlock_token(
    soc_ifc: &SocIfc,
    sha2_512_384: &mut Sha2_512_384,
    sha2_512_384_acc: &mut Sha2_512_384Acc,
    ecc384: &mut Ecc384,
    mldsa87: &mut Mldsa87,
    dma: &mut Dma,
    request: &ProductionAuthDebugUnlockReq,
    challenge: &ProductionAuthDebugUnlockChallenge,
    token: &ProductionAuthDebugUnlockToken,
) -> CaliptraResult<()> {
    // Validate the payload size.
    if token.length as usize * size_of::<u32>()
        != size_of::<ProductionAuthDebugUnlockToken>() - size_of::<MailboxReqHeader>()
    {
        crate::cprintln!(
            "Invalid ProductionAuthDebugUnlockToken payload length: {}",
            token.length
        );
        Err(CaliptraError::SS_DBG_UNLOCK_PROD_INVALID_TOKEN_CHALLENGE)?
    }

    // Check if the debug level is same as the request.
    if token.unlock_level != request.unlock_level {
        crate::cprintln!("Invalid unlock level: {}", token.unlock_level);
        Err(CaliptraError::SS_DBG_UNLOCK_PROD_INVALID_TOKEN_CHALLENGE)?;
    }

    // Check if the challenge is same as the request.
    if cfi_launder(token.challenge) != challenge.challenge {
        crate::cprintln!("Challenge mismatch");
        Err(CaliptraError::SS_DBG_UNLOCK_PROD_INVALID_TOKEN_CHALLENGE)?;
    } else {
        cfi_assert_eq_12_words(
            &Array4x12::from(token.challenge).0,
            &Array4x12::from(challenge.challenge).0,
        );
    }

    // Hash the ECC and MLDSA public keys in the payload.
    let pub_keys_digest = {
        let ecc_public_key_offset = offset_of!(ProductionAuthDebugUnlockToken, ecc_public_key);
        let combined_len = span_of!(
            ProductionAuthDebugUnlockToken,
            ecc_public_key..=mldsa_public_key
        )
        .len();

        let mut request_digest = Array4x12::default();
        let lock_state = if cfg!(feature = "rom") {
            ShaAccLockState::AssumedLocked
        } else {
            ShaAccLockState::NotAcquired
        };
        let mut acc_op = sha2_512_384_acc
            .try_start_operation(lock_state)?
            .ok_or(CaliptraError::SS_DBG_UNLOCK_PROD_INVALID_TOKEN_WRONG_PUBLIC_KEYS)?;

        acc_op.digest_384(
            combined_len as u32,
            ecc_public_key_offset as u32,
            false,
            &mut request_digest,
        )?;
        request_digest
    };

    let debug_auth_pk_offset =
        soc_ifc.debug_unlock_pk_hash_offset(token.unlock_level as u32)? as u64;
    let mci_base: AxiAddr = soc_ifc.mci_base_addr().into();
    let debug_auth_pk_hash_base = mci_base + debug_auth_pk_offset;

    let mut fuse_digest: [u32; 12] = [0; 12];
    dma.read_buffer(debug_auth_pk_hash_base, &mut fuse_digest, None);

    // Verify the fuse digest matches with the ECC and MLDSA public key digest.
    let fuse_digest = Array4x12::from(fuse_digest);

    if cfi_launder(pub_keys_digest) != fuse_digest {
        crate::cprintln!("Public keys hash mismatch");
        Err(CaliptraError::SS_DBG_UNLOCK_PROD_INVALID_TOKEN_WRONG_PUBLIC_KEYS)?;
    } else {
        cfi_assert_eq_12_words(&pub_keys_digest.0, &fuse_digest.0);
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

    // Create ECC message hash
    let mut digest_op = sha2_512_384.sha384_digest_init()?;
    digest_op.update(&token.unique_device_identifier)?;
    digest_op.update(&[token.unlock_level])?;
    digest_op.update(&token.reserved)?;
    digest_op.update(&token.challenge)?;

    let mut ecc_msg = Array4x12::default();
    digest_op.finalize(&mut ecc_msg)?;
    let result = ecc384.verify(&pubkey, &ecc_msg, &signature)?;
    if result == Ecc384Result::SigVerifyFailed {
        crate::cprintln!("ECC Signature verification failed");
        Err(CaliptraError::SS_DBG_UNLOCK_PROD_INVALID_TOKEN_INVALID_SIGNATURE)?;
    }

    // Create MLDSA message hash
    let mut digest_op = sha2_512_384.sha512_digest_init()?;
    digest_op.update(&token.unique_device_identifier)?;
    digest_op.update(&[token.unlock_level])?;
    digest_op.update(&token.reserved)?;
    digest_op.update(&token.challenge)?;
    let mut mldsa_msg = Array4x16::default();
    digest_op.finalize(&mut mldsa_msg)?;

    // Convert the digest to little endian format for MLDSA.
    let mldsa_msg: LEArray4x16 = mldsa_msg.into();

    let result = mldsa87.verify(
        &Mldsa87PubKey::from(&token.mldsa_public_key),
        &mldsa_msg,
        &Mldsa87Signature::from(&token.mldsa_signature),
    )?;

    if result == Mldsa87Result::SigVerifyFailed {
        crate::cprintln!("MLDSA Signature verification failed");
        Err(CaliptraError::SS_DBG_UNLOCK_PROD_INVALID_TOKEN_INVALID_SIGNATURE)?;
    }

    Ok(())
}
