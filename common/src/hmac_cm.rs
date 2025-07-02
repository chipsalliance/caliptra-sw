/*++

Licensed under the Apache-2.0 license.

File Name:

    hmac_cm.rs

Abstract:

    HMAC Cryptographic Mailbox command processing.

--*/

use crate::crypto::{Crypto, EncryptedCmk, UnencryptedCmk};
use caliptra_api::mailbox::{
    CmHashAlgorithm, CmHmacReq, CmHmacResp, CmKeyUsage, Cmk, MailboxRespHeaderVarSize,
    ResponseVarSize,
};
use caliptra_drivers::{Aes, Array4x12, Array4x16, Hmac, HmacData, HmacMode, Trng};
use caliptra_error::{CaliptraError, CaliptraResult};
use caliptra_image_types::{SHA384_DIGEST_BYTE_SIZE, SHA512_DIGEST_BYTE_SIZE};
use zerocopy::{FromBytes, IntoBytes, KnownLayout};

#[inline(always)]
pub(crate) fn mutrefbytes<R: FromBytes + IntoBytes + KnownLayout>(
    resp: &mut [u8],
) -> CaliptraResult<&mut R> {
    // the error should be impossible but check to avoid panic
    let (resp, _) = R::mut_from_prefix(resp).map_err(|_| CaliptraError::RUNTIME_INTERNAL)?;
    Ok(resp)
}

pub fn decrypt_hmac_key(
    aes: &mut Aes,
    trng: &mut Trng,
    kek: ([u8; 32], [u8; 32]),
    cmk: &Cmk,
) -> CaliptraResult<UnencryptedCmk> {
    let encrypted_cmk = EncryptedCmk::ref_from_bytes(&cmk.0[..])
        .map_err(|_| CaliptraError::CMB_HMAC_INVALID_ENC_CMK)?;

    let cmk = Crypto::decrypt_cmk(aes, trng, kek, encrypted_cmk)?;

    match (cmk.length, CmKeyUsage::from(cmk.key_usage as u32)) {
        (48 | 64, CmKeyUsage::Hmac) => Ok(cmk),
        _ => Err(CaliptraError::CMB_HMAC_INVALID_KEY_USAGE),
    }
}

#[inline(always)]
pub fn hmac(
    hmac: &mut Hmac,
    aes: &mut Aes,
    trng: &mut Trng,
    kek: ([u8; 32], [u8; 32]),
    cmd_bytes: &[u8],
    resp: &mut [u8],
) -> CaliptraResult<usize> {
    if cmd_bytes.len() > core::mem::size_of::<CmHmacReq>() {
        Err(CaliptraError::CMB_HMAC_INVALID_REQ_SIZE)?;
    }
    let mut cmd = CmHmacReq::default();
    cmd.as_mut_bytes()[..cmd_bytes.len()].copy_from_slice(cmd_bytes);

    let cm_hash_algorithm = CmHashAlgorithm::from(cmd.hash_algorithm);

    if cmd.data_size as usize > cmd.data.len() {
        Err(CaliptraError::CMB_HMAC_INVALID_REQ_SIZE)?;
    }

    let data = &cmd.data[..cmd.data_size as usize];

    let cmk = decrypt_hmac_key(aes, trng, kek, &cmd.cmk)?;
    // the hardware will fail if a 384-bit key is used with SHA512
    if cmk.length == 48 && cm_hash_algorithm != CmHashAlgorithm::Sha384 {
        Err(CaliptraError::CMB_HMAC_INVALID_KEY_USAGE_AND_SIZE)?;
    }

    let resp = mutrefbytes::<CmHmacResp>(resp)?;
    resp.hdr = MailboxRespHeaderVarSize::default();
    resp.hdr.data_len = match cm_hash_algorithm {
        CmHashAlgorithm::Sha384 => SHA384_DIGEST_BYTE_SIZE as u32,
        CmHashAlgorithm::Sha512 => SHA512_DIGEST_BYTE_SIZE as u32,
        _ => return Err(CaliptraError::CMB_HMAC_UNSUPPORTED_HASH_ALGORITHM)?,
    };

    match cm_hash_algorithm {
        CmHashAlgorithm::Sha384 => {
            let hmac_mode = HmacMode::Hmac384;
            let arr: [u8; 48] = cmk.key_material[..48].try_into().unwrap();
            let key: Array4x12 = arr.into();
            let mut tag = Array4x12::default();
            hmac.hmac(
                (&key).into(),
                HmacData::Slice(data),
                trng,
                (&mut tag).into(),
                hmac_mode,
            )?;
            // convert out of HW format
            tag.0.iter_mut().for_each(|x| {
                *x = x.swap_bytes();
            });
            resp.mac[..tag.as_bytes().len()].copy_from_slice(tag.as_bytes())
        }
        CmHashAlgorithm::Sha512 => {
            let hmac_mode = HmacMode::Hmac512;
            let arr: [u8; 64] = cmk.key_material[..64].try_into().unwrap();
            let key: Array4x16 = arr.into();
            let mut tag = Array4x16::default();
            hmac.hmac(
                (&key).into(),
                HmacData::Slice(data),
                trng,
                (&mut tag).into(),
                hmac_mode,
            )?;
            // convert out of HW format
            tag.0.iter_mut().for_each(|x| {
                *x = x.swap_bytes();
            });
            resp.mac[..tag.as_bytes().len()].copy_from_slice(tag.as_bytes())
        }
        _ => return Err(CaliptraError::CMB_HMAC_UNSUPPORTED_HASH_ALGORITHM)?,
    };

    resp.partial_len()
}
