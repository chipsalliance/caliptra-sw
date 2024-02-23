/*++

Licensed under the Apache-2.0 license.

File Name:

    lms_hss.rs

Abstract:

    File contains API for LMS signature validation
    Implementation follows the LMS specification and pseudocode from RFC 8554
    https://www.rfc-editor.org/rfc/rfc8554

--*/

use core::mem::MaybeUninit;

use crate::{sha256::Sha256Alg, Array4x8, CaliptraResult, Sha256, Sha256DigestOp};
use caliptra_error::CaliptraError;
use caliptra_lms_types::{
    LmotsAlgorithmType, LmsAlgorithmType, LmsIdentifier, LmsPublicKey, LmsSignature,
};
use zerocopy::{AsBytes, LittleEndian, U32};
use zeroize::Zeroize;

pub const D_PBLC: u16 = 0x8080;
pub const D_MESG: u16 = 0x8181;
pub const D_LEAF: u16 = 0x8282;
pub const D_INTR: u16 = 0x8383;

#[derive(Default, Debug)]
pub struct Lms {}

pub type Sha256Digest = HashValue<8>;
pub type Sha192Digest = HashValue<6>;

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LmsResult {
    Success = 0xCCCCCCCC,
    SigVerifyFailed = 0x33333333,
}

#[repr(transparent)]
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct HashValue<const N: usize>(pub [u32; N]);

impl<const N: usize> Default for HashValue<N> {
    fn default() -> Self {
        let data = [0u32; N];
        HashValue(data)
    }
}

impl<const N: usize> HashValue<N> {
    pub fn new(data: [u32; N]) -> Self {
        HashValue(data)
    }
}
impl<const N: usize> From<[U32<LittleEndian>; N]> for HashValue<N> {
    fn from(data: [U32<LittleEndian>; N]) -> Self {
        HashValue(swap_bytes(data))
    }
}

impl<const N: usize> From<&[u32; N]> for HashValue<N> {
    fn from(data: &[u32; N]) -> Self {
        HashValue(*data)
    }
}

impl From<[u32; 8]> for HashValue<6> {
    fn from(data: [u32; 8]) -> Self {
        let mut result = [0u32; 6];
        result[..6].copy_from_slice(&data[..6]);
        HashValue(result)
    }
}
impl From<[u8; 24]> for HashValue<6> {
    fn from(data: [u8; 24]) -> Self {
        let mut result = [0u32; 6];
        for i in 0..6 {
            result[i] = u32::from_be_bytes([
                data[i * 4],
                data[i * 4 + 1],
                data[i * 4 + 2],
                data[i * 4 + 3],
            ]);
        }
        HashValue(result)
    }
}

impl From<[u8; 32]> for HashValue<8> {
    fn from(data: [u8; 32]) -> Self {
        let mut result = [0u32; 8];
        for i in 0..8 {
            result[i] = u32::from_be_bytes([
                data[i * 4],
                data[i * 4 + 1],
                data[i * 4 + 2],
                data[i * 4 + 3],
            ]);
        }
        HashValue(result)
    }
}

impl<const N: usize> From<Array4x8> for HashValue<N> {
    fn from(data: Array4x8) -> Self {
        let mut result = [0u32; N];
        result[..N].copy_from_slice(&data.0[..N]);
        HashValue(result)
    }
}

impl<const N: usize> AsRef<[u32]> for HashValue<N> {
    fn as_ref(&self) -> &[u32] {
        &self.0
    }
}

fn swap_bytes<const N: usize>(b: [U32<LittleEndian>; N]) -> [u32; N] {
    let mut result = MaybeUninit::<[u32; N]>::uninit();
    let dest = result.as_mut_ptr() as *mut u32;
    #[allow(clippy::needless_range_loop)]
    for i in 0..N {
        unsafe { dest.add(i).write(b[i].get().swap_bytes()) }
    }
    unsafe { result.assume_init() }
}

#[derive(Debug)]
pub struct LmotsParameter {
    pub algorithm_name: LmotsAlgorithmType,
    pub n: u8,
    pub w: u8,
    pub p: u16,
    pub ls: u8,
}

const LMOTS_P: [LmotsParameter; 9] = [
    LmotsParameter {
        algorithm_name: LmotsAlgorithmType::LmotsReserved,
        n: 0,
        w: 0,
        p: 0,
        ls: 0,
    },
    LmotsParameter {
        algorithm_name: LmotsAlgorithmType::LmotsSha256N32W1,
        n: 32,
        w: 1,
        p: 265,
        ls: 7,
    },
    LmotsParameter {
        algorithm_name: LmotsAlgorithmType::LmotsSha256N32W2,
        n: 32,
        w: 2,
        p: 133,
        ls: 6,
    },
    LmotsParameter {
        algorithm_name: LmotsAlgorithmType::LmotsSha256N32W4,
        n: 32,
        w: 4,
        p: 67,
        ls: 4,
    },
    LmotsParameter {
        algorithm_name: LmotsAlgorithmType::LmotsSha256N32W8,
        n: 32,
        w: 8,
        p: 34,
        ls: 0,
    },
    LmotsParameter {
        algorithm_name: LmotsAlgorithmType::LmotsSha256N24W1,
        n: 24,
        w: 1,
        p: 200,
        ls: 8,
    },
    LmotsParameter {
        algorithm_name: LmotsAlgorithmType::LmotsSha256N24W2,
        n: 24,
        w: 2,
        p: 101,
        ls: 6,
    },
    LmotsParameter {
        algorithm_name: LmotsAlgorithmType::LmotsSha256N24W4,
        n: 24,
        w: 4,
        p: 51,
        ls: 4,
    },
    LmotsParameter {
        algorithm_name: LmotsAlgorithmType::LmotsSha256N24W8,
        n: 24,
        w: 8,
        p: 26,
        ls: 0,
    },
];

pub fn get_lmots_parameters(
    algo_type: LmotsAlgorithmType,
) -> CaliptraResult<&'static LmotsParameter> {
    for i in &LMOTS_P {
        if i.algorithm_name == algo_type {
            return Ok(i);
        }
    }
    Err(CaliptraError::DRIVER_LMS_INVALID_LMOTS_ALGO_TYPE)
}

pub fn get_lms_parameters(algo_type: LmsAlgorithmType) -> CaliptraResult<(u8, u8)> {
    match algo_type {
        LmsAlgorithmType::LmsSha256N32H5 => Ok((32, 5)),
        LmsAlgorithmType::LmsSha256N32H10 => Ok((32, 10)),
        LmsAlgorithmType::LmsSha256N32H15 => Ok((32, 15)),
        LmsAlgorithmType::LmsSha256N32H20 => Ok((32, 20)),
        LmsAlgorithmType::LmsSha256N32H25 => Ok((32, 25)),
        LmsAlgorithmType::LmsSha256N24H5 => Ok((24, 5)),
        LmsAlgorithmType::LmsSha256N24H10 => Ok((24, 10)),
        LmsAlgorithmType::LmsSha256N24H15 => Ok((24, 15)),
        LmsAlgorithmType::LmsSha256N24H20 => Ok((24, 20)),
        LmsAlgorithmType::LmsSha256N24H25 => Ok((24, 25)),
        _ => Err(CaliptraError::DRIVER_LMS_INVALID_LMS_ALGO_TYPE),
    }
}

impl Lms {
    // follows pseudo code at https://www.rfc-editor.org/rfc/rfc8554#section-3.1.3
    pub fn coefficient(&self, s: &[u8], i: usize, w: usize) -> CaliptraResult<u8> {
        let valid_w = matches!(w, 1 | 2 | 4 | 8);
        if !valid_w {
            return Err(CaliptraError::DRIVER_LMS_INVALID_WINTERNITS_PARAM);
        }
        let bitmask: u16 = (1 << (w)) - 1;
        let index = i * w / 8;
        if index >= s.len() {
            return Err(CaliptraError::DRIVER_LMS_INVALID_INDEX);
        }
        let b = s[index];

        // extra logic to avoid the divide by 0
        // which a good compiler would notice only happens when w is 0 and that portion of the
        // expression could be skipped
        let mut shift = 8;
        if w != 0 {
            shift = 8 - (w * (i % (8 / w)) + w);
        }

        // Rust errors if we try to shift off all of the bits off from a value
        // some implementations 0 fill, others do some other filling.
        // we make this be 0
        let mut rs = 0;
        if shift < 8 {
            rs = b >> shift;
        }
        let small_bitmask = bitmask as u8;
        Ok(small_bitmask & rs)
    }

    fn checksum(&self, algo_type: LmotsAlgorithmType, input_string: &[u8]) -> CaliptraResult<u16> {
        let params = get_lmots_parameters(algo_type)?;
        let mut sum = 0u16;
        let valid_w = matches!(params.w, 1 | 2 | 4 | 8);
        if !valid_w {
            return Err(CaliptraError::DRIVER_LMS_INVALID_WINTERNITS_PARAM);
        }
        let upper_bound = params.n as u16 * (8 / params.w as u16);
        let bitmask = (1 << params.w) - 1;
        for i in 0..upper_bound as usize {
            sum += bitmask - (self.coefficient(input_string, i, params.w as usize)? as u16);
        }
        let shifted = sum << params.ls;
        Ok(shifted)
    }

    pub fn hash_message<const N: usize>(
        &self,
        sha256_driver: &mut impl Sha256Alg,
        message: &[u8],
        lms_identifier: &LmsIdentifier,
        q: &[u8; 4],
        nonce: &[U32<LittleEndian>; N],
    ) -> CaliptraResult<HashValue<N>> {
        let mut digest = Array4x8::default();
        let mut hasher = sha256_driver.digest_init()?;
        hasher.update(lms_identifier)?;
        hasher.update(q)?;
        hasher.update(&D_MESG.to_be_bytes())?;
        hasher.update(nonce.as_bytes())?;
        hasher.update(message)?;
        hasher.finalize(&mut digest)?;
        Ok(HashValue::from(digest))
    }

    #[cfg(feature = "hw-latest")]
    pub fn hash_chain<const N: usize>(
        &self,
        sha256_driver: &mut impl Sha256Alg,
        wnt_prefix: &mut [u8; 55],
        coeff: u8,
        params: &LmotsParameter,
        tmp: &mut HashValue<N>,
    ) -> CaliptraResult<HashValue<N>> {
        const WNTZ_MODE_SHA256: u8 = 32;

        let iteration_count = ((1u16 << params.w) - 1) as u8;

        if coeff < iteration_count {
            let mut digest = Array4x8::default();
            let mut hasher = sha256_driver.digest_init()?;
            wnt_prefix[22] = coeff;
            let mut i = 23;
            for val in tmp.0.iter().take(N) {
                wnt_prefix[i..i + 4].clone_from_slice(&val.to_be_bytes());
                i += 4;
            }
            //set n_mode: 1 for n=32, and 0 for n=24
            let mut n_mode: bool = false;
            if params.n == WNTZ_MODE_SHA256 {
                n_mode = true;
            }
            hasher.update_wntz(&wnt_prefix[0..23 + N * 4], params.w, n_mode)?;
            hasher.finalize_wntz(&mut digest, params.w, n_mode)?;
            *tmp = HashValue::<N>::from(digest);
        }
        Ok(*tmp)
    }

    // This operation is accelerated in hardware by RTL1.1.
    #[cfg(not(feature = "hw-latest"))]
    pub fn hash_chain<const N: usize>(
        &self,
        sha256_driver: &mut impl Sha256Alg,
        wnt_prefix: &mut [u8; 55],
        coeff: u8,
        params: &LmotsParameter,
        tmp: &mut HashValue<N>,
    ) -> CaliptraResult<HashValue<N>> {
        let iteration_count = ((1u16 << params.w) - 1) as u8;

        for j in coeff..iteration_count {
            let mut digest = Array4x8::default();
            let mut hasher = sha256_driver.digest_init()?;
            wnt_prefix[22] = j;
            let mut i = 23;
            for val in tmp.0.iter().take(N) {
                wnt_prefix[i..i + 4].clone_from_slice(&val.to_be_bytes());
                i += 4;
            }
            hasher.update(&wnt_prefix[0..23 + N * 4])?;
            hasher.finalize(&mut digest)?;
            *tmp = HashValue::<N>::from(digest);
        }
        Ok(*tmp)
    }

    pub fn candidate_ots_signature<const N: usize, const P: usize>(
        &self,
        sha256_driver: &mut impl Sha256Alg,
        lms_identifier: &LmsIdentifier,
        algo_type: LmotsAlgorithmType,
        q: &[u8; 4],
        y: &[[U32<LittleEndian>; N]; P],
        message_digest: &HashValue<N>,
    ) -> CaliptraResult<HashValue<N>> {
        // wntz_mode: 1 for SHA256 with n=32, and 0 for SHA192 with n=24

        let params: &LmotsParameter = get_lmots_parameters(algo_type)?;

        if params.p as usize != P {
            return Err(CaliptraError::DRIVER_LMS_INVALID_PVALUE);
        }
        if params.n > 32 {
            return Err(CaliptraError::DRIVER_LMS_INVALID_HASH_WIDTH);
        }
        if params.n as usize != N * 4 {
            return Err(CaliptraError::DRIVER_LMS_INVALID_HASH_WIDTH);
        }
        let mut z = [HashValue::<N>::default(); P];

        let mut message_hash_with_checksum = [0u8; 34]; // 2 extra bytes for the checksum. needs to be N+2

        let mut i = 0;
        for val in message_digest.0.iter() {
            message_hash_with_checksum[i..i + 4].clone_from_slice(&val.to_be_bytes());
            i += 4;
        }

        let checksum_q = self.checksum(algo_type, &message_hash_with_checksum)?;
        let be_checksum = checksum_q.to_be_bytes();
        let checksum_offset = N * 4;
        message_hash_with_checksum[checksum_offset] = be_checksum[0];
        message_hash_with_checksum[checksum_offset + 1] = be_checksum[1];

        // In order to reduce the number of copies allocate a single block of memory
        // and update only the portions that update between iterations
        let mut hash_block = [0u8; 55];
        hash_block[0..16].clone_from_slice(lms_identifier);
        hash_block[16..20].clone_from_slice(q);

        for (i, val) in z.iter_mut().enumerate() {
            let a = self.coefficient(&message_hash_with_checksum, i, params.w as usize)?;
            let mut tmp = HashValue::<N>::from(y[i]);

            hash_block[20..22].clone_from_slice(&(i as u16).to_be_bytes());

            *val = self.hash_chain(sha256_driver, &mut hash_block, a, params, &mut tmp)?;
        }
        let mut digest = Array4x8::default();
        let mut hasher = sha256_driver.digest_init()?;
        hasher.update(lms_identifier)?;
        hasher.update(q)?;
        hasher.update(&D_PBLC.to_be_bytes())?;
        for t in z {
            for val in t.0.iter() {
                hasher.update(&val.to_be_bytes())?;
            }
        }
        hasher.finalize(&mut digest)?;
        let result = HashValue::<N>::from(digest);
        digest.0.zeroize();
        Ok(result)
    }

    ///  Note: Use this function only if glitch protection is not needed.
    ///        If glitch protection is needed, use `verify_lms_signature_cfi` instead.
    pub fn verify_lms_signature(
        &self,
        sha256_driver: &mut Sha256,
        input_string: &[u8],
        lms_public_key: &LmsPublicKey<6>,
        lms_sig: &LmsSignature<6, 51, 15>,
    ) -> CaliptraResult<LmsResult> {
        let mut candidate_key =
            self.verify_lms_signature_cfi(sha256_driver, input_string, lms_public_key, lms_sig)?;
        let result = if candidate_key != HashValue::from(lms_public_key.digest) {
            Ok(LmsResult::SigVerifyFailed)
        } else {
            Ok(LmsResult::Success)
        };
        candidate_key.0.zeroize();
        result
    }

    ///  Note: Use this function only if glitch protection is not needed.
    ///        If glitch protection is needed, use `verify_lms_signature_cfi_generic` instead.
    pub fn verify_lms_signature_generic<const N: usize, const P: usize, const H: usize>(
        &self,
        sha256_driver: &mut impl Sha256Alg,
        input_string: &[u8],
        lms_public_key: &LmsPublicKey<N>,
        lms_sig: &LmsSignature<N, P, H>,
    ) -> CaliptraResult<LmsResult> {
        let mut candidate_key = self.verify_lms_signature_cfi_generic(
            sha256_driver,
            input_string,
            lms_public_key,
            lms_sig,
        )?;
        let result = if candidate_key != HashValue::from(lms_public_key.digest) {
            Ok(LmsResult::SigVerifyFailed)
        } else {
            Ok(LmsResult::Success)
        };
        candidate_key.0.zeroize();
        result
    }

    // When callers from separate crates call a function like
    // verify_lms_signature_cfi_generic(), Rustc 1.70
    // may build multiple versions (depending on optimizer heuristics), even when all the
    // generic parameters are identical. This is bad, as it can bloat the binary and the
    // second copy violates the FIPS requirements that the same machine code be used for the
    // KAT as the actual implementation. To defend against it, we provide this non-generic
    // function that production firmware should call instead.
    #[inline(never)]
    pub fn verify_lms_signature_cfi(
        &self,
        sha256_driver: &mut Sha256,
        input_string: &[u8],
        lms_public_key: &LmsPublicKey<6>,
        lms_sig: &LmsSignature<6, 51, 15>,
    ) -> CaliptraResult<HashValue<6>> {
        self.verify_lms_signature_cfi_generic(sha256_driver, input_string, lms_public_key, lms_sig)
    }

    #[inline(always)]
    pub fn verify_lms_signature_cfi_generic<const N: usize, const P: usize, const H: usize>(
        &self,
        sha256_driver: &mut impl Sha256Alg,
        input_string: &[u8],
        lms_public_key: &LmsPublicKey<N>,
        lms_sig: &LmsSignature<N, P, H>,
    ) -> CaliptraResult<HashValue<N>> {
        if lms_sig.ots.ots_type != lms_public_key.otstype {
            return Err(CaliptraError::DRIVER_LMS_SIGNATURE_LMOTS_DOESNT_MATCH_PUBKEY_LMOTS);
        }

        let q_str = <[u8; 4]>::from(lms_sig.q);
        let (_, tree_height) = get_lms_parameters(lms_sig.tree_type)?;
        // Make sure the height of the tree matches the value of H this was compiled with
        if tree_height as usize != H {
            return Err(CaliptraError::DRIVER_LMS_INVALID_TREE_HEIGHT);
        }
        // Make sure the value of Q is valid for the tree height
        if lms_sig.q.get() >= 1 << H {
            return Err(CaliptraError::DRIVER_LMS_INVALID_Q_VALUE);
        }
        let mut node_num: u32 = (1 << tree_height) + lms_sig.q.get();
        if node_num >= 2 << tree_height {
            return Err(CaliptraError::DRIVER_LMS_INVALID_Q_VALUE);
        }
        let message_digest = self.hash_message(
            sha256_driver,
            input_string,
            &lms_public_key.id,
            &q_str,
            &lms_sig.ots.nonce,
        )?;
        let candidate_key = self.candidate_ots_signature(
            sha256_driver,
            &lms_public_key.id,
            lms_sig.ots.ots_type,
            &q_str,
            &lms_sig.ots.y,
            &message_digest,
        )?;

        match tree_height {
            5 => (),
            10 => (),
            15 => (),
            20 => (),
            25 => (),
            _ => return Err(CaliptraError::DRIVER_LMS_INVALID_TREE_HEIGHT),
        }

        let mut digest = Array4x8::default();
        let mut hasher = sha256_driver.digest_init()?;
        hasher.update(&lms_public_key.id)?;
        hasher.update(&node_num.to_be_bytes())?;
        hasher.update(&D_LEAF.to_be_bytes())?;
        for val in candidate_key.0.iter() {
            hasher.update(&val.to_be_bytes())?;
        }
        hasher.finalize(&mut digest)?;
        let mut temp = HashValue::<N>::from(digest);
        let mut i = 0;
        while node_num > 1 {
            let mut digest = Array4x8::default();
            let mut hasher = sha256_driver.digest_init()?;
            hasher.update(&lms_public_key.id)?;
            hasher.update(&(node_num / 2).to_be_bytes())?;
            hasher.update(&D_INTR.to_be_bytes())?;
            if node_num % 2 == 1 {
                hasher.update(
                    lms_sig
                        .tree_path
                        .get(i)
                        .ok_or(CaliptraError::DRIVER_LMS_PATH_OUT_OF_BOUNDS)?
                        .as_bytes(),
                )?;
            }
            for val in temp.0.iter() {
                hasher.update(&val.to_be_bytes())?;
            }
            if node_num % 2 == 0 {
                hasher.update(
                    lms_sig
                        .tree_path
                        .get(i)
                        .ok_or(CaliptraError::DRIVER_LMS_PATH_OUT_OF_BOUNDS)?
                        .as_bytes(),
                )?;
            }
            hasher.finalize(&mut digest)?;
            temp = HashValue::<N>::from(digest);
            node_num /= 2;
            i += 1;
            digest.0.zeroize();
        }
        digest.0.zeroize();
        Ok(temp)
    }
}
