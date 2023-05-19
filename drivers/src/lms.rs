/*++

Licensed under the Apache-2.0 license.

File Name:

    lms_hss.rs

Abstract:

    File contains API for LMS signature validation
    Implementation follows the LMS specification and pseudocode from RFC 8554
    https://www.rfc-editor.org/rfc/rfc8554

--*/

use crate::{caliptra_err_def, Array4x8, CaliptraResult, Sha256};

pub const D_PBLC: u16 = 0x8080;
pub const D_MESG: u16 = 0x8181;
pub const D_LEAF: u16 = 0x8282;
pub const D_INTR: u16 = 0x8383;

caliptra_err_def! {
    Lms,
    LmsErr
    {
        InvalidLmsAlgorithmType = 0x01,
        InvalidLmotsAlgorithmType = 0x02,
        InvalidWinternitzParameter = 0x03,
        InvalidPValue = 0x04,
        InvalidHashWidth = 0x05,
        InvalidTreeHeight = 0x06,
        InvalidQValue = 0x07,
        InvalidIndex = 0x08,
        PathOutOfBounds = 0x09,
        InvalidSignatureLength = 0x0a,
        InvalidPublicKeyLength = 0x0b,
        InvalidSignatureDepth = 0x0c,
    }
}
#[derive(Default, Debug)]
pub struct Lms {}

pub type Sha256Digest = HashValue<8>;
pub type Sha192Digest = HashValue<6>;
pub type LmsIdentifier = [u8; 16];

pub fn slice_to_num(buff: &[u8]) -> u32 {
    u32::from_be_bytes(buff.try_into().unwrap())
}

#[derive(Debug, Clone, Copy, PartialEq)]
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
impl<const N: usize> From<[u32; N]> for HashValue<N> {
    fn from(data: [u32; N]) -> Self {
        HashValue(data)
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

#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum LmotsAlgorithmType {
    LmotsReserved = 0,
    LmotsSha256N32W1 = 1,
    LmotsSha256N32W2 = 2,
    LmotsSha256N32W4 = 3,
    LmotsSha256N32W8 = 4,
    LmotsSha256N24W1 = 5,
    LmotsSha256N24W2 = 6,
    LmotsSha256N24W4 = 7,
    LmotsSha256N24W8 = 8,
}

// take in a u32 and return an LmotsAlgorithmType
pub fn lookup_lmots_algorithm_type(val: u32) -> Option<LmotsAlgorithmType> {
    match val {
        0 => Some(LmotsAlgorithmType::LmotsReserved),
        1 => Some(LmotsAlgorithmType::LmotsSha256N32W1),
        2 => Some(LmotsAlgorithmType::LmotsSha256N32W2),
        3 => Some(LmotsAlgorithmType::LmotsSha256N32W4),
        4 => Some(LmotsAlgorithmType::LmotsSha256N32W8),
        5 => Some(LmotsAlgorithmType::LmotsSha256N24W1),
        6 => Some(LmotsAlgorithmType::LmotsSha256N24W2),
        7 => Some(LmotsAlgorithmType::LmotsSha256N24W4),
        8 => Some(LmotsAlgorithmType::LmotsSha256N24W8),
        _ => None,
    }
}

#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum LmsAlgorithmType {
    LmsReserved = 0,
    LmsSha256N32H5 = 5,
    LmsSha256N32H10 = 6,
    LmsSha256N32H15 = 7,
    LmsSha256N32H20 = 8,
    LmsSha256N32H25 = 9,
    LmsSha256N24H5 = 10,
    LmsSha256N24H10 = 11,
    LmsSha256N24H15 = 12,
    LmsSha256N24H20 = 13,
    LmsSha256N24H25 = 14,
}

pub fn lookup_lms_algorithm_type(val: u32) -> Option<LmsAlgorithmType> {
    match val {
        0 => Some(LmsAlgorithmType::LmsReserved),
        5 => Some(LmsAlgorithmType::LmsSha256N32H5),
        6 => Some(LmsAlgorithmType::LmsSha256N32H10),
        7 => Some(LmsAlgorithmType::LmsSha256N32H15),
        8 => Some(LmsAlgorithmType::LmsSha256N32H20),
        9 => Some(LmsAlgorithmType::LmsSha256N32H25),
        10 => Some(LmsAlgorithmType::LmsSha256N24H5),
        11 => Some(LmsAlgorithmType::LmsSha256N24H10),
        12 => Some(LmsAlgorithmType::LmsSha256N24H15),
        13 => Some(LmsAlgorithmType::LmsSha256N24H20),
        14 => Some(LmsAlgorithmType::LmsSha256N24H25),
        _ => None,
    }
}

#[derive(Debug)]
pub struct LmotsSignature<const N: usize, const P: usize> {
    pub ots_type: LmotsAlgorithmType,
    pub nonce: [u32; N],
    pub y: [HashValue<N>; P],
}

#[derive(Debug)]
pub struct LmsSignature<const N: usize, const P: usize, const H: usize> {
    pub q: u32,
    pub ots_type: LmotsAlgorithmType,
    pub nonce: [u32; N],
    pub y: [HashValue<N>; P],
    pub lms_type: LmsAlgorithmType,
    pub path: [HashValue<N>; H],
}

#[derive(Debug)]
pub struct LmsPublicKey<const N: usize> {
    pub lms_identifier: LmsIdentifier,
    pub root_hash: HashValue<N>,
    pub lms_type: LmsAlgorithmType,
    pub lmots_type: LmotsAlgorithmType,
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
    algo_type: &LmotsAlgorithmType,
) -> CaliptraResult<&'static LmotsParameter> {
    for i in &LMOTS_P {
        if i.algorithm_name == *algo_type {
            return Ok(i);
        }
    }
    raise_err!(InvalidLmotsAlgorithmType)
}

pub fn get_lms_parameters(algo_type: &LmsAlgorithmType) -> CaliptraResult<(u8, u8)> {
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
        LmsAlgorithmType::LmsReserved => {
            raise_err!(InvalidLmsAlgorithmType)
        }
    }
}

pub fn parse_public_contents<const N: usize>(
    public_string: &[u8],
) -> CaliptraResult<LmsPublicKey<N>> {
    if public_string.len() != (24 + N * 4) {
        raise_err!(InvalidPublicKeyLength);
    }
    let mut pos = 0;
    let lms_type = lookup_lms_algorithm_type(slice_to_num(&public_string[pos..pos + 4]))
        .ok_or(err_u32!(InvalidLmsAlgorithmType))?;
    pos += 4;

    let lmots_type = lookup_lmots_algorithm_type(slice_to_num(&public_string[pos..pos + 4]))
        .ok_or(err_u32!(InvalidLmotsAlgorithmType))?;
    pos += 4;

    let (hash_width, _) = get_lms_parameters(&lms_type)?;
    if hash_width as usize != N * 4 {
        raise_err!(InvalidHashWidth);
    }

    let mut lms_identifier = [0u8; 16];
    lms_identifier.copy_from_slice(&public_string[pos..pos + 16]);
    pos += 16;

    let mut temp = [0u32; N];
    //temp.copy_from_slice(&public_string[pos..pos + N]);

    for t in temp.iter_mut().take(N) {
        *t = slice_to_num(&public_string[pos..pos + 4]);
        pos += 4;
    }

    let public_hash = HashValue::<N>::from(temp);

    let pk = LmsPublicKey {
        lms_type,
        lmots_type,
        lms_identifier,
        root_hash: public_hash,
    };
    Ok(pk)
}

pub fn parse_signature_contents<const N: usize, const P: usize, const H: usize>(
    signature: &[u8],
) -> CaliptraResult<LmsSignature<N, P, H>> {
    if signature.len() < 8 {
        raise_err!(InvalidSignatureLength);
    }
    let mut pos = 0;
    let q = slice_to_num(&signature[pos..pos + 4]);
    pos += 4;

    let ots_type = lookup_lmots_algorithm_type(slice_to_num(&signature[pos..pos + 4]))
        .ok_or(err_u32!(InvalidLmotsAlgorithmType))?;
    pos += 4;
    let lmots_params = get_lmots_parameters(&ots_type)?;
    if lmots_params.n as usize != N * 4 {
        raise_err!(InvalidHashWidth);
    }
    if lmots_params.p as usize != P {
        raise_err!(InvalidPValue);
    }

    let signature_size_before_path = 8 + N * 4 + (lmots_params.p as usize * N * 4) + 4;
    if signature.len() < signature_size_before_path {
        raise_err!(InvalidSignatureLength);
    }

    let mut nonce = [0u32; N];
    for i in nonce.iter_mut().take(N) {
        *i = slice_to_num(&signature[pos..pos + 4]);
        pos += 4;
    }

    let mut y = [HashValue::<N>::default(); P];
    for t in y.iter_mut().take(P) {
        let mut tmp = [0u32; N];
        for tt in tmp.iter_mut().take(N) {
            *tt = slice_to_num(&signature[pos..pos + 4]);
            pos += 4;
        }
        *t = HashValue::<N>::from(tmp);
    }
    let lms_type = lookup_lms_algorithm_type(slice_to_num(&signature[pos..pos + 4]))
        .ok_or(err_u32!(InvalidLmsAlgorithmType))?;
    pos += 4;

    let (hash_width, height) = get_lms_parameters(&lms_type)?;

    if N * 4 != hash_width as usize {
        raise_err!(InvalidHashWidth);
    }

    if height as usize != H {
        raise_err!(InvalidSignatureDepth);
    }

    if (H * N * 4) + pos > signature.len() {
        raise_err!(InvalidSignatureDepth);
    }

    let mut path = [HashValue::<N>::default(); H];
    for t in path.iter_mut().take(H) {
        let mut tmp = [0u32; N];
        for tt in tmp.iter_mut().take(N) {
            *tt = slice_to_num(&signature[pos..pos + 4]);
            pos += 4;
        }
        *t = HashValue::<N>::from(tmp);
    }
    let lms_sig = LmsSignature {
        q,
        ots_type,
        nonce,
        y,
        lms_type,
        path,
    };
    Ok(lms_sig)
}

impl Lms {
    // follows pseudo code at https://www.rfc-editor.org/rfc/rfc8554#section-3.1.3
    pub fn coefficient(&self, s: &[u8], i: usize, w: usize) -> CaliptraResult<u8> {
        let valid_w = matches!(w, 1 | 2 | 4 | 8);
        if !valid_w {
            raise_err!(InvalidWinternitzParameter)
        }
        let bitmask: u16 = (1 << (w)) - 1;
        let index = i * w / 8;
        if index >= s.len() {
            raise_err!(InvalidIndex)
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

    fn checksum(&self, algo_type: &LmotsAlgorithmType, input_string: &[u8]) -> CaliptraResult<u16> {
        let params = get_lmots_parameters(algo_type)?;
        let mut sum = 0u16;
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
        message: &[u8],
        lms_identifier: &LmsIdentifier,
        q: &[u8; 4],
        nonce: &[u32; N],
    ) -> CaliptraResult<HashValue<N>> {
        let mut digest = Array4x8::default();
        let sha = Sha256::default();
        let mut hasher = sha.digest_init(&mut digest)?;
        hasher.update(lms_identifier)?;
        hasher.update(q)?;
        hasher.update(&D_MESG.to_be_bytes())?;
        //hasher.update(nonce)?;
        for i in nonce.iter() {
            hasher.update(&i.to_be_bytes())?;
        }
        hasher.update(message)?;
        hasher.finalize()?;
        Ok(HashValue::from(digest))
    }

    pub fn candidate_ots_signature<const N: usize, const P: usize>(
        &self,
        lms_identifier: &LmsIdentifier,
        algo_type: &LmotsAlgorithmType,
        q: &[u8; 4],
        y: &[HashValue<N>; P],
        message_digest: &HashValue<N>,
    ) -> CaliptraResult<HashValue<N>> {
        let params = get_lmots_parameters(algo_type)?;
        if params.p as usize != P {
            raise_err!(InvalidPValue);
        }
        if params.n > 32 {
            raise_err!(InvalidHashWidth);
        }
        if params.n as usize != N * 4 {
            raise_err!(InvalidHashWidth);
        }
        let mut z = [HashValue::<N>::default(); P];

        let mut message_hash_with_checksum = [0u8; 34]; // 2 extra bytes for the checksum. needs to be N+2

        let mut i = 0;
        for val in message_digest.0.iter().take(N) {
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
        for (i, val) in z.iter_mut().enumerate().take(P) {
            let a = self.coefficient(&message_hash_with_checksum, i, params.w as usize)?;
            let mut tmp = y[i];
            let t_upper: u16 = (1 << params.w) - 1; // subtract with overflow?
            let upper = t_upper as u8;
            hash_block[20..22].clone_from_slice(&(i as u16).to_be_bytes());
            for j in a..upper {
                let mut digest = Array4x8::default();
                let sha = Sha256::default();
                let mut hasher = sha.digest_init(&mut digest)?;
                hash_block[22] = j;
                //hash_block[23..23 + N].clone_from_slice(&tmp.0);
                let mut i = 23;
                for val in tmp.0.iter().take(N) {
                    hash_block[i..i + 4].clone_from_slice(&val.to_be_bytes());
                    i += 4;
                }
                hasher.update(&hash_block[0..23 + N * 4])?;
                hasher.finalize()?;
                tmp = HashValue::<N>::from(digest);
            }
            *val = tmp;
        }
        let mut digest = Array4x8::default();
        let sha = Sha256::default();
        let mut hasher = sha.digest_init(&mut digest)?;
        hasher.update(lms_identifier)?;
        hasher.update(q)?;
        hasher.update(&D_PBLC.to_be_bytes())?;
        for t in z {
            //hasher.update(&t.0)?;
            for val in t.0.iter() {
                hasher.update(&val.to_be_bytes())?;
            }
        }
        hasher.finalize()?;
        let result = HashValue::<N>::from(digest);
        Ok(result)
    }

    pub fn verify_lms_signature<const N: usize, const P: usize, const H: usize>(
        &self,
        input_string: &[u8],
        lms_public_key: &LmsPublicKey<N>,
        lms_sig: &LmsSignature<N, P, H>,
    ) -> CaliptraResult<bool> {
        let q_str = lms_sig.q.to_be_bytes();
        let (_, tree_height) = get_lms_parameters(&lms_sig.lms_type)?;
        let mut node_num: u32 = (1 << tree_height) + lms_sig.q;
        if node_num > 2 << tree_height {
            raise_err!(InvalidQValue);
        }
        let message_digest = self.hash_message(
            input_string,
            &lms_public_key.lms_identifier,
            &q_str,
            &lms_sig.nonce,
        )?;
        let candidate_key = self.candidate_ots_signature(
            &lms_public_key.lms_identifier,
            &lms_sig.ots_type,
            &q_str,
            &lms_sig.y,
            &message_digest,
        )?;

        match tree_height {
            5 => (),
            10 => (),
            15 => (),
            20 => (),
            25 => (),
            _ => raise_err!(InvalidTreeHeight),
        }

        let mut digest = Array4x8::default();
        let sha = Sha256::default();
        let mut hasher = sha.digest_init(&mut digest)?;
        hasher.update(&lms_public_key.lms_identifier)?;
        hasher.update(&node_num.to_be_bytes())?;
        hasher.update(&D_LEAF.to_be_bytes())?;
        //hasher.update(&candidate_key.0)?;
        for val in candidate_key.0.iter() {
            hasher.update(&val.to_be_bytes())?;
        }
        hasher.finalize()?;
        let mut temp = HashValue::<N>::from(digest);
        let mut i = 0;
        while node_num > 1 {
            if node_num % 2 == 1 {
                let mut digest = Array4x8::default();
                let sha = Sha256::default();
                let mut hasher = sha.digest_init(&mut digest)?;
                hasher.update(&lms_public_key.lms_identifier)?;
                hasher.update(&(node_num / 2).to_be_bytes())?;
                hasher.update(&D_INTR.to_be_bytes())?;
                //hasher.update(&lms_sig.lms_path.get(i).ok_or(err_u32!(PathOutOfBounds))?.0)?;
                for val in lms_sig
                    .path
                    .get(i)
                    .ok_or(err_u32!(PathOutOfBounds))?
                    .0
                    .iter()
                    .take(N)
                {
                    hasher.update(&val.to_be_bytes())?;
                }
                //hasher.update(&temp.0)?;
                for val in temp.0.iter().take(N) {
                    hasher.update(&val.to_be_bytes())?;
                }
                hasher.finalize()?;
                temp = HashValue::<N>::from(digest);
            } else {
                let mut digest = Array4x8::default();
                let sha = Sha256::default();
                let mut hasher = sha.digest_init(&mut digest)?;
                hasher.update(&lms_public_key.lms_identifier)?;
                hasher.update(&(node_num / 2).to_be_bytes())?;
                hasher.update(&D_INTR.to_be_bytes())?;
                //hasher.update(&temp.0)?;
                for val in temp.0.iter() {
                    hasher.update(&val.to_be_bytes())?;
                }
                //hasher.update(&lms_sig.lms_path[i].0)?;
                //hasher.update(&lms_sig.lms_path.get(i).ok_or(err_u32!(PathOutOfBounds))?.0)?;
                for val in lms_sig
                    .path
                    .get(i)
                    .ok_or(err_u32!(PathOutOfBounds))?
                    .0
                    .iter()
                    .take(N)
                {
                    hasher.update(&val.to_be_bytes())?;
                }
                hasher.finalize()?;
                temp = HashValue::<N>::from(digest);
            }
            node_num /= 2;
            i += 1;
        }
        let candidate_key = temp;
        if candidate_key != lms_public_key.root_hash {
            return Ok(false);
        }
        Ok(true)
    }
}
