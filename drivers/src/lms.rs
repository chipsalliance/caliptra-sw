/*++

Licensed under the Apache-2.0 license.

File Name:

    lms_hss.rs

Abstract:

    File contains API for LMS signature validation
    Implementation follows the LMS specification and pseudocode from RFC 8554
    https://www.rfc-editor.org/rfc/rfc8554

--*/

use crate::{Array4x8, Sha256, caliptra_err_def, CaliptraResult};

const D_PBLC: u16 = 0x8080;
const D_MESG: u16 = 0x8181;
const D_LEAF: u16 = 0x8282;
const D_INTR: u16 = 0x8383;

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
    }
}
#[derive(Default, Debug)]
pub struct Lms {}

pub type Sha256Digest = HashValue<32>;
pub type Sha192Digest = HashValue<24>;
pub type LmsIdentifier = [u8; 16];

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct HashValue<const N: usize>([u8; N]);

impl<const N: usize> Default for HashValue<N> {
    fn default() -> Self {
        let data = [0u8; N];
        HashValue(data)
    }
}

impl<const N: usize> HashValue<N> {
    pub fn new(data: [u8; N]) -> Self {
        HashValue(data)
    }
}
impl<const N: usize> From<[u8; N]> for HashValue<N> {
    fn from(data: [u8; N]) -> Self {
        HashValue(data)
    }
}

impl<const N: usize> From<&[u8; N]> for HashValue<N> {
    fn from(data: &[u8; N]) -> Self {
        HashValue(*data)
    }
}

impl From<[u8; 32]> for HashValue<24> {
    fn from(data: [u8; 32]) -> Self {
        let mut t = [0u8; 24];
        for index in 0..24 {
            t[index] = data[index];
        }
        HashValue(t)
    }
}

impl<const N: usize> From<Array4x8> for HashValue<N> {
    fn from(data: Array4x8) -> Self {
        let mut t = [0u8; N];
        for (index, word) in data.0.iter().enumerate() {
            if index >= (N/4) {
                break;
            }
            t[index*4..index*4+4].copy_from_slice(&word.to_be_bytes());
        }
        HashValue(t)
    }
}

impl<const N: usize> AsRef<[u8]> for HashValue<N> {
    fn as_ref(&self) -> &[u8] {
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
    pub nonce: [u8; N],
    pub y: [HashValue<N>; P],
}

#[derive(Debug)]
pub struct LmsSignature<'a, const N: usize, const P: usize> {
    pub q: u32,
    pub lmots_signature: LmotsSignature<N, P>,
    pub sig_type: LmsAlgorithmType,
    pub lms_path: &'a [HashValue<N>],
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


// maybe this should just return the 5 values and not a struct?
// similar to how the LMS parameters are returned
pub fn get_lmots_parameters(algo_type: &LmotsAlgorithmType) -> CaliptraResult<&'static LmotsParameter> {
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

// follows pseudo code at https://www.rfc-editor.org/rfc/rfc8554#section-3.1.3
fn coefficient(s: &[u8], i: usize, w: usize) -> u8 {
    let blah: u16 = (1 << (w)) - 1;
    let index = i * w / 8;
    let b = s[index as usize];

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
    let small_blah = blah as u8;
    return small_blah & rs;
}

fn checksum(algo_type: &LmotsAlgorithmType, input_string: &[u8]) -> CaliptraResult<u16> {
    let params = get_lmots_parameters(algo_type)?;
    let mut sum = 0u16;
    let upper_bound = params.n as u16 * (8 / params.w as u16);
    for i in 0..upper_bound as usize {
        sum = sum + ((1 << params.w) - 1)
            - (coefficient(input_string, i, params.w as usize) as u16);
    }
    let shifted = sum << params.ls;
    return Ok(shifted);
}

pub fn hash_message<const N: usize>(message :&[u8], lms_identifier :&LmsIdentifier, q: &[u8; 4], nonce: &[u8; N]) -> CaliptraResult<HashValue<N>> {
    let mut digest = Array4x8::default();
    let sha = Sha256::default();
    let mut hasher = sha.digest_init(&mut digest)?;
    hasher.update(lms_identifier)?;
    hasher.update(q)?;
    hasher.update(&D_MESG.to_be_bytes())?;
    hasher.update(nonce)?;
    hasher.update(message)?;
    hasher.finalize()?;
    return Ok(HashValue::from(digest));
}

pub fn candidate_ots_signature<const N: usize, const P: usize>(
    algo_type: &LmotsAlgorithmType,
    lms_identifier: &LmsIdentifier,
    q: &[u8; 4],
    signature: &LmotsSignature<N, P>,
    message_digest: &HashValue<N>,
) -> CaliptraResult<HashValue<N>> {
    if algo_type != &signature.ots_type {
        // println!("These have different ots types");
        raise_err!(InvalidLmotsAlgorithmType);
    }
    let params = get_lmots_parameters(algo_type)?;
    if params.p as usize != P {
        raise_err!(InvalidPValue);
    }
    if params.n > 34 {
        raise_err!(InvalidHashWidth);
    }
    if params.n as usize != N {
        raise_err!(InvalidHashWidth);
    }
    let mut z = [HashValue::<N>::default(); P];
    let mut message_hash_with_checksum = [0u8; 34]; // 2 extra bytes for the checksum. needs to be N+2
    for index in 0..N {
        message_hash_with_checksum[index] = message_digest.0[index];
    }

    let checksum_q = checksum(algo_type, &message_hash_with_checksum)?;
    let be_checksum = checksum_q.to_be_bytes();
    message_hash_with_checksum[N] = be_checksum[0];
    message_hash_with_checksum[N + 1] = be_checksum[1];

    // In order to reduce the number of copies allocate a single block of memory
    // and update only the portions that update between iterations
    let mut hash_block = [0u8; 55];
    hash_block[0..16].clone_from_slice(lms_identifier);
    hash_block[16..20].clone_from_slice(q);
    for i in 0..params.p as u16 {
        let a = coefficient(&message_hash_with_checksum, i as usize, params.w as usize);
        let mut tmp = signature.y[i as usize].clone();
        let t_upper: u16 = (1 << params.w) - 1; // subtract with overflow?
        let upper = t_upper as u8;
        hash_block[20..22].clone_from_slice(&i.to_be_bytes());
        for j in a..upper {
            let mut digest = Array4x8::default();
            let sha = Sha256::default();
            let mut hasher = sha.digest_init(&mut digest)?;
            hash_block[22] = j;
            hash_block[23..23+N].clone_from_slice(&tmp.0);
            hasher.update(&hash_block[0..23+N])?;
            hasher.finalize()?;
            tmp = HashValue::<N>::from(digest);
        }
        z[i as usize] = tmp;
    }
    let mut digest = Array4x8::default();
    let sha = Sha256::default();
    let mut hasher = sha.digest_init(&mut digest)?;
    hasher.update(lms_identifier)?;
    hasher.update(q)?;
    hasher.update(&D_PBLC.to_be_bytes())?;
    for t in z {
        hasher.update(&t.0)?;
    }
    hasher.finalize()?;
    let result = HashValue::<N>::from(digest);
    return Ok(result);

}


pub fn verify_lms_signature<const N: usize, const P: usize>(
    tree_height: u8,
    input_string: &[u8],
    lms_identifier: &LmsIdentifier,
    q: u32,
    lms_public_key: &HashValue<N>,
    lms_sig: &LmsSignature<N, P>,
) -> CaliptraResult<bool> {
    let q_str = q.to_be_bytes();
    let message_digest = hash_message(input_string, lms_identifier, &q_str, &lms_sig.lmots_signature.nonce)?;
    let candidate_key = candidate_ots_signature(
        &lms_sig.lmots_signature.ots_type,
        lms_identifier,
        &q_str,
        &lms_sig.lmots_signature,
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

    let mut node_num = (1 << tree_height) + q;
    let mut digest = Array4x8::default();
    let sha = Sha256::default();
    let mut hasher = sha.digest_init(&mut digest)?;
    hasher.update(lms_identifier)?;
    hasher.update(&node_num.to_be_bytes())?;
    hasher.update(&D_LEAF.to_be_bytes())?;
    hasher.update(&candidate_key.0)?;
    hasher.finalize()?;
    let mut temp = HashValue::<N>::from(digest);
    let mut i = 0;
    while node_num > 1 {
        if node_num % 2 == 1 {
            let mut digest = Array4x8::default();
            let sha = Sha256::default();
            let mut hasher = sha.digest_init(&mut digest)?;
            hasher.update(lms_identifier)?;
            hasher.update(&(node_num / 2).to_be_bytes())?;
            hasher.update(&D_INTR.to_be_bytes())?;
            hasher.update(&lms_sig.lms_path[i].0)?;
            hasher.update(&temp.0)?;
            hasher.finalize()?;
            temp = HashValue::<N>::from(digest);
        } else {
            let mut digest = Array4x8::default();
            let sha = Sha256::default();
            let mut hasher = sha.digest_init(&mut digest)?;
            hasher.update(lms_identifier)?;
            hasher.update(&(node_num / 2).to_be_bytes())?;
            hasher.update(&D_INTR.to_be_bytes())?;
            hasher.update(&temp.0)?;
            hasher.update(&lms_sig.lms_path[i].0)?;
            hasher.finalize()?;
            temp = HashValue::<N>::from(digest);
        }
        node_num = node_num / 2;
        i = i + 1;
    }
    let candidate_key = temp;
    if candidate_key != *lms_public_key {
        return Ok(false);
    }

    return Ok(true);
}
