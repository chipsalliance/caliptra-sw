// Licensed under the Apache-2.0 license

use crate::ct::{ct_ge, ct_if, ct_lt};
use caliptra_shake::{Shake128, Shake256};
use core::convert::TryInto;

/* Public API Constants */
pub const MLDSA87_PRIVATE_SEED_BYTES: usize = 32;
pub const MLDSA87_RANDOMIZER_BYTES: usize = 32;
pub const MLDSA87_PUBLIC_KEY_BYTES: usize = 2592;
pub const MLDSA87_SIGNATURE_BYTES: usize = 4627;

/* Arithmetic parameters. */
const K_PRIME: u32 = 8380417;
const K_PRIME_NEG_INVERSE: u32 = 4236238847;
const K_DROPPED_BITS: u32 = 13;
const K_HALF_PRIME: u32 = (K_PRIME - 1) / 2;
const K_DEGREE: usize = 256;
const K_INVERSE_DEGREE_MONTGOMERY: u32 = 41978;

/* Common sizes. */
const K_RHO_BYTES: usize = 32;
const K_SIGMA_BYTES: usize = 64;
const K_K_BYTES: usize = 32;
const K_TR_BYTES: usize = 64;
const K_MU_BYTES: usize = 64;
const K_RHO_PRIME_BYTES: usize = 64;

/* ML-DSA-87 parameters. */
const TAU: usize = 60;
const LAMBDA_BYTES: usize = 256 / 8;
const GAMMA1: u32 = 1 << 19;
const K_GAMMA_2: u32 = (K_PRIME - 1) / 32;
const BETA: u32 = 120;
const OMEGA: usize = 75;

/* Fundamental types. */

#[derive(Clone, Copy)]
pub struct Scalar {
    pub c: [u32; K_DEGREE],
}

impl Default for Scalar {
    fn default() -> Self {
        Scalar {
            c: [0u32; K_DEGREE],
        }
    }
}

#[derive(Default, Clone, Copy)]
pub struct Vector8 {
    pub v: [Scalar; 8],
}

#[derive(Default, Clone, Copy)]
pub struct Vector7 {
    pub v: [Scalar; 7],
}

/* Complex types. */

pub struct PublicKey {
    pub rho: [u8; K_RHO_BYTES],
    pub t1: Vector8,
    pub public_key_hash: [u8; K_TR_BYTES],
}

pub struct PrivateKey {
    pub rho: [u8; K_RHO_BYTES],
    pub k: [u8; K_K_BYTES],
    pub public_key_hash: [u8; K_TR_BYTES],
    pub s1_ntt: Vector7,
    pub s2_ntt: Vector8,
    pub t0_ntt: Vector8,
}

pub struct Signature {
    pub c_tilde: [u8; 2 * LAMBDA_BYTES],
    pub z: Vector7,
    pub h: Vector8,
}

/* Arithmetic. */

static NTT_ROOTS_MONTGOMERY: [u32; K_DEGREE] = [
    4193792, 25847, 5771523, 7861508, 237124, 7602457, 7504169, 466468, 1826347, 2353451, 8021166,
    6288512, 3119733, 5495562, 3111497, 2680103, 2725464, 1024112, 7300517, 3585928, 7830929,
    7260833, 2619752, 6271868, 6262231, 4520680, 6980856, 5102745, 1757237, 8360995, 4010497,
    280005, 2706023, 95776, 3077325, 3530437, 6718724, 4788269, 5842901, 3915439, 4519302, 5336701,
    3574422, 5512770, 3539968, 8079950, 2348700, 7841118, 6681150, 6736599, 3505694, 4558682,
    3507263, 6239768, 6779997, 3699596, 811944, 531354, 954230, 3881043, 3900724, 5823537, 2071892,
    5582638, 4450022, 6851714, 4702672, 5339162, 6927966, 3475950, 2176455, 6795196, 7122806,
    1939314, 4296819, 7380215, 5190273, 5223087, 4747489, 126922, 3412210, 7396998, 2147896,
    2715295, 5412772, 4686924, 7969390, 5903370, 7709315, 7151892, 8357436, 7072248, 7998430,
    1349076, 1852771, 6949987, 5037034, 264944, 508951, 3097992, 44288, 7280319, 904516, 3958618,
    4656075, 8371839, 1653064, 5130689, 2389356, 8169440, 759969, 7063561, 189548, 4827145,
    3159746, 6529015, 5971092, 8202977, 1315589, 1341330, 1285669, 6795489, 7567685, 6940675,
    5361315, 4499357, 4751448, 3839961, 2091667, 3407706, 2316500, 3817976, 5037939, 2244091,
    5933984, 4817955, 266997, 2434439, 7144689, 3513181, 4860065, 4621053, 7183191, 5187039,
    900702, 1859098, 909542, 819034, 495491, 6767243, 8337157, 7857917, 7725090, 5257975, 2031748,
    3207046, 4823422, 7855319, 7611795, 4784579, 342297, 286988, 5942594, 4108315, 3437287,
    5038140, 1735879, 203044, 2842341, 2691481, 5790267, 1265009, 4055324, 1247620, 2486353,
    1595974, 4613401, 1250494, 2635921, 4832145, 5386378, 1869119, 1903435, 7329447, 7047359,
    1237275, 5062207, 6950192, 7929317, 1312455, 3306115, 6417775, 7100756, 1917081, 5834105,
    7005614, 1500165, 777191, 2235880, 3406031, 7838005, 5548557, 6709241, 6533464, 5796124,
    4656147, 594136, 4603424, 6366809, 2432395, 2454455, 8215696, 1957272, 3369112, 185531,
    7173032, 5196991, 162844, 1616392, 3014001, 810149, 1652634, 4686184, 6581310, 5341501,
    3523897, 3866901, 269760, 2213111, 7404533, 1717735, 472078, 7953734, 1723600, 6577327,
    1910376, 6712985, 7276084, 8119771, 4546524, 5441381, 6144432, 7959518, 6094090, 183443,
    7403526, 1612842, 4834730, 7826001, 3919660, 8332111, 7018208, 3937738, 1400424, 7534263,
    1976782,
];

#[inline(always)]
fn reduce_once(x: u32) -> u32 {
    ct_if(ct_lt(x, K_PRIME), x, x.wrapping_sub(K_PRIME))
}

#[inline(always)]
fn abs_signed(x: u32) -> u32 {
    ct_if(ct_lt(x, 0x80000000), x, 0u32.wrapping_sub(x))
}

#[inline(always)]
fn abs_mod_prime(x: u32) -> u32 {
    ct_if(ct_lt(K_HALF_PRIME, x), K_PRIME.wrapping_sub(x), x)
}

#[inline(always)]
fn maximum(x: u32, y: u32) -> u32 {
    ct_if(ct_lt(x, y), y, x)
}

#[inline(always)]
fn mod_sub(a: u32, b: u32) -> u32 {
    reduce_once(K_PRIME.wrapping_add(a).wrapping_sub(b))
}

fn scalar_add(out: &mut Scalar, lhs: &Scalar, rhs: &Scalar) {
    for i in 0..K_DEGREE {
        out.c[i] = reduce_once(lhs.c[i].wrapping_add(rhs.c[i]));
    }
}

fn scalar_sub(out: &mut Scalar, lhs: &Scalar, rhs: &Scalar) {
    for i in 0..K_DEGREE {
        out.c[i] = mod_sub(lhs.c[i], rhs.c[i]);
    }
}

fn reduce_montgomery(x: u64) -> u32 {
    let a = (x.wrapping_mul(K_PRIME_NEG_INVERSE as u64) as u32) as u64;
    let b = x.wrapping_add(a.wrapping_mul(K_PRIME as u64));
    let c = (b >> 32) as u32;
    reduce_once(c)
}

fn scalar_mul(out: &mut Scalar, lhs: &Scalar, rhs: &Scalar) {
    for i in 0..K_DEGREE {
        out.c[i] = reduce_montgomery((lhs.c[i] as u64).wrapping_mul(rhs.c[i] as u64));
    }
}

fn scalar_mul_add(out: &mut Scalar, a: &Scalar, b: &Scalar, c: &Scalar) {
    for i in 0..K_DEGREE {
        out.c[i] = reduce_once(a.c[i].wrapping_add(reduce_montgomery(
            (b.c[i] as u64).wrapping_mul(c.c[i] as u64),
        )));
    }
}

fn scalar_ntt(s: &mut Scalar) {
    let mut offset = K_DEGREE;
    let mut step = 1;
    while step < K_DEGREE {
        offset >>= 1;
        let mut k = 0;
        for i in 0..step {
            let step_root = NTT_ROOTS_MONTGOMERY[step + i];
            for j in k..(k + offset) {
                let even = s.c[j];
                let odd =
                    reduce_montgomery((step_root as u64).wrapping_mul(s.c[j + offset] as u64));
                s.c[j] = reduce_once(odd.wrapping_add(even));
                s.c[j + offset] = mod_sub(even, odd);
            }
            k += 2 * offset;
        }
        step <<= 1;
    }
}

fn scalar_inverse_ntt(s: &mut Scalar) {
    let mut step = K_DEGREE;
    let mut offset = 1;
    while offset < K_DEGREE {
        step >>= 1;
        let mut k = 0;
        for i in 0..step {
            let step_root = K_PRIME.wrapping_sub(NTT_ROOTS_MONTGOMERY[step + (step - 1 - i)]);
            for j in k..(k + offset) {
                let even = s.c[j];
                let odd = s.c[j + offset];
                s.c[j] = reduce_once(odd.wrapping_add(even));
                s.c[j + offset] = reduce_montgomery(
                    (step_root as u64)
                        .wrapping_mul((K_PRIME.wrapping_add(even).wrapping_sub(odd)) as u64),
                );
            }
            k += 2 * offset;
        }
        offset <<= 1;
    }
    for i in 0..K_DEGREE {
        s.c[i] =
            reduce_montgomery((s.c[i] as u64).wrapping_mul(K_INVERSE_DEGREE_MONTGOMERY as u64));
    }
}

fn vector8_zero(out: &mut Vector8) {
    *out = Vector8::default();
}

fn vector8_add(out: &mut Vector8, lhs: &Vector8, rhs: &Vector8) {
    for i in 0..8 {
        scalar_add(&mut out.v[i], &lhs.v[i], &rhs.v[i]);
    }
}

fn vector7_add(out: &mut Vector7, lhs: &Vector7, rhs: &Vector7) {
    for i in 0..7 {
        scalar_add(&mut out.v[i], &lhs.v[i], &rhs.v[i]);
    }
}

fn vector8_sub(out: &mut Vector8, lhs: &Vector8, rhs: &Vector8) {
    for i in 0..8 {
        scalar_sub(&mut out.v[i], &lhs.v[i], &rhs.v[i]);
    }
}

fn vector8_mul_scalar(out: &mut Vector8, lhs: &Vector8, rhs: &Scalar) {
    for i in 0..8 {
        scalar_mul(&mut out.v[i], &lhs.v[i], rhs);
    }
}

fn vector7_mul_scalar(out: &mut Vector7, lhs: &Vector7, rhs: &Scalar) {
    for i in 0..7 {
        scalar_mul(&mut out.v[i], &lhs.v[i], rhs);
    }
}

fn vector8_ntt(a: &mut Vector8) {
    for i in 0..8 {
        scalar_ntt(&mut a.v[i]);
    }
}

fn vector7_ntt(a: &mut Vector7) {
    for i in 0..7 {
        scalar_ntt(&mut a.v[i]);
    }
}

fn vector8_inverse_ntt(a: &mut Vector8) {
    for i in 0..8 {
        scalar_inverse_ntt(&mut a.v[i]);
    }
}

fn vector7_inverse_ntt(a: &mut Vector7) {
    for i in 0..7 {
        scalar_inverse_ntt(&mut a.v[i]);
    }
}

/* Rounding and hints. */

fn power2_round(r1: &mut u32, r0: &mut u32, r: u32) {
    *r1 = r >> K_DROPPED_BITS;
    *r0 = r.wrapping_sub(*r1 << K_DROPPED_BITS);

    let r0_adjusted = mod_sub(*r0, 1 << K_DROPPED_BITS);
    let r1_adjusted = *r1 + 1;

    let cond = ct_lt((1 << (K_DROPPED_BITS - 1)) as u32, *r0);
    *r0 = ct_if(cond, r0_adjusted, *r0);
    *r1 = ct_if(cond, r1_adjusted, *r1);
}

fn scale_power2_round(out: &mut u32, r1: u32) {
    *out = r1 << K_DROPPED_BITS;
}

fn high_bits(x: u32) -> u32 {
    let mut r1 = (x.wrapping_add(127)) >> 7;
    r1 = (r1.wrapping_mul(1025).wrapping_add(1 << 21)) >> 22;
    r1 & 15
}

fn decompose(r1: &mut u32, r0: &mut i32, r: u32) {
    *r1 = high_bits(r);

    let mut temp = r as i32;
    temp = temp.wrapping_sub((*r1 as i32).wrapping_mul(2).wrapping_mul(K_GAMMA_2 as i32));
    temp = temp.wrapping_sub((((K_HALF_PRIME as i32).wrapping_sub(temp)) >> 31) & (K_PRIME as i32));
    *r0 = temp;
}

fn low_bits(x: u32) -> i32 {
    let mut r1 = 0;
    let mut r0 = 0;
    decompose(&mut r1, &mut r0, x);
    r0
}

fn make_hint(ct0: u32, cs2: u32, w: u32) -> i32 {
    let r_plus_z = mod_sub(w, cs2);
    let r = reduce_once(r_plus_z.wrapping_add(ct0));
    (high_bits(r) != high_bits(r_plus_z)) as i32
}

fn use_hint(h: u32, r: u32) -> u32 {
    let mut r1 = 0;
    let mut r0 = 0;
    decompose(&mut r1, &mut r0, r);

    if h != 0 {
        if r0 > 0 {
            return (r1 + 1) & 15;
        } else {
            return (r1.wrapping_sub(1)) & 15;
        }
    }
    r1
}

fn scalar_power2_round(s1: &mut Scalar, s0: &mut Scalar, s: &Scalar) {
    for i in 0..K_DEGREE {
        power2_round(&mut s1.c[i], &mut s0.c[i], s.c[i]);
    }
}

fn scalar_scale_power2_round(out: &mut Scalar, in_val: &Scalar) {
    for i in 0..K_DEGREE {
        scale_power2_round(&mut out.c[i], in_val.c[i]);
    }
}

fn scalar_high_bits(out: &mut Scalar, in_val: &Scalar) {
    for i in 0..K_DEGREE {
        out.c[i] = high_bits(in_val.c[i]);
    }
}

fn scalar_low_bits(out: &mut Scalar, in_val: &Scalar) {
    for i in 0..K_DEGREE {
        out.c[i] = low_bits(in_val.c[i]) as u32;
    }
}

fn scalar_max(max: &mut u32, s: &Scalar) {
    for i in 0..K_DEGREE {
        let abs = abs_mod_prime(s.c[i]);
        *max = maximum(*max, abs);
    }
}

fn scalar_max_signed(max: &mut u32, s: &Scalar) {
    for i in 0..K_DEGREE {
        let abs = abs_signed(s.c[i]);
        *max = maximum(*max, abs);
    }
}

fn scalar_make_hint(out: &mut Scalar, ct0: &Scalar, cs2: &Scalar, w: &Scalar) {
    for i in 0..K_DEGREE {
        out.c[i] = make_hint(ct0.c[i], cs2.c[i], w.c[i]) as u32;
    }
}

fn scalar_use_hint(out: &mut Scalar, h: &Scalar, r: &Scalar) {
    for i in 0..K_DEGREE {
        out.c[i] = use_hint(h.c[i], r.c[i]);
    }
}

fn vector8_power2_round(t1: &mut Vector8, t0: &mut Vector8, t: &Vector8) {
    for i in 0..8 {
        scalar_power2_round(&mut t1.v[i], &mut t0.v[i], &t.v[i]);
    }
}

fn vector8_scale_power2_round(out: &mut Vector8, in_val: &Vector8) {
    for i in 0..8 {
        scalar_scale_power2_round(&mut out.v[i], &in_val.v[i]);
    }
}

fn vector8_high_bits(out: &mut Vector8, in_val: &Vector8) {
    for i in 0..8 {
        scalar_high_bits(&mut out.v[i], &in_val.v[i]);
    }
}

fn vector8_low_bits(out: &mut Vector8, in_val: &Vector8) {
    for i in 0..8 {
        scalar_low_bits(&mut out.v[i], &in_val.v[i]);
    }
}

fn vector8_max(a: &Vector8) -> u32 {
    let mut max = 0;
    for i in 0..8 {
        scalar_max(&mut max, &a.v[i]);
    }
    max
}

fn vector7_max(a: &Vector7) -> u32 {
    let mut max = 0;
    for i in 0..7 {
        scalar_max(&mut max, &a.v[i]);
    }
    max
}

fn vector8_max_signed(a: &Vector8) -> u32 {
    let mut max = 0;
    for i in 0..8 {
        scalar_max_signed(&mut max, &a.v[i]);
    }
    max
}

fn vector8_count_ones(a: &Vector8) -> usize {
    let mut count = 0;
    for i in 0..8 {
        for j in 0..K_DEGREE {
            count += a.v[i].c[j] as usize;
        }
    }
    count
}

fn vector8_make_hint(out: &mut Vector8, ct0: &Vector8, cs2: &Vector8, w: &Vector8) {
    for i in 0..8 {
        scalar_make_hint(&mut out.v[i], &ct0.v[i], &cs2.v[i], &w.v[i]);
    }
}

fn vector8_use_hint(out: &mut Vector8, h: &Vector8, r: &Vector8) {
    for i in 0..8 {
        scalar_use_hint(&mut out.v[i], &h.v[i], &r.v[i]);
    }
}

/* Bit packing. */

fn scalar_encode_4(out: &mut [u8], s: &Scalar) {
    for (i, out_byte) in out.iter_mut().enumerate().take(K_DEGREE / 2) {
        let a = s.c[2 * i];
        let b = s.c[2 * i + 1];
        *out_byte = (a | (b << 4)) as u8;
    }
}

fn scalar_encode_10(out: &mut [u8], s: &Scalar) {
    for i in 0..(K_DEGREE / 4) {
        let a = s.c[4 * i];
        let b = s.c[4 * i + 1];
        let c = s.c[4 * i + 2];
        let d = s.c[4 * i + 3];
        out[5 * i] = a as u8;
        out[5 * i + 1] = ((a >> 8) | (b << 2)) as u8;
        out[5 * i + 2] = ((b >> 6) | (c << 4)) as u8;
        out[5 * i + 3] = ((c >> 4) | (d << 6)) as u8;
        out[5 * i + 4] = (d >> 2) as u8;
    }
}

fn scalar_encode_signed_20_19(out: &mut [u8], s: &Scalar) {
    let k_max = 1u32 << 19;
    for i in 0..(K_DEGREE / 4) {
        let mut a = mod_sub(k_max, s.c[4 * i]);
        let mut b = mod_sub(k_max, s.c[4 * i + 1]);
        let c = mod_sub(k_max, s.c[4 * i + 2]);
        let d = mod_sub(k_max, s.c[4 * i + 3]);
        a |= b << 20;
        b >>= 12;
        b |= c << 8;
        b |= d << 28;
        let d_shifted = d >> 4;

        out[10 * i..10 * i + 4].copy_from_slice(&a.to_le_bytes());
        out[10 * i + 4..10 * i + 8].copy_from_slice(&b.to_le_bytes());
        out[10 * i + 8..10 * i + 10].copy_from_slice(&(d_shifted as u16).to_le_bytes());
    }
}

fn scalar_decode_10(out: &mut Scalar, in_val: &[u8]) {
    for i in 0..(K_DEGREE / 4) {
        let v = u32::from_le_bytes(in_val[5 * i..5 * i + 4].try_into().unwrap());
        out.c[4 * i] = v & 0x3FF;
        out.c[4 * i + 1] = (v >> 10) & 0x3FF;
        out.c[4 * i + 2] = (v >> 20) & 0x3FF;
        out.c[4 * i + 3] = (v >> 30) | ((in_val[5 * i + 4] as u32) << 2);
    }
}

fn scalar_decode_signed_20_19(out: &mut Scalar, in_val: &[u8]) {
    let k_max = 1u32 << 19;
    let k20_bits = (1u32 << 20) - 1;

    for i in 0..(K_DEGREE / 4) {
        let a = u32::from_le_bytes(in_val[10 * i..10 * i + 4].try_into().unwrap());
        let b = u32::from_le_bytes(in_val[10 * i + 4..10 * i + 8].try_into().unwrap());
        let c = u16::from_le_bytes(in_val[10 * i + 8..10 * i + 10].try_into().unwrap());

        out.c[i * 4] = mod_sub(k_max, a & k20_bits);
        out.c[i * 4 + 1] = mod_sub(k_max, (a >> 20) | ((b & 0xFF) << 12));
        out.c[i * 4 + 2] = mod_sub(k_max, (b >> 8) & k20_bits);
        out.c[i * 4 + 3] = mod_sub(k_max, (b >> 28) | ((c as u32) << 4));
    }
}

/* Expansion functions. */

fn scalar_from_keccak_vartime(out: &mut Scalar, derived_seed: &[u8]) {
    let mut shake128 = Shake128::new();
    shake128.absorb(derived_seed);

    let mut done = 0;
    while done < K_DEGREE {
        let mut block = [0u8; 168];
        shake128.squeeze(&mut block);
        let mut i = 0;
        while i < block.len() && done < K_DEGREE {
            let value = (block[i] as u32)
                | ((block[i + 1] as u32) << 8)
                | (((block[i + 2] as u32) & 0x7F) << 16);
            if value < K_PRIME {
                out.c[done] = value;
                done += 1;
            }
            i += 3;
        }
    }
}

fn coefficient_from_nibble_2(mut nibble: u32, result: &mut u32) -> bool {
    if nibble < 15 {
        nibble = nibble.wrapping_sub(5u32.wrapping_mul((205u32.wrapping_mul(nibble)) >> 10));
        *result = mod_sub(2, nibble);
        return true;
    }
    false
}

fn scalar_uniform_2(out: &mut Scalar, derived_seed: &[u8]) {
    let mut shake256 = Shake256::new();
    shake256.absorb(derived_seed);

    let mut done = 0;
    while done < K_DEGREE {
        let mut block = [0u8; 136];
        shake256.squeeze(&mut block);
        for byte in &block {
            if done >= K_DEGREE {
                break;
            }
            let t0 = (byte & 0x0F) as u32;
            let t1 = (byte >> 4) as u32;

            let mut v = 0;
            if coefficient_from_nibble_2(t0, &mut v) {
                out.c[done] = v;
                done += 1;
            }
            if done < K_DEGREE && coefficient_from_nibble_2(t1, &mut v) {
                out.c[done] = v;
                done += 1;
            }
        }
    }
}

fn scalar_sample_mask(out: &mut Scalar, derived_seed: &[u8]) {
    let mut buf = [0u8; 640];
    let mut shake256 = Shake256::new();
    shake256.absorb(derived_seed);
    shake256.squeeze(&mut buf);

    scalar_decode_signed_20_19(out, &buf);
}

fn scalar_sample_in_ball_vartime(out: &mut Scalar, seed: &[u8], len: usize) {
    let mut shake256 = Shake256::new();
    shake256.absorb(&seed[..len]);

    let mut block = [0u8; 136];
    shake256.squeeze(&mut block);

    let mut signs = u64::from_le_bytes(block[0..8].try_into().unwrap());
    let mut offset = 8;

    *out = Scalar::default();
    for i in (K_DEGREE - TAU)..K_DEGREE {
        let mut byte: usize;
        loop {
            if offset == 136 {
                shake256.squeeze(&mut block);
                offset = 0;
            }

            byte = block[offset] as usize;
            offset += 1;
            if byte <= i {
                break;
            }
        }

        out.c[i] = out.c[byte];
        out.c[byte] = mod_sub(1, (2u32).wrapping_mul((signs & 1) as u32));
        signs >>= 1;
    }
}

fn matrix87_expand_mul(out: &mut Vector8, rho: &[u8; K_RHO_BYTES], a: &Vector7) {
    let mut derived_seed = [0u8; K_RHO_BYTES + 2];
    derived_seed[..K_RHO_BYTES].copy_from_slice(rho);
    vector8_zero(out);
    for i in 0..8 {
        for j in 0..7 {
            let mut m_ij = Scalar::default();
            derived_seed[K_RHO_BYTES + 1] = i as u8;
            derived_seed[K_RHO_BYTES] = j as u8;
            scalar_from_keccak_vartime(&mut m_ij, &derived_seed);
            let out_vi_copy = out.v[i];
            scalar_mul_add(&mut out.v[i], &out_vi_copy, &m_ij, &a.v[j]);
        }
    }
}

fn vectors78_expand_short(s1: &mut Vector7, s2: &mut Vector8, sigma: &[u8; K_SIGMA_BYTES]) {
    let mut derived_seed = [0u8; K_SIGMA_BYTES + 2];
    derived_seed[..K_SIGMA_BYTES].copy_from_slice(sigma);
    derived_seed[K_SIGMA_BYTES] = 0;
    derived_seed[K_SIGMA_BYTES + 1] = 0;
    for i in 0..7 {
        scalar_uniform_2(&mut s1.v[i], &derived_seed);
        derived_seed[K_SIGMA_BYTES] = derived_seed[K_SIGMA_BYTES].wrapping_add(1);
    }
    for i in 0..8 {
        scalar_uniform_2(&mut s2.v[i], &derived_seed);
        derived_seed[K_SIGMA_BYTES] = derived_seed[K_SIGMA_BYTES].wrapping_add(1);
    }
}

fn vector7_expand_mask(out: &mut Vector7, seed: &[u8; K_RHO_PRIME_BYTES], kappa: usize) {
    let mut derived_seed = [0u8; K_RHO_PRIME_BYTES + 2];
    derived_seed[..K_RHO_PRIME_BYTES].copy_from_slice(seed);
    for i in 0..7 {
        let index = kappa + i;
        derived_seed[K_RHO_PRIME_BYTES] = (index & 0xFF) as u8;
        derived_seed[K_RHO_PRIME_BYTES + 1] = ((index >> 8) & 0xFF) as u8;
        scalar_sample_mask(&mut out.v[i], &derived_seed);
    }
}

/* Encoding. */

fn vector8_encode_4(out: &mut [u8], a: &Vector8) {
    for i in 0..8 {
        scalar_encode_4(&mut out[i * 4 * K_DEGREE / 8..], &a.v[i]);
    }
}

fn vector8_encode_10(out: &mut [u8], a: &Vector8) {
    for i in 0..8 {
        scalar_encode_10(&mut out[i * 10 * K_DEGREE / 8..], &a.v[i]);
    }
}

fn vector8_decode_10(out: &mut Vector8, in_val: &[u8]) {
    for i in 0..8 {
        scalar_decode_10(&mut out.v[i], &in_val[i * 10 * K_DEGREE / 8..]);
    }
}

fn vector7_encode_signed_20_19(out: &mut [u8], a: &Vector7) {
    for i in 0..7 {
        scalar_encode_signed_20_19(&mut out[i * 20 * K_DEGREE / 8..], &a.v[i]);
    }
}

fn vector7_decode_signed_20_19(out: &mut Vector7, in_val: &[u8]) {
    for i in 0..7 {
        scalar_decode_signed_20_19(&mut out.v[i], &in_val[i * 20 * K_DEGREE / 8..]);
    }
}

fn w1_encode(out: &mut [u8; 128 * 8], w1: &Vector8) {
    vector8_encode_4(out, w1);
}

fn hint_bit_pack(out: &mut [u8; OMEGA + 8], h: &Vector8) {
    out.fill(0);
    let mut index = 0;
    for i in 0..8 {
        for j in 0..K_DEGREE {
            if h.v[i].c[j] != 0 {
                out[index] = j as u8;
                index += 1;
            }
        }
        out[OMEGA + i] = index as u8;
    }
}

fn hint_bit_unpack(h: &mut Vector8, in_val: &[u8; OMEGA + 8]) -> bool {
    vector8_zero(h);
    let mut index = 0;
    for i in 0..8 {
        let limit = in_val[OMEGA + i] as usize;
        if limit < index || limit > OMEGA {
            return false;
        }
        let mut last: i32 = -1;
        while index < limit {
            let byte = in_val[index] as usize;
            index += 1;
            if last >= 0 && byte <= last as usize {
                return false;
            }
            last = byte as i32;
            h.v[i].c[byte] = 1;
        }
    }
    for val in in_val.iter().take(OMEGA).skip(index) {
        if *val != 0 {
            return false;
        }
    }
    true
}

fn encode_public_key(out: &mut [u8; MLDSA87_PUBLIC_KEY_BYTES], pub_key: &PublicKey) {
    out[..K_RHO_BYTES].copy_from_slice(&pub_key.rho);
    vector8_encode_10(&mut out[K_RHO_BYTES..], &pub_key.t1);
}

fn decode_public_key(pub_key: &mut PublicKey, in_val: &[u8; MLDSA87_PUBLIC_KEY_BYTES]) {
    pub_key.rho.copy_from_slice(&in_val[..K_RHO_BYTES]);
    vector8_decode_10(&mut pub_key.t1, &in_val[K_RHO_BYTES..]);

    let mut shake256 = Shake256::new();
    shake256.absorb(in_val);
    shake256.squeeze(&mut pub_key.public_key_hash);
}

fn encode_signature(out: &mut [u8; MLDSA87_SIGNATURE_BYTES], sign: &Signature) {
    out[..2 * LAMBDA_BYTES].copy_from_slice(&sign.c_tilde);
    vector7_encode_signed_20_19(&mut out[2 * LAMBDA_BYTES..], &sign.z);

    let hint_out: &mut [u8; OMEGA + 8] = (&mut out
        [2 * LAMBDA_BYTES + 640 * 7..2 * LAMBDA_BYTES + 640 * 7 + OMEGA + 8])
        .try_into()
        .unwrap();
    hint_bit_pack(hint_out, &sign.h);
}

fn decode_signature(sign: &mut Signature, in_val: &[u8; MLDSA87_SIGNATURE_BYTES]) -> bool {
    sign.c_tilde.copy_from_slice(&in_val[..2 * LAMBDA_BYTES]);
    vector7_decode_signed_20_19(&mut sign.z, &in_val[2 * LAMBDA_BYTES..]);

    let hint_in: &[u8; OMEGA + 8] = (&in_val
        [2 * LAMBDA_BYTES + 640 * 7..2 * LAMBDA_BYTES + 640 * 7 + OMEGA + 8])
        .try_into()
        .unwrap();
    hint_bit_unpack(&mut sign.h, hint_in)
}

/* Main algorithms. */

fn generate_key_internal(
    out_encoded_public_key: &mut [u8; MLDSA87_PUBLIC_KEY_BYTES],
    priv_key: &mut PrivateKey,
    entropy: &[u8; MLDSA87_PRIVATE_SEED_BYTES],
) {
    let mut augmented_entropy = [0u8; MLDSA87_PRIVATE_SEED_BYTES + 2];
    augmented_entropy[..MLDSA87_PRIVATE_SEED_BYTES].copy_from_slice(entropy);
    augmented_entropy[MLDSA87_PRIVATE_SEED_BYTES] = 8;
    augmented_entropy[MLDSA87_PRIVATE_SEED_BYTES + 1] = 7;

    let mut expanded_seed = [0u8; K_RHO_BYTES + K_SIGMA_BYTES + K_K_BYTES];
    let mut shake256 = Shake256::new();
    shake256.absorb(&augmented_entropy);
    shake256.squeeze(&mut expanded_seed);

    let rho = &expanded_seed[..K_RHO_BYTES];
    let sigma = &expanded_seed[K_RHO_BYTES..K_RHO_BYTES + K_SIGMA_BYTES];
    let k = &expanded_seed[K_RHO_BYTES + K_SIGMA_BYTES..];

    priv_key.rho.copy_from_slice(rho);
    priv_key.k.copy_from_slice(k);

    vectors78_expand_short(
        &mut priv_key.s1_ntt,
        &mut priv_key.s2_ntt,
        sigma.try_into().unwrap(),
    );
    vector7_ntt(&mut priv_key.s1_ntt);

    let mut t = Vector8::default();
    matrix87_expand_mul(&mut t, rho.try_into().unwrap(), &priv_key.s1_ntt);
    vector8_inverse_ntt(&mut t);
    let t_copy = t;
    vector8_add(&mut t, &t_copy, &priv_key.s2_ntt);

    let rho_bytes: [u8; K_RHO_BYTES] = rho.try_into().unwrap();
    let mut pub_key = PublicKey {
        rho: rho_bytes,
        t1: Vector8::default(),
        public_key_hash: [0u8; K_TR_BYTES],
    };
    vector8_power2_round(&mut pub_key.t1, &mut priv_key.t0_ntt, &t);

    vector8_ntt(&mut priv_key.s2_ntt);
    vector8_ntt(&mut priv_key.t0_ntt);

    encode_public_key(out_encoded_public_key, &pub_key);

    let mut shake256 = Shake256::new();
    shake256.absorb(out_encoded_public_key);
    shake256.squeeze(&mut priv_key.public_key_hash);
}

fn generate_priv_internal(
    priv_key: &mut PrivateKey,
    private_key_seed: &[u8; MLDSA87_PRIVATE_SEED_BYTES],
) {
    let mut encoded_public_key = [0u8; MLDSA87_PUBLIC_KEY_BYTES];
    generate_key_internal(&mut encoded_public_key, priv_key, private_key_seed);
}

fn sign_internal(
    out_encoded_signature: &mut [u8; MLDSA87_SIGNATURE_BYTES],
    priv_key: &PrivateKey,
    msg: &[u8],
    context: &[u8],
    randomizer: &[u8; MLDSA87_RANDOMIZER_BYTES],
) {
    let mut mu = [0u8; K_MU_BYTES];
    let mut shake256 = Shake256::new();
    shake256.absorb(&priv_key.public_key_hash);
    let context_prefix = [0u8, context.len() as u8];
    shake256.absorb(&context_prefix);
    shake256.absorb(context);
    shake256.absorb(msg);
    shake256.squeeze(&mut mu);

    let mut rho_prime = [0u8; K_RHO_PRIME_BYTES];
    let mut shake256 = Shake256::new();
    shake256.absorb(&priv_key.k);
    shake256.absorb(randomizer);
    shake256.absorb(&mu);
    shake256.squeeze(&mut rho_prime);

    let mut sign = Signature {
        c_tilde: [0u8; 2 * LAMBDA_BYTES],
        z: Vector7::default(),
        h: Vector8::default(),
    };
    let mut w1 = Vector8::default();

    // We use a union in C, in Rust we can just use separate variables or reuse if needed.
    // Given stack space is usually not as tight in Rust unless specified, but let's be careful.
    let mut cs1 = Vector7::default();
    let mut cs2 = Vector8::default();

    let mut kappa = 0;
    loop {
        vector7_expand_mask(&mut sign.z, &rho_prime, kappa);
        vector7_ntt(&mut sign.z);

        let mut w = Vector8::default();
        matrix87_expand_mul(&mut w, &priv_key.rho, &sign.z);
        vector8_inverse_ntt(&mut w);

        vector8_high_bits(&mut w1, &w);
        let mut w1_encoded = [0u8; 128 * 8];
        w1_encode(&mut w1_encoded, &w1);

        let mut shake256 = Shake256::new();
        shake256.absorb(&mu);
        shake256.absorb(&w1_encoded);
        shake256.squeeze(&mut sign.c_tilde);

        let mut c_ntt = Scalar::default();
        scalar_sample_in_ball_vartime(&mut c_ntt, &sign.c_tilde, sign.c_tilde.len());
        scalar_ntt(&mut c_ntt);

        vector7_mul_scalar(&mut cs1, &priv_key.s1_ntt, &c_ntt);
        vector7_inverse_ntt(&mut cs1);

        let mut y = Vector7::default();
        vector7_expand_mask(&mut y, &rho_prime, kappa);
        vector7_add(&mut sign.z, &y, &cs1);

        vector8_mul_scalar(&mut cs2, &priv_key.s2_ntt, &c_ntt);
        vector8_inverse_ntt(&mut cs2);

        let mut r0 = Vector8::default();
        vector8_sub(&mut r0, &w, &cs2);
        let r0_copy = r0;
        vector8_low_bits(&mut r0, &r0_copy);

        let z_max = vector7_max(&sign.z);
        let r0_max = vector8_max_signed(&r0);

        if (ct_ge(z_max, GAMMA1.wrapping_sub(BETA)) | ct_ge(r0_max, K_GAMMA_2.wrapping_sub(BETA)))
            != 0
        {
            kappa += 7;
            continue;
        }

        let mut ct0 = Vector8::default();
        vector8_mul_scalar(&mut ct0, &priv_key.t0_ntt, &c_ntt);
        vector8_inverse_ntt(&mut ct0);
        vector8_make_hint(&mut sign.h, &ct0, &cs2, &w);

        let ct0_max = vector8_max(&ct0);
        let h_ones = vector8_count_ones(&sign.h);

        if (ct_ge(ct0_max, K_GAMMA_2) | ct_lt(OMEGA as u32, h_ones as u32)) != 0 {
            kappa += 7;
            continue;
        }

        encode_signature(out_encoded_signature, &sign);
        return;
    }
}

fn verify_internal(
    pub_key: &PublicKey,
    encoded_signature: &[u8; MLDSA87_SIGNATURE_BYTES],
    msg: &[u8],
    context: &[u8],
) -> bool {
    let mut sign = Signature {
        c_tilde: [0u8; 2 * LAMBDA_BYTES],
        z: Vector7::default(),
        h: Vector8::default(),
    };
    if !decode_signature(&mut sign, encoded_signature) {
        return false;
    }

    let z_max = vector7_max(&sign.z);
    vector7_ntt(&mut sign.z);

    let mut mu = [0u8; K_MU_BYTES];
    let mut shake256 = Shake256::new();
    shake256.absorb(&pub_key.public_key_hash);
    let context_prefix = [0u8, context.len() as u8];
    shake256.absorb(&context_prefix);
    shake256.absorb(context);
    shake256.absorb(msg);
    shake256.squeeze(&mut mu);

    let mut c_ntt = Scalar::default();
    scalar_sample_in_ball_vartime(&mut c_ntt, &sign.c_tilde, sign.c_tilde.len());
    scalar_ntt(&mut c_ntt);

    let mut az_ntt = Vector8::default();
    matrix87_expand_mul(&mut az_ntt, &pub_key.rho, &sign.z);

    let mut ct1_ntt = Vector8::default();
    vector8_scale_power2_round(&mut ct1_ntt, &pub_key.t1);
    vector8_ntt(&mut ct1_ntt);
    let ct1_ntt_copy = ct1_ntt;
    vector8_mul_scalar(&mut ct1_ntt, &ct1_ntt_copy, &c_ntt);

    let mut w1 = Vector8::default();
    vector8_sub(&mut w1, &az_ntt, &ct1_ntt);
    vector8_inverse_ntt(&mut w1);

    let w1_copy = w1;
    vector8_use_hint(&mut w1, &sign.h, &w1_copy);
    let mut w1_encoded = [0u8; 128 * 8];
    w1_encode(&mut w1_encoded, &w1);

    let mut c_tilde = [0u8; 2 * LAMBDA_BYTES];
    let mut shake256 = Shake256::new();
    shake256.absorb(&mu);
    shake256.absorb(&w1_encoded);
    shake256.squeeze(&mut c_tilde);

    z_max < (GAMMA1 - BETA) && c_tilde == sign.c_tilde
}

/* Public API. */

pub fn mldsa87_pub_from_seed(
    out_encoded_public_key: &mut [u8; MLDSA87_PUBLIC_KEY_BYTES],
    private_key_seed: &[u8; MLDSA87_PRIVATE_SEED_BYTES],
) {
    let mut priv_key = PrivateKey {
        rho: [0u8; K_RHO_BYTES],
        k: [0u8; K_K_BYTES],
        public_key_hash: [0u8; K_TR_BYTES],
        s1_ntt: Vector7::default(),
        s2_ntt: Vector8::default(),
        t0_ntt: Vector8::default(),
    };
    generate_key_internal(out_encoded_public_key, &mut priv_key, private_key_seed);
}

pub fn mldsa87_sign(
    out_encoded_signature: &mut [u8; MLDSA87_SIGNATURE_BYTES],
    private_key_seed: &[u8; MLDSA87_PRIVATE_SEED_BYTES],
    randomizer: &[u8; MLDSA87_RANDOMIZER_BYTES],
    msg: &[u8],
) {
    let mut priv_key = PrivateKey {
        rho: [0u8; K_RHO_BYTES],
        k: [0u8; K_K_BYTES],
        public_key_hash: [0u8; K_TR_BYTES],
        s1_ntt: Vector7::default(),
        s2_ntt: Vector8::default(),
        t0_ntt: Vector8::default(),
    };
    generate_priv_internal(&mut priv_key, private_key_seed);
    sign_internal(out_encoded_signature, &priv_key, msg, &[], randomizer);
}

pub fn mldsa87_sign_deterministic(
    out_encoded_signature: &mut [u8; MLDSA87_SIGNATURE_BYTES],
    private_key_seed: &[u8; MLDSA87_PRIVATE_SEED_BYTES],
    msg: &[u8],
) {
    let mut priv_key = PrivateKey {
        rho: [0u8; K_RHO_BYTES],
        k: [0u8; K_K_BYTES],
        public_key_hash: [0u8; K_TR_BYTES],
        s1_ntt: Vector7::default(),
        s2_ntt: Vector8::default(),
        t0_ntt: Vector8::default(),
    };
    generate_priv_internal(&mut priv_key, private_key_seed);
    let randomizer = [0u8; MLDSA87_RANDOMIZER_BYTES];
    sign_internal(out_encoded_signature, &priv_key, msg, &[], &randomizer);
}

pub fn mldsa87_verify(
    encoded_public_key: &[u8; MLDSA87_PUBLIC_KEY_BYTES],
    encoded_signature: &[u8; MLDSA87_SIGNATURE_BYTES],
    msg: &[u8],
) -> bool {
    let mut pub_key = PublicKey {
        rho: [0u8; K_RHO_BYTES],
        t1: Vector8::default(),
        public_key_hash: [0u8; K_TR_BYTES],
    };
    decode_public_key(&mut pub_key, encoded_public_key);
    verify_internal(&pub_key, encoded_signature, msg, &[])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mldsa87_keygen() {
        let seed_hex = "6e2afcc2b5bf76728b340ddde141499e181a94e8dc41289216cd714fa4495b9f";
        let exp_pk_hex = "6cfc915f1042d9d957a0d15b5921aac38a47c8d9c543f643d10afb7774df090dcb5bc49e\
             e0ca8a7ab268789a8844b1e8ed2ebdf25ec48a01514269b2c90131f3812eee9e6590111c\
             49e19219808663aa11c2a5d80c3b9395c53dc766ae729e68779cf983fb3d5da260edcee8\
             cb2bb781ace648643ea4b49fbc1f6aea79b1779303130eea185c606c2eb2ce218b334409\
             a992ffd330718334cc44a67699ae5d910a96bb4d91f80e10c80feadd9611d414c502c954\
             0f0ab911419fc802c9f11cb8990f181d6dc4304eee39bd15b797693ca5491f1e5577a8aa\
             0902451a15db650b2eadeb61c8f2b1b9d8647537c2a7217e2bc19d9160b49cc72ef889f4\
             7f48bd7902dbc8f6693522397a498d07c543dc6a4c9a2fd4565f2ab20662a3ac77becc08\
             1fe75c78cbe6d47377eb0ed3da700ca7715ed55818898d748d533c888598170600db2271\
             5a48cc98810994b5ff349b64171bec0b5afe9f2a372b472318dc2655435ba72c686ad5ab\
             232c856c869224922eaa5bdf61b2432902e7563439f7d381214a8c41bd3d6989a101f6ca\
             3c350905393663ac924a1c3d4ed25eba365ddc1401dbe04f5b5c99fb402a7c0cd8489af3\
             2e727e3ee5da6dbeab1597113eb9630abcd5902956edf8973ab4fcd8e483bb4a804c9967\
             dad7c9e336db2ac4ce454cf016a5bf4c6bbc6d739d7681d0ec45f095d84160dc4bea33e2\
             fc1bc466f2f0a7ce0a236ed1abcd7b0b6826166af5c9ca9c5f41debb64bb106ff6e4c381\
             5aae96118291bdceaf7e1f10cec6353ad9d3f3e9bbae13dca3de419345db193c0051a3e6\
             73f60591d5d9813bac831b59ddae9cbb462efec85857164bafed35422b3b6452a0937a84\
             d515713e52cbf1f7b55671dfd8c92c2ecd553e31e74d936db04f416271b47b917b8ec1e3\
             14a01a8464579c3c9f606bc1b7c050737b9b0bbdb841ac1578826d0ce97389cf82486adc\
             55d294a7d783f69d345580e1915131f6c8448d4b70e1692da868daaf6844b841d956f1a6\
             9aad7cdf3b5c227971c6f40a7b83cb234b8654ae6ce4579fec7019ab1662a6571eef0523\
             4f4da6d77d5df3f1146ed3ee82397a785575fd089f77132e33f697b4a135a58d79d2d94b\
             ab7255c3cb7f8b0e2c6a7938a7193cf66f07e46aadee2816f0656af1ddd04dd5077d41f9\
             99e5bc9001cd2b98a5068e69f5828534ad7dd0d0acd0d08aef910e607175645b671d1c18\
             baf57c0d38a2d41d3347cf895b22821412975051048ca2902326e26a7e7be45d51ae35f9\
             2ded0b1b522eed853002cef38a40a9d70255caf83268c055d690448cef057ee1f4259041\
             300225e2f8c3e721f351f2cbdc733fa7d9c9f3c4e53e65f6d4ceea48e3ae5b4102c94b61\
             e4665ffb10af3c61aabe3326eced24a34de1422a7dd86cbbbc47efa0af1253b170d1037f\
             c0a3718bbe909a4c849b56585893d9fea0cd847d6daaba5f263903d62b204e646554945d\
             abe93577d7775759075ff27768c9b9f2cef6bb477cc3317f138db7981993b3b7d7f4a052\
             41ebb5fe12bfd4f463398bc5796b3d716d904fc5892730873c35ab9dca2f15ea1d77efb7\
             30bd928299460ab31c581d3906d835afb1323a52b051fd76ef6341d49c9d420a69d8f90b\
             7c8e8f5fc65d1287aa8cc326f3eafe1a90dbab182205a7cc9d802d5c4f330262cb8ceb5c\
             e2e4c7e61c1af4caf72a482f90824e41b909424c13b542d08d53393ae8d019f99dac9439\
             7ffeeacc68ca2bb0230cf285b5c5cebfe0c81181bc81cc1f5c9c2612350242f7dc45aa1f\
             c6725625663feef808529b3f267bd2a3ed09f48cb5ada5b960f07d86d7302b1a867d4d97\
             2aa7e92ddda5111938c1382473a106e544fea36428fd37d36ee44c62353e955813cd8e59\
             97c865223bd9fa34fb7cd52af94b9d1f289f0793bb596621e1058a4b191da27067866cd5\
             f89ef497d289349acf9d8fbee468be56192dec05faf87ae873077bbb3ffaf061bf387756\
             877776731a07242dc049cc335df0cffd7da1687f472364a57ea0efdd74ebdaf147ade25e\
             99c56c9fbb63150777c3734a81031899b06dddb2f1702ef4c23db9a54e5d792b181a7e07\
             0aef9608f9158c8267d56560b214ec0d66ce689ef5d1a328baf10e8b635ac8fde7bf69d6\
             c007ebb319899390aab1511bd6a5b81481d6ba2b3d403d1547fb5e2015d8b234c75fbea9\
             fd9e245b07987e93547c9f5516a72d29bedddc6f563c733770bc8eb46e8f02640a04d942\
             f342222b398fbf01958b9f6fa26f743ff6a8b290defb88bb46bf9f74e6b487416d2d63fd\
             6034369209e574b19ce2edb2796830cc8dc0409150be447504ae84517890dc5a7a66d892\
             bc4aab6ab781be696ea6f094e9325f03bed3545a28ffdeda10d3c65093d1cc73dabb787a\
             d3fe389e73886d475489b1315521615650f023d54250c340243d0a54e9c126886fb5b496\
             e460aea57c110cf346b0ae246d2f25e12e95b3f73d499f2166608a16d6f9a08278d9e4cc\
             d69103e6ce9a40069d5c68bb3974a621b703fdcfe5003f6f2184bde8c0c7ba27d5ac88f2\
             b6f03d3355624bb34209dba9de37d5fe02dd416f2b26ed9ffe9a2e9d108649154103d413\
             aff806f885b70c46b289cedbd70d8fd5447b7e13baceba2c23aadf59f3ae4299d9cb5d19\
             8af98015cb949d56ef6fed4dc690c30a1c78bb0f4a92ae1c885ebffe67eed5ad462cec9e\
             9b106bbf4b35770b087d2ab0ac3dd8feda49a3503ca8fa5c734257099392ec32fa6db3db\
             ec36c51ae9fafb886f7ce42eb9cae6657b5772041d8a5eb40e643f43e70531fc04cd3af8\
             66ef34e9c75a4e6fdd65fa5e61c34d08462713899214b11638bdd79533391172f937e4ee\
             688788d917b12efff28b745b24f4ff08501f5e14c288843a5e428082375484b68fdb9160\
             4cd5c28dcb88f542d3fe90cf0380651bdeea22bfc2ae72b9bf659560d148a0e42861ef6d\
             78b039cf37fe2c6e22a17dc8775b585da9fd45e2b78d62080484939a31eb10af0173502d\
             5616309c7c5f7a8e3163f0925308fd7407f46c6e9fe5c9f4cba6f17c91f048bf45fdf1b9\
             1d18e5c3de450e144206abce528e1e3cb26f210283a11ac5bf56c0519d93bbe00b8e2568\
             7f9423240f3b044f6e22fb3bc8fe7ea2327d7e89dee2e3c62120c1be42c13da3f666cb5b\
             7dbb903a1709b64d72a3e6a9f46ec67a330f266d55797071920ac402f544f5224cadee87\
             0357a37c3e84b6b73c15542e689a8aaee9305fb906cef1c32bdc675706326953d1f0ccc4\
             f27961d024496b1d4baa2e1035b979e6b62eb753b342e36d090840722dfd89e77048d3f0\
             c16856b52d7995441b269428711c985a71525b364dad5f24464c518e03c159d50f607ecd\
             f9c4fdbe140a20e5f224b6efd4545f5fd132cb7ef005c04a597e81ba7031ca92a3ad634e\
             447536d0f5537a0d418ea71ea8ed0026ed3413a0a7ca4beb9891c72031a590f8ad9a804e\
             168d39ab5dbb814f2bb602a723fda562192f15d895c80a3e4d1c7b9060d9b5b145168911\
             eab24c1ee96452e6eb0691325983c9ca571660c4aad8ae90b68246030a0682b9163d198d\
             508cb34a014a72840b32a2ae1717fa64f40b0c0a5450ef78db56c5c2684688b5cd7483e8\
             63a55e207bf06764802ae3d61a29621701b972aef272955171e29a5961d613bae5c892d\
             f";

        let seed = hex::decode(seed_hex).unwrap();
        let exp_pk = hex::decode(exp_pk_hex).unwrap();

        let mut pk = [0u8; MLDSA87_PUBLIC_KEY_BYTES];
        mldsa87_pub_from_seed(&mut pk, seed.as_slice().try_into().unwrap());
        assert_eq!(pk.as_slice(), exp_pk.as_slice());
    }

    #[test]
    fn test_mldsa87_sign() {
        let seed_hex = "713def3d7a4bf7ee2f934eae31491070d7cf8dd7f7fb9eddad1cd0ef39b82a69";
        let msg_hex = "5622971f1d3e96a4c91ec74ce8bdfa5c";
        let exp_sig_hex =
            "cd21b280a2fb0e47c11961b74482c71eb0b49d4a990f243173487664f13b0741b389d2de\
             51c5d43b8f678e39f6701d5e24fd37a445ae257134aa1bf6ff4105e8f17ac6d39978813a\
             ca7b524a61aa412eed0a2227e56daea83678a545268bc302a56331fe7b40cd6061ec98e5\
             dd5f246c97fedbd273af821754e4eae7e4c6dfa3a79c057e782bb3c2e829d095940cb14b\
             4fdaf78a2e7e89de56fe022083e6734ba73071c02dce2148be7c96d5d5ebe9334feb0768\
             2ab08ef1e8cc7e595cd98e4b3c81d2989586860be8bda07ec8c80519befa4c7c82020d68\
             f66fb0fff2929f67a104494b82d46f6ddc7fe67f48a54861637c64fc6898102746ca882c\
             8e9a4a7fbc79d4f271bef8ed1e0e5612dc422a9b0b1bd6c9146f6049a585705d43e78864\
             cf833789c4d6a115a6235fd5e3c3a61af010be8efced82ac672a3ceb6e77dc7c1c3127c8\
             794b87139494072c3a5573c244b0c14cbfb2f8855c8be5a41ccd66fb13077e04ae730d6f\
             bdcb58e53aee83e73d72f146077a21074e66a91aee1403cf2e65e5b53dc5922fc3cb0c1b\
             3b42d176b2451b20e14dda1059566d14187e1e320483d41a38681884cad2bf78434c789c\
             820efade7ec0b3d45af2a1becb0c62b3402d35eb563bad8bccfbca6c0ca4b3da61f2825f\
             a5c5f0e0d3b7f912361016539c5307bf9cb69adbf469f424d7f6f0ef31d91d7c641f4479\
             b779dee46fbbd2ff8131a9358ba7e43f2f02712b4d7cf0b70030fc5818697285ce510473\
             a3481c47e2f4361140775cd5a768a17db88868b33408aeb0ed29d8cd2866d65f449236aa\
             b74acf33aa99a6b88d936bb2c0de8419b1bd2d97c6a1cdaabac08d5f0d68d22b72a309f4\
             2a4354753c0f31ef9f2b7b807b9f4e7cc984523c66ec8dcf3e83b0792fcc7151830937f9\
             3f04c16b7b12674ed8fd2902de6c28aaa9c520bb02af0c47d02d7cd80eac6a2009a96582\
             1463474d981626cb8cad982785264567cf15360ad83439d53b296fc2f8b9170f4adc39ad\
             3f47b2f25f848fa1777156035ad6b455c4bc423ad9959ed6571ef6bad2352ca95800ccde\
             48935a00e2bbab31d79ea7229e086165bde713de3032e7649a7de75c21856190b85aa586\
             ff0c0c43610ace7634df1a8ec9d350067a33f746484a493744fd478a60b7ac2f5898d078\
             5d08a239fed81d88cfd992d84f90d701e1ca2b91ca85b1c96d8752bc3e4afe8a93c2fb64\
             409095c1ff7e3163445260403d3df4c8717e753905702490eb09530198d732da3a71407b\
             f8a4efc55ef82f970bd8209eccaa144d03b1b21ab5171410d5f400c18c30ff64b4b9c2dc\
             e78fe99882fc969031b1919a2ab23bfa902080e5622a8910223972b14e4187ef622c71ce\
             d36f0a6ececb1e9702101ef09859d47a06a42b39178516323ceac18c5539239bcc80356a\
             c4f5c648e55897a8bd4758eee228737037b5981e31f3c96d43e20856cf730f2a0db3686c\
             dab3993b0544e4add9d0cfb5fe25dc2eab539165535ee80d2070d8fdb22bb69f65b4bfdc\
             5dddb2d88836d7eb38996e5e0467ab1060c43e341cd6d4630fb68fd8e6d8f9196b750d09\
             1c9fec80fd155d09381e9a546b98e963a2399f82a9b738ef61ccf07963a6407898f759e0\
             13112ab3251bdfabfe9a66555e5ba0c7af457ec4e3d83e2c4a7a2f8a701d2a18788a662d\
             1a87e90cbc86af7292d22b2026725368371d76a59d6340b7548a0f9f39b31889c5a41278\
             fe6cdeda45167910178161238ff5c7902c5dcc08c1f08b33a28d59187f4c8e301763079a\
             6f3352c3cfc84b64beee8e6aabc63fee1700b25aae0b5fdbdd312105ef865e461c11980f\
             ac3260c635e7e1625b2aa86f68e55fdb16af2153c7639725a731948bbc0cd64d043b0af7\
             d7b412e107af19b9b7f94ad641de3bb9fb0f135963e008adf11ebf5d81ce06d68109de4e\
             ffdc54283e7fcb10febe65087199e2080364ff39180e9362a23afd0606579e92c9a0d20b\
             86f30822bb21bd3e97db2f8099c47b995b078c8d0e236590f47fe8dc30b72820cc7428e6\
             da1a6edd978b02f26c7fbddd5a8221074cbd5d9b04726067b7d3899bc0cfb7f0b17a3b00\
             75ab7e12ed40b580c116e29fbd607bbaa6b0c14b5c354fe607aa5c776e528e85182af12d\
             4e67b56f414f7d4dfa4aaa833f2e93dcdfc41bdf4f9e0499852c4317c4c9a4617c634da2\
             e4f1a2ad0cfdb0fba936cddc100cf1441a87723c568430772cf07df6e66726a978e55524\
             5aa3e98f8fb777621ff5d2b941b86a8e3e99b6dda5918827e9d5d41fd99a12f8385c81ac\
             4a65760fc620984317f09ef210e2425dc39bb7589bf96b6e4e4ea9712d7d884ba8dfb607\
             c8c5475ca3676298bebd4b1c924ef86df01bd45dea8626d8d055df41a223ee86b15b5c49\
             d11c242e4be1681e2db453f46607d14a70bb68b372f27efa96b18028bbd324559a6c2a6c\
             a4887d57770225fedc0015e69e2b1e50154891d52ada00fa6ef61245b08fd2614d8b46f6\
             932ba92ac648de4366f58168ef986a800ec624dbf853b244f5e360f320526b5b9ad43f57\
             4345f578d3e2fcd3f52fddbbcbf64152e7c62d308bbcad82de1f4fdea3a741bf88a48bf5\
             41e71b95d0034037f7161324020980216137fbad84825f64f89b374779943181d78ab2a4\
             a4f5b598e5e0c3a0d8e1dc179dda8fa77d5c6e369f2f5a648b501aeb0848a255ad0089fa\
             4ea29a314b8cd0edc80af29258b44b59c23650764fda9c34b3aaa43a08c5b2410319825a\
             594a98c07a26c01282855cf5e24a93ccacca9e64f74d546e86086a9e785b8ece5ea89fc4\
             9cd4012e376ea965ac1b5a86e541dcf721f2cfb506b8576de0d47cd1a5240d6b14ba722b\
             4d0ea8f52288b43dee4a1fbe753e8d20886a1e973830541edf782ac493f94100e2bda74d\
             b41563de706c19baa0b296ec61a5ca9b4767dafc222ea6f1fade91031bf3c36c7dbe69a1\
             cb360affba9d0fcf5c743b23b4fd71a412e301cb2bc264a0243740cd94d8865738c2a6c2\
             fd6f92b5d5da0bcf59bb710740599b07da576ef68086b7adc0d6264c7b9e7606c4d7c584\
             5800e2fb96c4911b43b81b613e00f7a56c2eab459a36f8e628873b3f81292244888e8c6c\
             1b017a776609828d2151bc950d17894303a22d6f914c0095071bfa9ab12cac3cff87dd70\
             46377cb1d73f50db0cf4b5d365244e543aa938c395bfbbd961ca3e219e209fc1bdd901ff\
             8c8d65e1d01a3667d970b5bf58400f1595f9ebfd039e056125c2bc3e9866312d9f7a93fd\
             38e36feb34ea3c2fdd6463990b630b40c6d926c0f24f93de81097242406a1f764b4ea315\
             1c6b4571f09f47980615fecea47cdbdf609d548a2ea880ff0c58370c4490362b17b86c09\
             0840cce82653c02b2931b5bf0b86ef3955507bdfa9ad37405af281a72b03ba06b4faaa49\
             1a97f8f0e142742ea6819e43dbd7eaac3ce622a994dc970f5ba0ff4a616507df2670fb06\
             1a10c88d7aa7be18a630dd1a66f0b26862f6f70fa489c7186a25cfc674ffcc31b45d642a\
             2ed09de70d6f6fc852971f7539050386b03f3e1e2e17e73215a693564cd09c36d673c4da\
             99475c0cd6fbfc6b557040a2e9bc40d259558a9e692ae056648b92f56e596d9fc51a3e0a\
             71a1476bc91bd5b996801503115f4fc2450e25394579cd61e5258baa230f24c0d7ecdcf3\
             2c930c7d615fe9b0dd3a711136bd1fcfc952cbab9da80a83fc2cb7d90a4e95991ebb1b57\
             ef38be225523939376d76b52d12405d446c37e9ce1106c5ed84f3fafbb9d6967b356ffdb\
             0d033ae0ec94266f85342f34a43f6a7f99000bc83fda3544bb9584fcebd11f7396466edd\
             cbc6de9a23c25189d099ad3bddc2f79e3dc3c83d92b1567f4984cd08db7cf68b757c0a17\
             62969ed7b3c50381c536ffc9743301332e1b7bd7617d6c3a4df7cd6ce8c1c2eb1024571a\
             54a67e48350bece1db489955c15673d16fdb5ea711d24cae7923c5da25963c0fc228e7b8\
             0ba80589c3aa00e42622a18b62533fb17773fa2afe2d19504baafd494be2291264c283a2\
             a940a8811a2a4d8e266ae5653a96fcc48921bf7c80c4fcd6e317b457f375a4082a2b52a0\
             23ac79ba7f699ede6b589ab96b68a1475fd57717809402f4652aee08e847bdfa520c46f4\
             a0e53b338981d060edf1dd8450d03b35d622c7b3c580d518562928019b155be02091003c\
             a526e97be54fe689cf6c088629db39785c84aaab5b9618ee9446e476360d8d1938096b5a\
             6a7e3f2e5f277296ca3163a25138782980a9b39ae955a657e203983f2a19c586e75fec84\
             887c9de9b313631f712d35d4ab3e3a545a93c80e77c8569118e0fa69c31744c6d54c8944\
             da6b4814d77d3ac6d9a9da28609b2be94131e49b4d6c38e2736de0bacd251125c921c5b8\
             7264ca3e76f725d3ee2470b0e15f155f5c0aa735e12ce97ccf9be79ef97f3442d996df92\
             182d7b32a1bd173fbb4b27dc5806a0e84ca6d52ee9c38f1d7d3775146c760c37e540a045\
             30d7fad5fc6d45b6b9082ca7a7c379cfd2adc76971cf2a3852fc2d4b6ef787d8bea4576d\
             4273965fc3d0a19471edad2bbf04496b8608bd99c843d4e972c75075fe8a46e143583920\
             a99f1e5bad81070b5ef58f5773f5d6e41ebda08006d6eed4bb093a09c32aa7a8dc8979ba\
             32d8042a32e4d14890db860b42d3c7d6d36785feee7f4c097761268d7ffe65c7effc0038\
             b75f516ac5a4a941ab42c865a18d4e7617210754c48f7e9cdf3471073897ce469be8e8b5\
             f5cd4cde2633b964e29756834cd3295fb51b11889dc27b836e51607b254a2018592e207b\
             a62989d931b79dc5ae23039a74b88150718f9c1ff1a57b789d1e80b86e025bb12ffd66d2\
             3be6ec4eb70e7c4b62fcbce5caafa3df20fab61c9a2517809452b1cc2dc8eb9b7bfe783f\
             c37c582748806aed8dde62f21aa9d81ebb9a7432475625008fdd0836ea0e7f6739fe75de\
             500f8dd40b19a3257b4e3e72fd477b614f282c517543e96696851328dc361065f339d9a9\
             d2a17f9bc4b066112cc7d0757001d2ab078c7e1ff824842369b4ccf9fbe1eb82277f3d17\
             e3ff2d41870814e3e05452da1e35ad9735b1ac8c7267662eb1bb8247394ab84edbe69183\
             65e45d2e44952f3f5bb91e0cb817cc2b7c834579058f7fca717d24d3038f07a2dfea0e2e\
             eb3c32ca63a9c2e33cb5bc26286e297622f38764bf3758dcad4759c02e2266d933a6d3af\
             95568757fcea5df9f556bf9d67d2341938652870ca9f16984b7b06fd1440f3e5a29c6fd7\
             56847b0a8e2f46b89390cfa550b361076b1b7215aee9fc877051863a97b5596a230c2a31\
             1c0291b5688ccd6e32bc7b89d0028cd0904bba4c24d1debca86ce93f275e1bae0581264c\
             84cf409165043893510e794f2f73c7c6afc5404bbbb835054620c3099f98ba2a1b39dd25\
             5a3b96c6ec561f93c95d72ce37ee10f4016df4a77116d15cd4a5e87103b0194302ac7fd8\
             a8c2414e2a9c4072f086493eb28f398f330bb0e53e8a6002219c4fe1e76db9b7b5a70112\
             8a3d6c86c65b15be30e178b71481343b08adfd16582b733f7769a63d3abc9d51020efa8e\
             b4978187868683c256a07291fdbe8e8fec3dbdcea16d1f7ef04e2299f8b151379714f2db\
             85260fd4ce825ababf06a62b7dc4b0a3c9a7de339e0a0c8cc90aeb2b89505a7746addeb6\
             1106613cae1caa1a564a4fab61a59ed2303b078792d64265919ec3ee19434fa6b272582f\
             0267c679907d1240fdc3e044d6dcd7e81b2fd3611e9cd3c841a5185f91e5133019211737\
             703fa41dd294d5ca4594a68a44bd19dc83d012531830e3f30833638ce5000d8452dd08d0\
             b14c90916b4c6e5cc47f7805b585054a2b514bf6bfb7d62f0b366c26aa97f7611c31a212\
             3cdd543b3d0bb5d06531de780796d05292102a2c788756c92ba606783f394d0a2710863b\
             c90673193cdae98e2aada2587571df48736d2934338620163424383c532c07d6b9d692cf\
             c637ebc21eec156165144de1a18d772fb9b402c51fa6c9b41bd649d2701c02e51c9358b4\
             3d778902b4bfc4929649ee8a5e806a2c469cb2be1b64201e9446d82cf6094b4553807830\
             ed2cd5ceb9088877beb6922fa636b1be25705a49e9694179dce98064183f3ed30c052f00\
             f944933e11264d118ee6b11da522e9c811543cee732342215d9f86552cc85f7fd2446e76\
             7a95e86964d3884bfa8a33e813a74d213cde44fe0b904e59d9eabc32d7753b8982de08ea\
             1219b55143bf0e6934936721f4b69dacf2a955432b0aa0418001ffc0f569f783713c5d50\
             2bf6bc0c3df381b1fec061eb18b48ea17c5a517df392cfdb8303923e4fedfacc21bc2b63\
             829a5fe0ada04ff619eef293bb07af2741f041bd1203a29c581649e4d89748eb56fbe0b0\
             8b2638691aaf626f143e40b41c91ea4d1dacb37ffe1ff056801c8929c7e9d2465c0d350b\
             d23e10d90b09d4a31b21303f4b78a9b1b4cdceff010f5668729698adb7d5dadffd3e569b\
             c1db0e1935555a5e7cb7ea4a587a9fa0e00a315b674b5e6872b209a6acc0e6f100000000\
             00000000000000000000000c191e272d31363c";

        let seed = hex::decode(seed_hex).unwrap();
        let msg = hex::decode(msg_hex).unwrap();
        let exp_sig = hex::decode(exp_sig_hex).unwrap();

        let mut sig = [0u8; MLDSA87_SIGNATURE_BYTES];
        mldsa87_sign_deterministic(
            &mut sig,
            seed.as_slice().try_into().unwrap(),
            msg.as_slice(),
        );

        assert_eq!(sig.as_slice(), exp_sig.as_slice());
    }

    #[test]
    fn test_mldsa87_sign_verify_roundtrip() {
        let priv_seed = [0u8; MLDSA87_PRIVATE_SEED_BYTES];
        let msg = b"hello world";

        let mut sig = [0u8; MLDSA87_SIGNATURE_BYTES];
        mldsa87_sign_deterministic(&mut sig, &priv_seed, msg);

        let mut pub_key = [0u8; MLDSA87_PUBLIC_KEY_BYTES];
        mldsa87_pub_from_seed(&mut pub_key, &priv_seed);

        assert!(mldsa87_verify(&pub_key, &sig, msg));
    }
}
